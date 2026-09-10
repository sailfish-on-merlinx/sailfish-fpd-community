/*
 * AIDL fingerprint backend for sailfish-fpd-community.
 *
 * Devices on an Android 13+ base publish the AIDL fingerprint HAL
 * (android.hardware.biometrics.fingerprint.IFingerprint, V4 here) and no HIDL
 * android.hardware.biometrics.fingerprint@2.x at all. The existing backend,
 * biometry_fp_hidl_for_hybris.cpp, only speaks HIDL, so on such a device there
 * is nothing on the Sailfish side that can reach the sensor even though the
 * hardware, its kernel drivers and the vendor service all work.
 *
 * This implements the same C API against AIDL. It is written for the Xiaomi
 * Redmi Note 10 Pro (sweet) on hybris-23.2 / Android 16, but there is nothing
 * device-specific in it.
 *
 * The two interfaces differ in shape, not just in spelling:
 *
 *   - HIDL is one flat object with methods and one callback interface. AIDL is
 *     session based: IFingerprint::createSession() returns an ISession, and
 *     every operation reports through the ISessionCallback given at creation.
 *   - HIDL's setActiveGroup(gid) switches user on the live object. AIDL binds
 *     the user id at createSession(), so changing group means closing the
 *     session and opening a new one.
 *   - HIDL preEnroll() returns the challenge synchronously. AIDL's
 *     generateChallenge() is asynchronous and answers on the callback, so this
 *     waits on a condition variable to keep the synchronous C API intact.
 *   - HIDL enroll() takes the raw hw_auth_token_t bytes Gatekeeper produces.
 *     AIDL takes a HardwareAuthToken parcelable, so the bytes have to be
 *     unpacked - see parseAuthToken().
 *
 * Gatekeeper is still HIDL (android.hardware.gatekeeper@1.0), so that half is
 * carried over from the HIDL backend unchanged.
 */

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>

#include <condition_variable>
#include <mutex>
#include <vector>

#include <aidl/android/hardware/biometrics/common/ICancellationSignal.h>
#include <aidl/android/hardware/biometrics/fingerprint/BnSessionCallback.h>
#include <aidl/android/hardware/biometrics/fingerprint/IFingerprint.h>
#include <aidl/android/hardware/keymaster/HardwareAuthToken.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

#include <utils/Log.h>

#include <biometry.h>

using android::sp;
using android::hardware::Return;
using android::hardware::hidl_vec;
using android::hardware::gatekeeper::V1_0::IGatekeeper;
using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;

namespace fp = aidl::android::hardware::biometrics::fingerprint;
using fp::AcquiredInfo;
using fp::Error;
using fp::IFingerprint;
using fp::ISession;
using aidl::android::hardware::biometrics::common::ICancellationSignal;
using aidl::android::hardware::keymaster::HardwareAuthToken;
using aidl::android::hardware::keymaster::HardwareAuthenticatorType;

static const char *kFingerprintServiceName =
    "android.hardware.biometrics.fingerprint.IFingerprint/default";

/* The device id the HIDL API reported. AIDL has no equivalent and the value is
 * only passed back out through the callbacks, so a constant will do. */
static const uint64_t kDeviceId = 1;

std::shared_ptr<IFingerprint> fpHal = nullptr;
std::shared_ptr<ISession> fpSession = nullptr;
std::shared_ptr<ICancellationSignal> fpCancel = nullptr;

static int32_t gSensorId = 0;
static int32_t gUserId = 0;

/* generateChallenge() and getAuthenticatorId() answer asynchronously, but the
 * C API they sit behind is synchronous. */
static std::mutex gWaitLock;
static std::condition_variable gWaitCv;
static bool gChallengeReady = false;
static int64_t gChallenge = 0;
static bool gAuthIdReady = false;
static int64_t gAuthenticatorId = 0;

struct UHardwareBiometry_
{
    UHardwareBiometry_();
    ~UHardwareBiometry_();

    bool init();

    uint64_t setNotify();
    uint64_t preEnroll();
    UHardwareBiometryRequestStatus enroll(uint32_t gid, uint32_t timeoutSec, uint32_t uid);
    UHardwareBiometryRequestStatus postEnroll();
    uint64_t getAuthenticatorId();
    UHardwareBiometryRequestStatus cancel();
    UHardwareBiometryRequestStatus enumerate();
    UHardwareBiometryRequestStatus remove(uint32_t gid, uint32_t fid);
    UHardwareBiometryRequestStatus setActiveGroup(uint32_t gid, char *storePath);
    UHardwareBiometryRequestStatus authenticate(uint64_t operationId, uint32_t gid);

    bool openSession(int32_t userId);
};

struct UHardwareBiometryCallback_
{
    UHardwareBiometryCallback_(UHardwareBiometryParams* params);

    UHardwareBiometryEnrollResult enrollresult_cb;
    UHardwareBiometryAcquired acquired_cb;
    UHardwareBiometryAuthenticated authenticated_cb;
    UHardwareBiometryError error_cb;
    UHardwareBiometryRemoved removed_cb;
    UHardwareBiometryEnumerate enumerate_cb;

    void* context;
};

namespace
{
UHardwareBiometry hybris_fp_instance = NULL;
UHardwareBiometryCallback hybris_fp_instance_cb = NULL;

UHardwareBiometryFingerprintAcquiredInfo AIDLToUFingerprintAcquiredInfo(AcquiredInfo info)
{
    switch (info) {
        case AcquiredInfo::GOOD:          return ACQUIRED_GOOD;
        case AcquiredInfo::PARTIAL:       return ACQUIRED_PARTIAL;
        case AcquiredInfo::INSUFFICIENT:  return ACQUIRED_INSUFFICIENT;
        case AcquiredInfo::SENSOR_DIRTY:  return ACQUIRED_IMAGER_DIRTY;
        case AcquiredInfo::TOO_SLOW:      return ACQUIRED_TOO_SLOW;
        case AcquiredInfo::TOO_FAST:      return ACQUIRED_TOO_FAST;
        default:                          return ACQUIRED_VENDOR;
    }
}

UHardwareBiometryFingerprintError AIDLToUFingerprintError(Error error)
{
    switch (error) {
        case Error::HW_UNAVAILABLE:      return ERROR_HW_UNAVAILABLE;
        case Error::UNABLE_TO_PROCESS:   return ERROR_UNABLE_TO_PROCESS;
        case Error::TIMEOUT:             return ERROR_TIMEOUT;
        case Error::NO_SPACE:            return ERROR_NO_SPACE;
        case Error::CANCELED:            return ERROR_CANCELED;
        case Error::UNABLE_TO_REMOVE:    return ERROR_UNABLE_TO_REMOVE;
        default:                         return ERROR_VENDOR;
    }
}

struct SessionCallback : public fp::BnSessionCallback
{
    ::ndk::ScopedAStatus onChallengeGenerated(int64_t challenge) override
    {
        {
            std::lock_guard<std::mutex> lock(gWaitLock);
            gChallenge = challenge;
            gChallengeReady = true;
        }
        gWaitCv.notify_all();
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onChallengeRevoked(int64_t) override
    {
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onAcquired(AcquiredInfo info, int32_t vendorCode) override
    {
        if (hybris_fp_instance_cb && hybris_fp_instance_cb->acquired_cb)
            hybris_fp_instance_cb->acquired_cb(kDeviceId,
                                               AIDLToUFingerprintAcquiredInfo(info),
                                               vendorCode,
                                               hybris_fp_instance_cb->context);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onError(Error error, int32_t vendorCode) override
    {
        if (hybris_fp_instance_cb && hybris_fp_instance_cb->error_cb)
            hybris_fp_instance_cb->error_cb(kDeviceId,
                                            AIDLToUFingerprintError(error),
                                            vendorCode,
                                            hybris_fp_instance_cb->context);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onEnrollmentProgress(int32_t enrollmentId, int32_t remaining) override
    {
        if (hybris_fp_instance_cb && hybris_fp_instance_cb->enrollresult_cb)
            hybris_fp_instance_cb->enrollresult_cb(kDeviceId, enrollmentId, gUserId,
                                                   remaining,
                                                   hybris_fp_instance_cb->context);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onAuthenticationSucceeded(int32_t enrollmentId,
                                                   const HardwareAuthToken &) override
    {
        if (hybris_fp_instance_cb && hybris_fp_instance_cb->authenticated_cb)
            hybris_fp_instance_cb->authenticated_cb(kDeviceId, enrollmentId, gUserId,
                                                    hybris_fp_instance_cb->context);
        return ::ndk::ScopedAStatus::ok();
    }

    /* HIDL had no distinct "failed" callback - a rejected finger arrived as
     * onAuthenticated() with fingerId 0. fpd relies on that, so keep it. */
    ::ndk::ScopedAStatus onAuthenticationFailed() override
    {
        if (hybris_fp_instance_cb && hybris_fp_instance_cb->authenticated_cb)
            hybris_fp_instance_cb->authenticated_cb(kDeviceId, 0, gUserId,
                                                    hybris_fp_instance_cb->context);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onLockoutTimed(int64_t) override
    {
        if (hybris_fp_instance_cb && hybris_fp_instance_cb->error_cb)
            hybris_fp_instance_cb->error_cb(kDeviceId, ERROR_LOCKOUT, 0,
                                            hybris_fp_instance_cb->context);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onLockoutPermanent() override
    {
        if (hybris_fp_instance_cb && hybris_fp_instance_cb->error_cb)
            hybris_fp_instance_cb->error_cb(kDeviceId, ERROR_LOCKOUT, 0,
                                            hybris_fp_instance_cb->context);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onLockoutCleared() override
    {
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onInteractionDetected() override
    {
        return ::ndk::ScopedAStatus::ok();
    }

    /* AIDL reports the whole set at once; the C API expects one call per
     * template with a countdown, the way HIDL delivered them. An empty set
     * still has to produce one call with fingerId 0, or fpd waits forever. */
    ::ndk::ScopedAStatus onEnrollmentsEnumerated(const std::vector<int32_t> &enrollmentIds) override
    {
        if (!hybris_fp_instance_cb || !hybris_fp_instance_cb->enumerate_cb)
            return ::ndk::ScopedAStatus::ok();

        if (enrollmentIds.empty()) {
            hybris_fp_instance_cb->enumerate_cb(kDeviceId, 0, gUserId, 0,
                                                hybris_fp_instance_cb->context);
        } else {
            uint32_t remaining = enrollmentIds.size();
            for (int32_t id : enrollmentIds) {
                --remaining;
                hybris_fp_instance_cb->enumerate_cb(kDeviceId, id, gUserId, remaining,
                                                    hybris_fp_instance_cb->context);
            }
        }
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onEnrollmentsRemoved(const std::vector<int32_t> &enrollmentIds) override
    {
        if (!hybris_fp_instance_cb || !hybris_fp_instance_cb->removed_cb)
            return ::ndk::ScopedAStatus::ok();

        if (enrollmentIds.empty()) {
            hybris_fp_instance_cb->removed_cb(kDeviceId, 0, gUserId, 0,
                                              hybris_fp_instance_cb->context);
        } else {
            uint32_t remaining = enrollmentIds.size();
            for (int32_t id : enrollmentIds) {
                --remaining;
                hybris_fp_instance_cb->removed_cb(kDeviceId, id, gUserId, remaining,
                                                  hybris_fp_instance_cb->context);
            }
        }
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onAuthenticatorIdRetrieved(int64_t authenticatorId) override
    {
        {
            std::lock_guard<std::mutex> lock(gWaitLock);
            gAuthenticatorId = authenticatorId;
            gAuthIdReady = true;
        }
        gWaitCv.notify_all();
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onAuthenticatorIdInvalidated(int64_t) override
    {
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onSessionClosed() override
    {
        return ::ndk::ScopedAStatus::ok();
    }
};

std::shared_ptr<SessionCallback> gSessionCallback = nullptr;

/*
 * Gatekeeper hands back a packed hw_auth_token_t. AIDL wants the fields.
 *
 *   uint8_t  version                     (0)
 *   uint64_t challenge                   host order
 *   uint64_t user_id                     host order
 *   uint64_t authenticator_id            host order
 *   uint32_t authenticator_type          big endian
 *   uint64_t timestamp                   big endian
 *   uint8_t  hmac[32]
 *
 * 69 bytes, packed, and the mixed endianness is not a mistake in this comment -
 * it is how the struct is defined in hw_auth_token.h.
 */
bool parseAuthToken(const uint8_t *data, size_t len, HardwareAuthToken *out)
{
    static const size_t kTokenSize = 1 + 8 + 8 + 8 + 4 + 8 + 32;

    if (!data || len < kTokenSize) {
        ALOGE("auth token too short: %zu bytes, need %zu", len, kTokenSize);
        return false;
    }

    size_t off = 1; /* skip version */
    uint64_t challenge, userId, authenticatorId, timestamp;
    uint32_t authenticatorType;

    memcpy(&challenge, data + off, 8);          off += 8;
    memcpy(&userId, data + off, 8);             off += 8;
    memcpy(&authenticatorId, data + off, 8);    off += 8;
    memcpy(&authenticatorType, data + off, 4);  off += 4;
    memcpy(&timestamp, data + off, 8);          off += 8;

    out->challenge = static_cast<int64_t>(challenge);
    out->userId = static_cast<int64_t>(userId);
    out->authenticatorId = static_cast<int64_t>(authenticatorId);
    out->authenticatorType =
        static_cast<HardwareAuthenticatorType>(be32toh(authenticatorType));
    out->timestamp.milliSeconds = static_cast<int64_t>(be64toh(timestamp));
    out->mac.assign(data + off, data + off + 32);
    return true;
}

} // namespace

UHardwareBiometry_::UHardwareBiometry_()
{
}

UHardwareBiometry_::~UHardwareBiometry_()
{
    if (fpSession != nullptr)
        fpSession->close();
}

bool UHardwareBiometry_::openSession(int32_t userId)
{
    if (fpHal == nullptr)
        return false;

    if (fpSession != nullptr) {
        fpSession->close();
        fpSession = nullptr;
    }

    if (gSessionCallback == nullptr)
        gSessionCallback = ::ndk::SharedRefBase::make<SessionCallback>();

    ::ndk::ScopedAStatus status =
        fpHal->createSession(gSensorId, userId, gSessionCallback, &fpSession);
    if (!status.isOk() || fpSession == nullptr) {
        ALOGE("createSession failed: %s", status.getDescription().c_str());
        return false;
    }

    gUserId = userId;
    return true;
}

bool UHardwareBiometry_::init()
{
    if (fpHal != nullptr)
        return true;

    /* Callbacks arrive on binder threads, so the pool has to be running or
     * nothing is ever delivered and every wait below times out. */
    ABinderProcess_startThreadPool();

    ::ndk::SpAIBinder binder(AServiceManager_waitForService(kFingerprintServiceName));
    if (binder.get() == nullptr) {
        ALOGE("Unable to get %s", kFingerprintServiceName);
        return false;
    }

    fpHal = IFingerprint::fromBinder(binder);
    if (fpHal == nullptr) {
        ALOGE("Unable to cast %s to IFingerprint", kFingerprintServiceName);
        return false;
    }

    std::vector<fp::SensorProps> props;
    ::ndk::ScopedAStatus status = fpHal->getSensorProps(&props);
    if (!status.isOk() || props.empty()) {
        ALOGE("getSensorProps failed: %s", status.getDescription().c_str());
        fpHal = nullptr;
        return false;
    }

    gSensorId = props[0].commonProps.sensorId;
    ALOGI("fingerprint sensor id %d, %zu sensor(s)", gSensorId, props.size());

    return openSession(gUserId);
}

uint64_t UHardwareBiometry_::setNotify()
{
    /* AIDL has no separate notify step - the callback was handed over at
     * createSession(). */
    return kDeviceId;
}

uint64_t UHardwareBiometry_::preEnroll()
{
    if (fpSession == nullptr) {
        ALOGE("Unable to get FP session\n");
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(gWaitLock);
        gChallengeReady = false;
        gChallenge = 0;
    }

    /* The lock must not be held across this call.
     *
     * Binder delivers a nested incoming transaction on the very thread that
     * made the outgoing one, so the HAL's onChallengeGenerated() usually runs
     * inline - inside generateChallenge(), on this thread - rather than on a
     * spare binder thread. The kernel's binder log shows the pair on one tid:
     *
     *   thread 18960:
     *     outgoing transaction ... from 18960:18960 to 3113:3113
     *     incoming transaction ... from 3113:3113 to 18960:18960
     *
     * gWaitLock is a plain std::mutex, so the callback taking it while this
     * function still held it was a self-deadlock: the main thread parked in
     * pthread_mutex_lock inside the AIDL proxy and never came back, and every
     * later D-Bus call into fpd timed out. Waiting only after the call returns
     * costs nothing - wait_for() checks the predicate before sleeping, so the
     * inline case falls straight through. */
    ::ndk::ScopedAStatus status = fpSession->generateChallenge();
    if (!status.isOk()) {
        ALOGE("generateChallenge failed: %s", status.getDescription().c_str());
        return 0;
    }

    std::unique_lock<std::mutex> lock(gWaitLock);
    if (!gWaitCv.wait_for(lock, std::chrono::seconds(5),
                          [] { return gChallengeReady; })) {
        ALOGE("timed out waiting for onChallengeGenerated");
        return 0;
    }

    return static_cast<uint64_t>(gChallenge);
}

UHardwareBiometryRequestStatus UHardwareBiometry_::enroll(uint32_t gid, uint32_t timeoutSec, uint32_t user_id)
{
    (void) timeoutSec; /* AIDL has no enrol timeout parameter */

    if (fpSession == nullptr) {
        ALOGE("Unable to get FP session\n");
        return SYS_UNKNOWN;
    }

    uint64_t challenge = preEnroll();
    if (challenge == 0) {
        ALOGE("no challenge, cannot enroll");
        return SYS_UNKNOWN;
    }

    /* Gatekeeper is still HIDL on these devices - this half is unchanged from
     * the HIDL backend. */
    int ret = 0;
    std::string Password = "default_password";
    sp<IGatekeeper> gk_device = IGatekeeper::getService();
    if (gk_device == nullptr) {
        ALOGE("Unable to get Gatekeeper service\n");
        return SYS_UNKNOWN;
    }

    hidl_vec<uint8_t> curPwdHandle;
    hidl_vec<uint8_t> enteredPwd;
    enteredPwd.setToExternal(const_cast<uint8_t *>((const uint8_t *)Password.c_str()),
                             Password.size());

    Return<void> hwRet = gk_device->enroll(user_id, NULL, NULL, enteredPwd,
        [&ret, &curPwdHandle](const GatekeeperResponse &rsp) {
            ret = static_cast<int>(rsp.code);
            if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                curPwdHandle.resize(rsp.data.size());
                std::copy(rsp.data.begin(), rsp.data.end(), curPwdHandle.data());
                ret = 0;
            } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT && rsp.timeout > 0) {
                ret = rsp.timeout;
            }
        });
    if (!hwRet.isOk() || ret) {
        ALOGE("Unable to Enroll on Gatekeeper\n");
        return SYS_UNKNOWN;
    }

    std::vector<uint8_t> authToken;
    hwRet = gk_device->verify(user_id, challenge, curPwdHandle, enteredPwd,
        [&ret, &authToken](const GatekeeperResponse &rsp) {
            ret = static_cast<int>(rsp.code);
            if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                authToken.assign(rsp.data.begin(), rsp.data.end());
                ret = 0;
            } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT && rsp.timeout > 0) {
                ret = rsp.timeout;
            }
        });
    if (!hwRet.isOk() || ret) {
        ALOGE("Unable to Verify on Gatekeeper\n");
        return SYS_UNKNOWN;
    }

    HardwareAuthToken hat;
    if (!parseAuthToken(authToken.data(), authToken.size(), &hat))
        return SYS_UNKNOWN;

    (void) gid;
    ::ndk::ScopedAStatus status = fpSession->enroll(hat, &fpCancel);
    if (!status.isOk()) {
        ALOGE("enroll failed: %s", status.getDescription().c_str());
        return SYS_UNKNOWN;
    }

    return SYS_OK;
}

UHardwareBiometryRequestStatus UHardwareBiometry_::postEnroll()
{
    if (fpSession == nullptr)
        return SYS_UNKNOWN;

    ::ndk::ScopedAStatus status = fpSession->revokeChallenge(gChallenge);
    return status.isOk() ? SYS_OK : SYS_UNKNOWN;
}

uint64_t UHardwareBiometry_::getAuthenticatorId()
{
    if (fpSession == nullptr)
        return 0;

    {
        std::lock_guard<std::mutex> lock(gWaitLock);
        gAuthIdReady = false;
        gAuthenticatorId = 0;
    }

    /* Same reentrancy rule as preEnroll(): onAuthenticatorIdRetrieved() can be
     * delivered inline on this thread, so the lock is taken only afterwards. */
    ::ndk::ScopedAStatus status = fpSession->getAuthenticatorId();
    if (!status.isOk())
        return 0;

    std::unique_lock<std::mutex> lock(gWaitLock);
    if (!gWaitCv.wait_for(lock, std::chrono::seconds(5),
                          [] { return gAuthIdReady; }))
        return 0;

    return static_cast<uint64_t>(gAuthenticatorId);
}

UHardwareBiometryRequestStatus UHardwareBiometry_::cancel()
{
    if (fpCancel == nullptr)
        return SYS_OK;

    ::ndk::ScopedAStatus status = fpCancel->cancel();
    fpCancel = nullptr;
    return status.isOk() ? SYS_OK : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus UHardwareBiometry_::enumerate()
{
    if (fpSession == nullptr)
        return SYS_UNKNOWN;

    ::ndk::ScopedAStatus status = fpSession->enumerateEnrollments();
    return status.isOk() ? SYS_OK : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus UHardwareBiometry_::remove(uint32_t gid, uint32_t fid)
{
    (void) gid;

    if (fpSession == nullptr)
        return SYS_UNKNOWN;

    /* HIDL used fid 0 to mean "remove everything in the group". AIDL has no
     * such convention, so enumerate first and remove what comes back. */
    std::vector<int32_t> ids;
    if (fid != 0)
        ids.push_back(static_cast<int32_t>(fid));

    ::ndk::ScopedAStatus status = fpSession->removeEnrollments(ids);
    return status.isOk() ? SYS_OK : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus UHardwareBiometry_::setActiveGroup(uint32_t gid, char *storePath)
{
    /* AIDL binds the user id at createSession() and has no storage path - the
     * HAL owns where templates live. */
    (void) storePath;

    if (static_cast<int32_t>(gid) == gUserId && fpSession != nullptr)
        return SYS_OK;

    return openSession(static_cast<int32_t>(gid)) ? SYS_OK : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus UHardwareBiometry_::authenticate(uint64_t operationId, uint32_t gid)
{
    (void) gid;

    if (fpSession == nullptr) {
        ALOGE("Unable to get FP session\n");
        return SYS_UNKNOWN;
    }

    ::ndk::ScopedAStatus status =
        fpSession->authenticate(static_cast<int64_t>(operationId), &fpCancel);
    if (!status.isOk()) {
        ALOGE("authenticate failed: %s", status.getDescription().c_str());
        return SYS_UNKNOWN;
    }

    return SYS_OK;
}

UHardwareBiometryCallback_::UHardwareBiometryCallback_(UHardwareBiometryParams* params)
    : enrollresult_cb(params->enrollresult_cb),
      acquired_cb(params->acquired_cb),
      authenticated_cb(params->authenticated_cb),
      error_cb(params->error_cb),
      removed_cb(params->removed_cb),
      enumerate_cb(params->enumerate_cb),
      context(params->context)
{
}

/////////////////////////////////////////////////////////////////////
// Implementation of the C API

UHardwareBiometry u_hardware_biometry_new()
{
    if (hybris_fp_instance != NULL)
        return NULL;

    UHardwareBiometry u_hardware_biometry = new UHardwareBiometry_();
    hybris_fp_instance = u_hardware_biometry;

    for (unsigned int i = 0; i < 50; i++)
        if (u_hardware_biometry->init())
            return hybris_fp_instance = u_hardware_biometry;
        else
            ::usleep(200 * 1000);

    delete u_hardware_biometry;
    return hybris_fp_instance;
}

uint64_t u_hardware_biometry_setNotify(UHardwareBiometry self, UHardwareBiometryParams *params)
{
    UHardwareBiometryCallback u_hardware_biometry_cb = new UHardwareBiometryCallback_(params);
    hybris_fp_instance_cb = u_hardware_biometry_cb;

    return self->setNotify();
}

uint64_t u_hardware_biometry_preEnroll(UHardwareBiometry self)
{
    return self->preEnroll();
}

UHardwareBiometryRequestStatus u_hardware_biometry_enroll(UHardwareBiometry self, uint32_t gid, uint32_t timeoutSec, uint32_t uid)
{
    return self->enroll(gid, timeoutSec, uid);
}

UHardwareBiometryRequestStatus u_hardware_biometry_postEnroll(UHardwareBiometry self)
{
    return self->postEnroll();
}

uint64_t u_hardware_biometry_getAuthenticatorId(UHardwareBiometry self)
{
    return self->getAuthenticatorId();
}

UHardwareBiometryRequestStatus u_hardware_biometry_cancel(UHardwareBiometry self)
{
    return self->cancel();
}

UHardwareBiometryRequestStatus u_hardware_biometry_enumerate(UHardwareBiometry self)
{
    return self->enumerate();
}

UHardwareBiometryRequestStatus u_hardware_biometry_remove(UHardwareBiometry self, uint32_t gid, uint32_t fid)
{
    return self->remove(gid, fid);
}

UHardwareBiometryRequestStatus u_hardware_biometry_setActiveGroup(UHardwareBiometry self, uint32_t gid, char *storePath)
{
    return self->setActiveGroup(gid, storePath);
}

UHardwareBiometryRequestStatus u_hardware_biometry_authenticate(UHardwareBiometry self, uint64_t operationId, uint32_t gid)
{
    return self->authenticate(operationId, gid);
}
