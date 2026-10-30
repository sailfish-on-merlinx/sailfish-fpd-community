/*
 * AIDL fingerprint backend for sailfish-fpd-community.
 *
 * Devices whose vendor publishes the AIDL fingerprint HAL
 * (android.hardware.biometrics.fingerprint.IFingerprint) and no HIDL
 * android.hardware.biometrics.fingerprint@2.x cannot be reached by the HIDL
 * backend, even though the hardware, its kernel drivers and the vendor service
 * all work. This implements the same backend interface against AIDL.
 *
 * Originally written by Nikola K for the Xiaomi Redmi Note 10 Pro (sweet) on
 * hybris-23.2 (Bigisoft/sailfish-fpd-community, branch sweet-aidl); nothing in
 * it is device specific.
 *
 * The two interfaces differ in shape, not just in spelling:
 *
 *   - HIDL is one flat object with methods and one callback interface. AIDL is
 *     session based: IFingerprint::createSession() returns an ISession, and
 *     every operation reports through the ISessionCallback given at creation.
 *   - HIDL's setActiveGroup(gid) switches user on the live object. AIDL binds
 *     the user id at createSession(), so changing group means closing the
 *     session and opening a new one. AIDL has no storage path either: the HAL
 *     decides where templates live.
 *   - HIDL preEnroll() returns the challenge synchronously. AIDL's
 *     generateChallenge() is asynchronous and answers on the callback, so this
 *     waits on a condition variable to keep the synchronous C API intact.
 *   - HIDL enroll() takes the raw hw_auth_token_t bytes Gatekeeper produces.
 *     AIDL takes a HardwareAuthToken parcelable.
 *   - HIDL remove(gid, 0) removes every template of the group. AIDL removes a
 *     list of ids, so "all" is the set this backend has seen enumerated.
 */

#include "biometry_backend.h"
#include "biometry_gatekeeper.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <aidl/android/hardware/biometrics/common/ICancellationSignal.h>
#include <aidl/android/hardware/biometrics/fingerprint/BnSessionCallback.h>
#include <aidl/android/hardware/biometrics/fingerprint/IFingerprint.h>
#include <aidl/android/hardware/keymaster/HardwareAuthToken.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <utils/Log.h>

namespace fp = aidl::android::hardware::biometrics::fingerprint;
using fp::AcquiredInfo;
using fp::Error;
using fp::IFingerprint;
using fp::ISession;
using aidl::android::hardware::biometrics::common::ICancellationSignal;
using aidl::android::hardware::keymaster::HardwareAuthToken;
using aidl::android::hardware::keymaster::HardwareAuthenticatorType;

namespace biometry {
namespace aidl_backend {
namespace {

const char *kFingerprintServiceName =
    "android.hardware.biometrics.fingerprint.IFingerprint/default";

/* The device id the HIDL API reported. AIDL has no equivalent and the value is
 * only passed back out through the callbacks, so a constant will do. */
const uint64_t kDeviceId = 1;

/* Android system uid/gid, owner of the HAL's template directory. */
const uid_t kAidSystem = 1000;

/* HAL callbacks are never run on the binder thread that delivered them.
 *
 * The daemon's handlers can call straight back into the HAL (ending an
 * enrolment calls postEnroll(), which is revokeChallenge()). Doing that from
 * inside the callback deadlocks both sides - the HAL thread is still waiting
 * for the callback to return, so it cannot service the new call. The kernel
 * binder log shows the pair on one thread of ours and one of theirs:
 *
 *   thread 13129:
 *     outgoing transaction 160249: from 13128:13129 to 3113:3667 code 2
 *     incoming transaction 160248: from 3113:3667 to 13128:13129 code 5
 *
 * One worker thread, FIFO, so ordering between callbacks is preserved and the
 * binder thread is released immediately. Deliberately never destroyed: the
 * daemon is killed by SIGTERM and tearing this down at exit only risks a race.
 */
class CallbackDispatcher
{
public:
    void post(std::function<void()> fn)
    {
        {
            std::lock_guard<std::mutex> lock(mLock);
            if (!mStarted) {
                mStarted = true;
                std::thread(&CallbackDispatcher::run, this).detach();
            }
            mQueue.push_back(std::move(fn));
        }
        mCv.notify_one();
    }

private:
    void run()
    {
        pthread_setname_np(pthread_self(), "fp-callbacks");
        for (;;) {
            std::function<void()> fn;
            {
                std::unique_lock<std::mutex> lock(mLock);
                mCv.wait(lock, [this] { return !mQueue.empty(); });
                fn = std::move(mQueue.front());
                mQueue.pop_front();
            }
            fn();
        }
    }

    std::mutex mLock;
    std::condition_variable mCv;
    std::deque<std::function<void()>> mQueue;
    bool mStarted = false;
};

CallbackDispatcher &dispatcher()
{
    static CallbackDispatcher *d = new CallbackDispatcher();
    return *d;
}

UHardwareBiometryFingerprintAcquiredInfo toU(AcquiredInfo info)
{
    switch (info) {
        case AcquiredInfo::GOOD:         return ACQUIRED_GOOD;
        case AcquiredInfo::PARTIAL:      return ACQUIRED_PARTIAL;
        case AcquiredInfo::INSUFFICIENT: return ACQUIRED_INSUFFICIENT;
        case AcquiredInfo::SENSOR_DIRTY: return ACQUIRED_IMAGER_DIRTY;
        case AcquiredInfo::TOO_SLOW:     return ACQUIRED_TOO_SLOW;
        case AcquiredInfo::TOO_FAST:     return ACQUIRED_TOO_FAST;
        default:                         return ACQUIRED_VENDOR;
    }
}

UHardwareBiometryFingerprintError toU(Error error)
{
    switch (error) {
        case Error::HW_UNAVAILABLE:    return ERROR_HW_UNAVAILABLE;
        case Error::UNABLE_TO_PROCESS: return ERROR_UNABLE_TO_PROCESS;
        case Error::TIMEOUT:           return ERROR_TIMEOUT;
        case Error::NO_SPACE:          return ERROR_NO_SPACE;
        case Error::CANCELED:          return ERROR_CANCELED;
        case Error::UNABLE_TO_REMOVE:  return ERROR_UNABLE_TO_REMOVE;
        default:                       return ERROR_VENDOR;
    }
}

/* State shared between the backend (daemon thread) and the session callback
 * (binder threads, then the dispatcher thread). */
struct Shared
{
    /* Set once by setNotify(); callbacks before that are dropped. */
    std::atomic<bool> haveParams{false};
    UHardwareBiometryParams params;

    std::atomic<int32_t> userId{0};

    /* generateChallenge() and getAuthenticatorId() answer asynchronously, but
     * the C API they sit behind is synchronous. */
    std::mutex waitLock;
    std::condition_variable waitCv;
    bool challengeReady = false;
    int64_t challenge = 0;
    bool authIdReady = false;
    int64_t authenticatorId = 0;

    /* One cancel must surface exactly one CANCELED.
     *
     * Some HALs answer a single ICancellationSignal::cancel() with two
     * onError(CANCELED) callbacks (seen on sweet as a doubled error_cb for one
     * Abort). The daemon suppresses the second Failed() but still emits
     * ErrorInfo twice on the bus, so every client sees a terminal error for an
     * operation that has already ended.
     *
     * Set when a CANCELED has been forwarded, cleared whenever a new operation
     * starts or a fresh cancel is issued, so a genuine HAL-initiated CANCELED
     * is never swallowed - only the immediate repeat is. */
    std::atomic<bool> canceledDelivered{false};

    /* Enrolment ids the HAL has reported, for remove(gid, 0). */
    std::mutex enrolledLock;
    std::set<int32_t> enrolled;

    /* HAL lockouts are reset as soon as they happen, the way Jolla's fpslave
     * does: attempts are limited by the device lock ("Too many unrecognized
     * fingers"), which never learns of a HAL lockout and cannot show one. A
     * reset needs a HardwareAuthToken for a fresh challenge, and the session
     * calls cannot be made from a callback, so this runs on the dispatcher. */
    std::mutex sessionLock;
    std::shared_ptr<ISession> session;
    std::atomic<bool> lockedOut{false};
    bool lockoutChallengePending = false; // guarded by waitLock
    int64_t lockoutChallenge = 0;         // dispatcher thread only
};

Shared &shared()
{
    static Shared *s = new Shared();
    return *s;
}

void post(std::function<void(const UHardwareBiometryParams &)> fn)
{
    dispatcher().post([fn] {
        Shared &s = shared();
        if (s.haveParams)
            fn(s.params);
    });
}

void forwardList(const std::vector<int32_t> &ids, bool removed)
{
    uint32_t gid = static_cast<uint32_t>(shared().userId.load());
    post([ids, removed, gid](const UHardwareBiometryParams &p) {
        auto cb = removed ? p.removed_cb : p.enumerate_cb;
        if (!cb)
            return;
        /* AIDL reports the whole set at once; the C API expects one call per
         * template with a countdown, the way HIDL delivered them. An empty set
         * still has to produce one call with fingerId 0, or the daemon waits
         * forever. */
        if (ids.empty()) {
            cb(kDeviceId, 0, gid, 0, p.context);
            return;
        }
        uint32_t remaining = ids.size();
        for (int32_t id : ids)
            cb(kDeviceId, static_cast<uint32_t>(id), gid, --remaining, p.context);
    });
}

HardwareAuthToken toHat(const AuthToken &t);

std::shared_ptr<ISession> currentSession()
{
    Shared &s = shared();
    std::lock_guard<std::mutex> lock(s.sessionLock);
    return s.session;
}

/* The reset could not be done: report the lockout as before. */
void forwardLockout()
{
    shared().lockedOut = false;
    post([](const UHardwareBiometryParams &p) {
        if (p.error_cb)
            p.error_cb(kDeviceId, ERROR_LOCKOUT, 0, p.context);
    });
}

/* Dispatcher thread: first step of a reset, ask for a challenge. */
void requestLockoutChallenge()
{
    Shared &s = shared();
    std::shared_ptr<ISession> session = currentSession();
    if (session == nullptr) {
        forwardLockout();
        return;
    }
    {
        std::lock_guard<std::mutex> lock(s.waitLock);
        s.lockoutChallengePending = true;
    }
    ::ndk::ScopedAStatus status = session->generateChallenge();
    if (!status.isOk()) {
        ALOGE("generateChallenge for lockout reset failed: %s", status.getDescription().c_str());
        {
            std::lock_guard<std::mutex> lock(s.waitLock);
            s.lockoutChallengePending = false;
        }
        forwardLockout();
    }
}

/* Dispatcher thread: authorise the reset with a token for that challenge. */
void resetLockout(int64_t challenge)
{
    Shared &s = shared();
    std::shared_ptr<ISession> session = currentSession();
    AuthToken token;
    if (session == nullptr
        || !gatekeeperAuthToken(static_cast<uint32_t>(s.userId.load()),
                                static_cast<uint64_t>(challenge), &token)) {
        forwardLockout();
        return;
    }
    s.lockoutChallenge = challenge;
    ::ndk::ScopedAStatus status = session->resetLockout(toHat(token));
    if (!status.isOk()) {
        ALOGE("resetLockout failed: %s", status.getDescription().c_str());
        forwardLockout();
    }
}

struct SessionCallback : public fp::BnSessionCallback
{
    ::ndk::ScopedAStatus onChallengeGenerated(int64_t challenge) override
    {
        Shared &s = shared();
        bool forLockout;
        {
            std::lock_guard<std::mutex> lock(s.waitLock);
            forLockout = s.lockoutChallengePending;
            s.lockoutChallengePending = false;
            if (!forLockout) {
                s.challenge = challenge;
                s.challengeReady = true;
            }
        }
        if (forLockout)
            dispatcher().post([challenge] { resetLockout(challenge); });
        else
            s.waitCv.notify_all();
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onChallengeRevoked(int64_t) override
    {
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onAcquired(AcquiredInfo info, int32_t vendorCode) override
    {
        UHardwareBiometryFingerprintAcquiredInfo u = toU(info);
        post([u, vendorCode](const UHardwareBiometryParams &p) {
            if (p.acquired_cb)
                p.acquired_cb(kDeviceId, u, vendorCode, p.context);
        });
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onError(Error error, int32_t vendorCode) override
    {
        if (error == Error::CANCELED && shared().canceledDelivered.exchange(true)) {
            ALOGI("dropping repeated onError(CANCELED) for one cancel");
            return ::ndk::ScopedAStatus::ok();
        }
        UHardwareBiometryFingerprintError u = toU(error);
        post([u, vendorCode](const UHardwareBiometryParams &p) {
            if (p.error_cb)
                p.error_cb(kDeviceId, u, vendorCode, p.context);
        });
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onEnrollmentProgress(int32_t enrollmentId, int32_t remaining) override
    {
        Shared &s = shared();
        if (remaining == 0) {
            std::lock_guard<std::mutex> lock(s.enrolledLock);
            s.enrolled.insert(enrollmentId);
        }
        uint32_t gid = static_cast<uint32_t>(s.userId.load());
        post([enrollmentId, remaining, gid](const UHardwareBiometryParams &p) {
            if (p.enrollresult_cb)
                p.enrollresult_cb(kDeviceId, static_cast<uint32_t>(enrollmentId), gid,
                                  static_cast<uint32_t>(remaining), p.context);
        });
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onAuthenticationSucceeded(int32_t enrollmentId,
                                                   const HardwareAuthToken &) override
    {
        uint32_t gid = static_cast<uint32_t>(shared().userId.load());
        post([enrollmentId, gid](const UHardwareBiometryParams &p) {
            if (p.authenticated_cb)
                p.authenticated_cb(kDeviceId, static_cast<uint32_t>(enrollmentId), gid,
                                   p.context);
        });
        return ::ndk::ScopedAStatus::ok();
    }

    /* HIDL had no distinct "failed" callback - a rejected finger arrived as
     * onAuthenticated() with fingerId 0. The daemon relies on that, so keep it. */
    ::ndk::ScopedAStatus onAuthenticationFailed() override
    {
        uint32_t gid = static_cast<uint32_t>(shared().userId.load());
        post([gid](const UHardwareBiometryParams &p) {
            if (p.authenticated_cb)
                p.authenticated_cb(kDeviceId, 0, gid, p.context);
        });
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onLockoutTimed(int64_t durationMillis) override
    {
        ALOGI("temporary fingerprint lockout (%lld ms), resetting",
              static_cast<long long>(durationMillis));
        lockedOut();
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onLockoutPermanent() override
    {
        ALOGI("permanent fingerprint lockout, resetting");
        lockedOut();
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onLockoutCleared() override
    {
        ALOGI("fingerprint lockout cleared");
        shared().lockedOut = false;
        dispatcher().post([] {
            Shared &s = shared();
            std::shared_ptr<ISession> session = currentSession();
            if (s.lockoutChallenge != 0 && session != nullptr)
                session->revokeChallenge(s.lockoutChallenge);
            s.lockoutChallenge = 0;
        });
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onInteractionDetected() override
    {
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onEnrollmentsEnumerated(const std::vector<int32_t> &ids) override
    {
        Shared &s = shared();
        {
            std::lock_guard<std::mutex> lock(s.enrolledLock);
            s.enrolled = std::set<int32_t>(ids.begin(), ids.end());
        }
        forwardList(ids, false);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onEnrollmentsRemoved(const std::vector<int32_t> &ids) override
    {
        Shared &s = shared();
        {
            std::lock_guard<std::mutex> lock(s.enrolledLock);
            for (int32_t id : ids)
                s.enrolled.erase(id);
        }
        forwardList(ids, true);
        return ::ndk::ScopedAStatus::ok();
    }

    ::ndk::ScopedAStatus onAuthenticatorIdRetrieved(int64_t authenticatorId) override
    {
        Shared &s = shared();
        {
            std::lock_guard<std::mutex> lock(s.waitLock);
            s.authenticatorId = authenticatorId;
            s.authIdReady = true;
        }
        s.waitCv.notify_all();
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

private:
    /* A locked-out HAL reports again on every touch; one reset is enough. */
    static void lockedOut()
    {
        if (!shared().lockedOut.exchange(true))
            dispatcher().post(requestLockoutChallenge);
    }
};

HardwareAuthToken toHat(const AuthToken &t)
{
    HardwareAuthToken hat;
    hat.challenge = static_cast<int64_t>(t.challenge);
    hat.userId = static_cast<int64_t>(t.userId);
    hat.authenticatorId = static_cast<int64_t>(t.authenticatorId);
    hat.authenticatorType = static_cast<HardwareAuthenticatorType>(t.authenticatorType);
    hat.timestamp.milliSeconds = static_cast<int64_t>(t.timestampMs);
    hat.mac.assign(t.mac, t.mac + sizeof(t.mac));
    return hat;
}

/* AIDL HALs choose where templates live; the AOSP convention, used by the
 * LineageOS HALs among others, is /data/vendor_de/<user>/fpdata. On Android
 * vold prepares /data/vendor_de/<user> when the user is created; nothing does
 * that under Sailfish OS, so make sure it exists. Harmless for a HAL that keeps
 * its templates elsewhere. */
void prepareVendorDe(int32_t userId)
{
    std::string user = "/data/vendor_de/" + std::to_string(userId);
    std::string fpdata = user + "/fpdata";

    if (mkdir(user.c_str(), 0771) != 0 && errno != EEXIST)
        ALOGW("cannot create %s: %s", user.c_str(), strerror(errno));

    struct stat st;
    if (lstat(fpdata.c_str(), &st) == 0)
        return;
    if (mkdir(fpdata.c_str(), 0700) != 0) {
        ALOGW("cannot create %s: %s", fpdata.c_str(), strerror(errno));
        return;
    }
    if (chown(fpdata.c_str(), kAidSystem, kAidSystem) != 0)
        ALOGW("cannot chown %s: %s", fpdata.c_str(), strerror(errno));
}

/* Wait for an asynchronous answer to arrive. The lock must not be held across
 * the outgoing call that triggers it: binder delivers a nested incoming
 * transaction on the very thread that made the outgoing one, so the answer
 * usually runs inline, inside the call, on this thread. Taking a plain mutex
 * there while the caller still held it was a self-deadlock (the daemon's main
 * thread parked in pthread_mutex_lock inside the AIDL proxy). wait_for()
 * checks the predicate before sleeping, so the inline case falls through. */
bool waitFor(bool Shared::*ready)
{
    Shared &s = shared();
    std::unique_lock<std::mutex> lock(s.waitLock);
    return s.waitCv.wait_for(lock, std::chrono::seconds(5), [&s, ready] { return s.*ready; });
}

class AidlBackend : public Backend
{
public:
    ~AidlBackend() override
    {
        if (mSession != nullptr)
            mSession->close();
    }

    const char *name() const override { return "AIDL IFingerprint"; }

    bool init() override
    {
        if (mHal != nullptr)
            return mSession != nullptr || openSession(shared().userId);

        /* Callbacks arrive on binder threads, so the pool has to be running
         * or nothing is ever delivered and every wait below times out. */
        static bool poolStarted = false;
        if (!poolStarted) {
            ABinderProcess_startThreadPool();
            poolStarted = true;
        }

        ::ndk::SpAIBinder binder(AServiceManager_waitForService(kFingerprintServiceName));
        mHal = IFingerprint::fromBinder(binder);
        if (mHal == nullptr) {
            ALOGE("Unable to get %s", kFingerprintServiceName);
            return false;
        }

        std::vector<fp::SensorProps> props;
        ::ndk::ScopedAStatus status = mHal->getSensorProps(&props);
        if (!status.isOk() || props.empty()) {
            ALOGE("getSensorProps failed: %s", status.getDescription().c_str());
            mHal = nullptr;
            return false;
        }
        mSensorId = props[0].commonProps.sensorId;
        ALOGI("fingerprint sensor id %d, %zu sensor(s)", mSensorId, props.size());

        return openSession(shared().userId);
    }

    uint64_t setNotify(const UHardwareBiometryParams &params) override
    {
        Shared &s = shared();
        s.params = params;
        s.haveParams = true;
        return kDeviceId;
    }

    uint64_t preEnroll() override
    {
        if (mSession == nullptr)
            return 0;

        Shared &s = shared();
        {
            std::lock_guard<std::mutex> lock(s.waitLock);
            s.challengeReady = false;
            s.challenge = 0;
        }
        ::ndk::ScopedAStatus status = mSession->generateChallenge();
        if (!status.isOk()) {
            ALOGE("generateChallenge failed: %s", status.getDescription().c_str());
            return 0;
        }
        if (!waitFor(&Shared::challengeReady)) {
            ALOGE("timed out waiting for onChallengeGenerated");
            return 0;
        }
        std::lock_guard<std::mutex> lock(s.waitLock);
        mChallenge = s.challenge;
        return static_cast<uint64_t>(mChallenge);
    }

    UHardwareBiometryRequestStatus enroll(uint32_t, uint32_t, uint32_t uid) override
    {
        /* AIDL has no enrolment timeout and binds the group at createSession(). */
        if (mSession == nullptr)
            return SYS_UNKNOWN;

        uint64_t challenge = preEnroll();
        if (challenge == 0) {
            ALOGE("no challenge, cannot enroll");
            return SYS_UNKNOWN;
        }

        AuthToken token;
        if (!gatekeeperAuthToken(uid, challenge, &token))
            return SYS_UNKNOWN;

        shared().canceledDelivered = false;
        ::ndk::ScopedAStatus status = mSession->enroll(toHat(token), &mCancel);
        if (!status.isOk()) {
            ALOGE("enroll failed: %s", status.getDescription().c_str());
            return SYS_UNKNOWN;
        }
        return SYS_OK;
    }

    UHardwareBiometryRequestStatus postEnroll() override
    {
        if (mSession == nullptr)
            return SYS_UNKNOWN;
        ::ndk::ScopedAStatus status = mSession->revokeChallenge(mChallenge);
        return status.isOk() ? SYS_OK : SYS_UNKNOWN;
    }

    uint64_t getAuthenticatorId() override
    {
        if (mSession == nullptr)
            return 0;

        Shared &s = shared();
        {
            std::lock_guard<std::mutex> lock(s.waitLock);
            s.authIdReady = false;
            s.authenticatorId = 0;
        }
        ::ndk::ScopedAStatus status = mSession->getAuthenticatorId();
        if (!status.isOk() || !waitFor(&Shared::authIdReady))
            return 0;
        std::lock_guard<std::mutex> lock(s.waitLock);
        return static_cast<uint64_t>(s.authenticatorId);
    }

    UHardwareBiometryRequestStatus cancel() override
    {
        if (mCancel == nullptr)
            return SYS_OK;

        /* This cancel is entitled to one CANCELED of its own. */
        shared().canceledDelivered = false;
        ::ndk::ScopedAStatus status = mCancel->cancel();
        mCancel = nullptr;
        return status.isOk() ? SYS_OK : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus enumerate() override
    {
        if (mSession == nullptr)
            return SYS_UNKNOWN;
        ::ndk::ScopedAStatus status = mSession->enumerateEnrollments();
        return status.isOk() ? SYS_OK : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus remove(uint32_t, uint32_t fid) override
    {
        if (mSession == nullptr)
            return SYS_UNKNOWN;

        std::vector<int32_t> ids;
        if (fid != 0) {
            ids.push_back(static_cast<int32_t>(fid));
        } else {
            /* HIDL's "remove everything in the group". */
            Shared &s = shared();
            std::lock_guard<std::mutex> lock(s.enrolledLock);
            ids.assign(s.enrolled.begin(), s.enrolled.end());
        }

        if (ids.empty()) {
            /* Nothing to remove. Removing an empty list may produce no
             * callback at all, and the daemon waits for one. */
            forwardList(ids, true);
            return SYS_OK;
        }

        ::ndk::ScopedAStatus status = mSession->removeEnrollments(ids);
        return status.isOk() ? SYS_OK : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus setActiveGroup(uint32_t gid, char *) override
    {
        /* AIDL binds the user id at createSession() and has no storage path -
         * the HAL owns where templates live. */
        int32_t userId = static_cast<int32_t>(gid);
        if (mSession != nullptr && userId == shared().userId)
            return SYS_OK;
        return openSession(userId) ? SYS_OK : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus authenticate(uint64_t operationId, uint32_t) override
    {
        if (mSession == nullptr)
            return SYS_UNKNOWN;

        shared().canceledDelivered = false;
        ::ndk::ScopedAStatus status =
            mSession->authenticate(static_cast<int64_t>(operationId), &mCancel);
        if (!status.isOk()) {
            ALOGE("authenticate failed: %s", status.getDescription().c_str());
            return SYS_UNKNOWN;
        }
        return SYS_OK;
    }

private:
    bool openSession(int32_t userId)
    {
        if (mHal == nullptr)
            return false;

        if (mSession != nullptr) {
            mSession->close();
            mSession = nullptr;
        }
        {
            Shared &s = shared();
            std::lock_guard<std::mutex> lock(s.enrolledLock);
            s.enrolled.clear();
        }
        {
            Shared &s = shared();
            std::lock_guard<std::mutex> lock(s.sessionLock);
            s.session = nullptr;
        }

        prepareVendorDe(userId);

        if (mCallback == nullptr)
            mCallback = ::ndk::SharedRefBase::make<SessionCallback>();

        ::ndk::ScopedAStatus status =
            mHal->createSession(mSensorId, userId, mCallback, &mSession);
        if (!status.isOk() || mSession == nullptr) {
            ALOGE("createSession failed: %s", status.getDescription().c_str());
            mSession = nullptr;
            return false;
        }
        shared().userId = userId;
        {
            Shared &s = shared();
            std::lock_guard<std::mutex> lock(s.sessionLock);
            s.session = mSession;
        }
        return true;
    }

    std::shared_ptr<IFingerprint> mHal;
    std::shared_ptr<ISession> mSession;
    std::shared_ptr<ICancellationSignal> mCancel;
    std::shared_ptr<SessionCallback> mCallback;
    int32_t mSensorId = 0;
    int64_t mChallenge = 0;
};

} // namespace

bool declared()
{
    return AServiceManager_isDeclared(kFingerprintServiceName);
}

Backend *create()
{
    return new AidlBackend();
}

} // namespace aidl_backend
} // namespace biometry
