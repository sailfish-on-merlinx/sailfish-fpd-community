#include "biometry_gatekeeper.h"

#include <endian.h>
#include <string.h>

#include <string>
#include <vector>

#include <hardware/hw_auth_token.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

#ifdef BIOMETRY_HAVE_AIDL_GATEKEEPER
#include <aidl/android/hardware/gatekeeper/IGatekeeper.h>
#include <android/binder_manager.h>
#endif

#include <utils/Log.h>

using android::sp;
using android::hardware::Return;
using android::hardware::hidl_vec;
using HidlGatekeeper = android::hardware::gatekeeper::V1_0::IGatekeeper;
using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;

namespace biometry {

static_assert(sizeof(hw_auth_token_t) == kHwAuthTokenSize, "hw_auth_token_t layout");

/* Fixed password: the daemon has no Android credential of its own. Kept as the
 * HIDL backend always had it, so existing enrolments keep verifying. */
static const char kPassword[] = "default_password";

void packHwAuthToken(const AuthToken &token, uint8_t out[kHwAuthTokenSize])
{
    hw_auth_token_t t;
    memset(&t, 0, sizeof(t));
    t.version = HW_AUTH_TOKEN_VERSION;
    t.challenge = token.challenge;
    t.user_id = token.userId;
    t.authenticator_id = token.authenticatorId;
    t.authenticator_type = htobe32(token.authenticatorType);
    t.timestamp = htobe64(token.timestampMs);
    memcpy(t.hmac, token.mac, sizeof(t.hmac));
    memcpy(out, &t, sizeof(t));
}

bool parseHwAuthToken(const uint8_t *data, size_t len, AuthToken *out)
{
    if (!data || len != kHwAuthTokenSize) {
        ALOGE("auth token of invalid length %zu", len);
        return false;
    }
    hw_auth_token_t t;
    memcpy(&t, data, sizeof(t));
    out->challenge = t.challenge;
    out->userId = t.user_id;
    out->authenticatorId = t.authenticator_id;
    out->authenticatorType = be32toh(t.authenticator_type);
    out->timestampMs = be64toh(t.timestamp);
    memcpy(out->mac, t.hmac, sizeof(out->mac));
    return true;
}

static bool hidlAuthToken(uint32_t uid, uint64_t challenge, AuthToken *out)
{
    sp<HidlGatekeeper> gk = HidlGatekeeper::getService();
    if (gk == nullptr) {
        ALOGE("no gatekeeper@1.0 service");
        return false;
    }

    hidl_vec<uint8_t> password;
    password.setToExternal(reinterpret_cast<uint8_t *>(const_cast<char *>(kPassword)),
                           strlen(kPassword));

    bool ok = false;
    hidl_vec<uint8_t> handle;
    Return<void> ret = gk->enroll(uid, hidl_vec<uint8_t>(), hidl_vec<uint8_t>(), password,
        [&](const GatekeeperResponse &rsp) {
            if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                handle = rsp.data;
                ok = true;
            } else {
                ALOGE("gatekeeper enroll: code %d timeout %u",
                      static_cast<int>(rsp.code), rsp.timeout);
            }
        });
    if (!ret.isOk() || !ok) {
        ALOGE("unable to enroll on gatekeeper@1.0");
        return false;
    }

    ok = false;
    ret = gk->verify(uid, challenge, handle, password,
        [&](const GatekeeperResponse &rsp) {
            if (rsp.code >= GatekeeperStatusCode::STATUS_OK)
                ok = parseHwAuthToken(rsp.data.data(), rsp.data.size(), out);
            else
                ALOGE("gatekeeper verify: code %d timeout %u",
                      static_cast<int>(rsp.code), rsp.timeout);
        });
    if (!ret.isOk() || !ok) {
        ALOGE("unable to verify on gatekeeper@1.0");
        return false;
    }
    return true;
}

#ifdef BIOMETRY_HAVE_AIDL_GATEKEEPER
using AidlGatekeeper = aidl::android::hardware::gatekeeper::IGatekeeper;
using aidl::android::hardware::gatekeeper::GatekeeperEnrollResponse;
using aidl::android::hardware::gatekeeper::GatekeeperVerifyResponse;

static const char *kAidlGatekeeper = "android.hardware.gatekeeper.IGatekeeper/default";

static bool aidlAuthToken(uint32_t uid, uint64_t challenge, AuthToken *out)
{
    ndk::SpAIBinder binder(AServiceManager_waitForService(kAidlGatekeeper));
    std::shared_ptr<AidlGatekeeper> gk = AidlGatekeeper::fromBinder(binder);
    if (gk == nullptr) {
        ALOGE("no %s", kAidlGatekeeper);
        return false;
    }

    std::vector<uint8_t> password(kPassword, kPassword + strlen(kPassword));

    GatekeeperEnrollResponse enrolled;
    ndk::ScopedAStatus status = gk->enroll(static_cast<int32_t>(uid), {}, {}, password, &enrolled);
    if (!status.isOk() || enrolled.statusCode < AidlGatekeeper::STATUS_OK) {
        ALOGE("unable to enroll on AIDL gatekeeper: %s status %d",
              status.getDescription().c_str(), enrolled.statusCode);
        return false;
    }

    GatekeeperVerifyResponse verified;
    status = gk->verify(static_cast<int32_t>(uid), static_cast<int64_t>(challenge),
                        enrolled.data, password, &verified);
    if (!status.isOk() || verified.statusCode < AidlGatekeeper::STATUS_OK) {
        ALOGE("unable to verify on AIDL gatekeeper: %s status %d",
              status.getDescription().c_str(), verified.statusCode);
        return false;
    }

    const auto &hat = verified.hardwareAuthToken;
    if (hat.mac.size() != sizeof(out->mac)) {
        ALOGE("auth token mac of invalid length %zu", hat.mac.size());
        return false;
    }
    out->challenge = static_cast<uint64_t>(hat.challenge);
    out->userId = static_cast<uint64_t>(hat.userId);
    out->authenticatorId = static_cast<uint64_t>(hat.authenticatorId);
    out->authenticatorType = static_cast<uint32_t>(hat.authenticatorType);
    out->timestampMs = static_cast<uint64_t>(hat.timestamp.milliSeconds);
    memcpy(out->mac, hat.mac.data(), sizeof(out->mac));
    return true;
}
#endif

bool gatekeeperAuthToken(uint32_t uid, uint64_t challenge, AuthToken *out)
{
#ifdef BIOMETRY_HAVE_AIDL_GATEKEEPER
    if (AServiceManager_isDeclared(kAidlGatekeeper))
        return aidlAuthToken(uid, challenge, out);
#endif
    return hidlAuthToken(uid, challenge, out);
}

} // namespace biometry
