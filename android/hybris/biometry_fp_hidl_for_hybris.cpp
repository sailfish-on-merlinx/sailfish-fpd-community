/*
 * Copyright © 2020 UBports foundation Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authored by: Erfan Abdi <erfangplus@gmail.com>
 */

/* HIDL backend: android.hardware.biometrics.fingerprint@2.1. HALs implementing
 * @2.2 or @2.3 also serve @2.1. */

#include "biometry_backend.h"
#include "biometry_gatekeeper.h"

#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>

#include <utils/Log.h>

using android::sp;
using android::hardware::Return;
using android::hardware::Void;
using android::hardware::hidl_array;
using android::hardware::hidl_vec;

using android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint;
using android::hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;
using android::hardware::biometrics::fingerprint::V2_1::RequestStatus;
using android::hardware::biometrics::fingerprint::V2_1::FingerprintAcquiredInfo;
using android::hardware::biometrics::fingerprint::V2_1::FingerprintError;

namespace biometry {
namespace hidl_backend {
namespace {

UHardwareBiometryFingerprintAcquiredInfo toU(FingerprintAcquiredInfo info)
{
    switch (info) {
        case FingerprintAcquiredInfo::ACQUIRED_GOOD:         return ACQUIRED_GOOD;
        case FingerprintAcquiredInfo::ACQUIRED_PARTIAL:      return ACQUIRED_PARTIAL;
        case FingerprintAcquiredInfo::ACQUIRED_INSUFFICIENT: return ACQUIRED_INSUFFICIENT;
        case FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY: return ACQUIRED_IMAGER_DIRTY;
        case FingerprintAcquiredInfo::ACQUIRED_TOO_SLOW:     return ACQUIRED_TOO_SLOW;
        case FingerprintAcquiredInfo::ACQUIRED_TOO_FAST:     return ACQUIRED_TOO_FAST;
        case FingerprintAcquiredInfo::ACQUIRED_VENDOR:       return ACQUIRED_VENDOR;
        default:                                             return ACQUIRED_GOOD;
    }
}

UHardwareBiometryFingerprintError toU(FingerprintError error)
{
    switch (error) {
        case FingerprintError::ERROR_NO_ERROR:          return ERROR_NO_ERROR;
        case FingerprintError::ERROR_HW_UNAVAILABLE:    return ERROR_HW_UNAVAILABLE;
        case FingerprintError::ERROR_UNABLE_TO_PROCESS: return ERROR_UNABLE_TO_PROCESS;
        case FingerprintError::ERROR_TIMEOUT:           return ERROR_TIMEOUT;
        case FingerprintError::ERROR_NO_SPACE:          return ERROR_NO_SPACE;
        case FingerprintError::ERROR_CANCELED:          return ERROR_CANCELED;
        case FingerprintError::ERROR_UNABLE_TO_REMOVE:  return ERROR_UNABLE_TO_REMOVE;
        case FingerprintError::ERROR_LOCKOUT:           return ERROR_LOCKOUT;
        case FingerprintError::ERROR_VENDOR:            return ERROR_VENDOR;
        default:                                        return ERROR_NO_ERROR;
    }
}

UHardwareBiometryRequestStatus toU(RequestStatus req)
{
    switch (req) {
        case RequestStatus::SYS_UNKNOWN:   return SYS_UNKNOWN;
        case RequestStatus::SYS_OK:        return SYS_OK;
        case RequestStatus::SYS_ENOENT:    return SYS_ENOENT;
        case RequestStatus::SYS_EINTR:     return SYS_EINTR;
        case RequestStatus::SYS_EIO:       return SYS_EIO;
        case RequestStatus::SYS_EAGAIN:    return SYS_EAGAIN;
        case RequestStatus::SYS_ENOMEM:    return SYS_ENOMEM;
        case RequestStatus::SYS_EACCES:    return SYS_EACCES;
        case RequestStatus::SYS_EFAULT:    return SYS_EFAULT;
        case RequestStatus::SYS_EBUSY:     return SYS_EBUSY;
        case RequestStatus::SYS_EINVAL:    return SYS_EINVAL;
        case RequestStatus::SYS_ENOSPC:    return SYS_ENOSPC;
        case RequestStatus::SYS_ETIMEDOUT: return SYS_ETIMEDOUT;
        default:                           return SYS_UNKNOWN;
    }
}

UHardwareBiometryRequestStatus toU(const Return<RequestStatus> &ret)
{
    return ret.isOk() ? toU(static_cast<RequestStatus>(ret)) : SYS_UNKNOWN;
}

struct ClientCallback : public IBiometricsFingerprintClientCallback
{
    explicit ClientCallback(const UHardwareBiometryParams &params) : p(params) {}

    Return<void> onEnrollResult(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                                uint32_t remaining) override
    {
        if (p.enrollresult_cb)
            p.enrollresult_cb(deviceId, fingerId, groupId, remaining, p.context);
        return Void();
    }

    Return<void> onAcquired(uint64_t deviceId, FingerprintAcquiredInfo info,
                            int32_t vendorCode) override
    {
        if (p.acquired_cb)
            p.acquired_cb(deviceId, toU(info), vendorCode, p.context);
        return Void();
    }

    Return<void> onAuthenticated(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                                 const hidl_vec<uint8_t> &) override
    {
        if (p.authenticated_cb)
            p.authenticated_cb(deviceId, fingerId, groupId, p.context);
        return Void();
    }

    Return<void> onError(uint64_t deviceId, FingerprintError error, int32_t vendorCode) override
    {
        if (p.error_cb)
            p.error_cb(deviceId, toU(error), vendorCode, p.context);
        return Void();
    }

    Return<void> onRemoved(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                           uint32_t remaining) override
    {
        if (p.removed_cb)
            p.removed_cb(deviceId, fingerId, groupId, remaining, p.context);
        return Void();
    }

    Return<void> onEnumerate(uint64_t deviceId, uint32_t fingerId, uint32_t groupId,
                             uint32_t remaining) override
    {
        if (p.enumerate_cb)
            p.enumerate_cb(deviceId, fingerId, groupId, remaining, p.context);
        return Void();
    }

    UHardwareBiometryParams p;
};

class HidlBackend : public Backend
{
public:
    ~HidlBackend() override
    {
        if (mHal != nullptr)
            mHal->cancel();
    }

    const char *name() const override { return "HIDL fingerprint@2.1"; }

    bool init() override
    {
        if (mHal == nullptr)
            mHal = IBiometricsFingerprint::getService();
        if (mHal == nullptr) {
            ALOGE("Unable to get FP service");
            return false;
        }
        return true;
    }

    uint64_t setNotify(const UHardwareBiometryParams &params) override
    {
        if (mHal == nullptr)
            return 0;
        mCallback = new ClientCallback(params);
        Return<uint64_t> ret = mHal->setNotify(mCallback);
        return ret.isOk() ? static_cast<uint64_t>(ret) : 0;
    }

    uint64_t preEnroll() override
    {
        if (mHal == nullptr)
            return 0;
        Return<uint64_t> ret = mHal->preEnroll();
        return ret.isOk() ? static_cast<uint64_t>(ret) : 0;
    }

    UHardwareBiometryRequestStatus enroll(uint32_t gid, uint32_t timeoutSec, uint32_t uid) override
    {
        if (mHal == nullptr)
            return SYS_UNKNOWN;

        uint64_t challenge = preEnroll();
        AuthToken token;
        if (!gatekeeperAuthToken(uid, challenge, &token))
            return SYS_UNKNOWN;

        hidl_array<uint8_t, kHwAuthTokenSize> hat;
        packHwAuthToken(token, hat.data());
        return toU(mHal->enroll(hat, gid, timeoutSec));
    }

    UHardwareBiometryRequestStatus postEnroll() override
    {
        return mHal != nullptr ? toU(mHal->postEnroll()) : SYS_UNKNOWN;
    }

    uint64_t getAuthenticatorId() override
    {
        if (mHal == nullptr)
            return 0;
        Return<uint64_t> ret = mHal->getAuthenticatorId();
        return ret.isOk() ? static_cast<uint64_t>(ret) : 0;
    }

    UHardwareBiometryRequestStatus cancel() override
    {
        return mHal != nullptr ? toU(mHal->cancel()) : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus enumerate() override
    {
        return mHal != nullptr ? toU(mHal->enumerate()) : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus remove(uint32_t gid, uint32_t fid) override
    {
        return mHal != nullptr ? toU(mHal->remove(gid, fid)) : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus setActiveGroup(uint32_t gid, char *storePath) override
    {
        return mHal != nullptr ? toU(mHal->setActiveGroup(gid, storePath)) : SYS_UNKNOWN;
    }

    UHardwareBiometryRequestStatus authenticate(uint64_t operationId, uint32_t gid) override
    {
        return mHal != nullptr ? toU(mHal->authenticate(operationId, gid)) : SYS_UNKNOWN;
    }

private:
    sp<IBiometricsFingerprint> mHal;
    sp<ClientCallback> mCallback;
};

} // namespace

Backend *create()
{
    return new HidlBackend();
}

} // namespace hidl_backend
} // namespace biometry
