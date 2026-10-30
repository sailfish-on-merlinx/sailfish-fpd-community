/*
 * Internal interface between the libbiometry_fp_api C API and the Android
 * fingerprint HAL backends.
 *
 * libbiometry_fp_api may contain two backends: HIDL
 * (android.hardware.biometrics.fingerprint@2.1, Android 8 and newer bases) and
 * AIDL (android.hardware.biometrics.fingerprint.IFingerprint, Android 12 and
 * newer bases). Which one a device needs depends on its vendor, not on the
 * Android base the adaptation is built from: a device on an Android 13+ base
 * can still publish only the HIDL HAL. biometry_fp_dispatch.cpp therefore
 * picks the backend at runtime from what the device declares.
 *
 * Each backend lives in its own namespace and is reached only through this
 * interface, so the two can be linked into one library.
 */

#ifndef BIOMETRY_BACKEND_H_
#define BIOMETRY_BACKEND_H_

#include <biometry.h>

namespace biometry {

class Backend
{
public:
    virtual ~Backend() {}

    virtual const char *name() const = 0;

    /* Connect to the HAL. May be retried; true once the backend is usable. */
    virtual bool init() = 0;

    virtual uint64_t setNotify(const UHardwareBiometryParams &params) = 0;
    virtual uint64_t preEnroll() = 0;
    virtual UHardwareBiometryRequestStatus enroll(uint32_t gid, uint32_t timeoutSec, uint32_t uid) = 0;
    virtual UHardwareBiometryRequestStatus postEnroll() = 0;
    virtual uint64_t getAuthenticatorId() = 0;
    virtual UHardwareBiometryRequestStatus cancel() = 0;
    virtual UHardwareBiometryRequestStatus enumerate() = 0;
    virtual UHardwareBiometryRequestStatus remove(uint32_t gid, uint32_t fid) = 0;
    virtual UHardwareBiometryRequestStatus setActiveGroup(uint32_t gid, char *storePath) = 0;
    virtual UHardwareBiometryRequestStatus authenticate(uint64_t operationId, uint32_t gid) = 0;
};

/* Not "hidl"/"aidl": inside namespace biometry those would hide the global
 * ::aidl namespace the generated NDK headers use. */
#ifdef BIOMETRY_HAVE_HIDL
namespace hidl_backend {
Backend *create();
}
#endif

#ifdef BIOMETRY_HAVE_AIDL
namespace aidl_backend {
/* True when the device's VINTF manifest declares the AIDL fingerprint HAL. */
bool declared();
Backend *create();
}
#endif

} // namespace biometry

#endif // BIOMETRY_BACKEND_H_
