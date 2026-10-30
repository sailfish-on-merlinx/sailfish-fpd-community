/*
 * libbiometry_fp_api C API: picks the fingerprint HAL backend at runtime.
 *
 * The Android base an adaptation is built from says which backends can be
 * compiled, not which one the device needs: a vendor on an Android 13+ base
 * may still publish only the HIDL HAL, and an AIDL-only vendor has nothing for
 * the HIDL client to bind to. So both are built where possible and the device
 * decides:
 *
 *   - FPD_BIOMETRY_BACKEND=aidl or =hidl in the environment forces one;
 *   - otherwise AIDL when the VINTF manifest declares
 *     android.hardware.biometrics.fingerprint.IFingerprint/default (as Android
 *     itself prefers AIDL), else HIDL.
 */

#include "biometry_backend.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <utils/Log.h>

struct UHardwareBiometry_
{
    biometry::Backend *backend;
};

namespace {

UHardwareBiometry gInstance = nullptr;

biometry::Backend *chooseBackend()
{
    const char *force = getenv("FPD_BIOMETRY_BACKEND");

#ifdef BIOMETRY_HAVE_AIDL
    if (force ? strcmp(force, "aidl") == 0 : biometry::aidl_backend::declared())
        return biometry::aidl_backend::create();
#endif
#ifdef BIOMETRY_HAVE_HIDL
    if (!force || strcmp(force, "hidl") == 0)
        return biometry::hidl_backend::create();
#endif

    ALOGE("no fingerprint backend for this device (FPD_BIOMETRY_BACKEND=%s)",
          force ? force : "");
    return nullptr;
}

} // namespace

UHardwareBiometry u_hardware_biometry_new()
{
    /* One instance per process. */
    if (gInstance != nullptr)
        return nullptr;

    biometry::Backend *backend = chooseBackend();
    if (backend == nullptr)
        return nullptr;

    /* Retry for up to 10 s in case the HAL is still starting. */
    for (unsigned int i = 0; i < 50; i++) {
        if (backend->init()) {
            ALOGI("using %s backend", backend->name());
            gInstance = new UHardwareBiometry_{backend};
            return gInstance;
        }
        ::usleep(200 * 1000);
    }

    ALOGE("%s backend did not come up", backend->name());
    delete backend;
    return nullptr;
}

uint64_t u_hardware_biometry_setNotify(UHardwareBiometry self, UHardwareBiometryParams *params)
{
    return self && params ? self->backend->setNotify(*params) : 0;
}

uint64_t u_hardware_biometry_preEnroll(UHardwareBiometry self)
{
    return self ? self->backend->preEnroll() : 0;
}

UHardwareBiometryRequestStatus u_hardware_biometry_enroll(UHardwareBiometry self, uint32_t gid, uint32_t timeoutSec, uint32_t uid)
{
    return self ? self->backend->enroll(gid, timeoutSec, uid) : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_postEnroll(UHardwareBiometry self)
{
    return self ? self->backend->postEnroll() : SYS_UNKNOWN;
}

uint64_t u_hardware_biometry_getAuthenticatorId(UHardwareBiometry self)
{
    return self ? self->backend->getAuthenticatorId() : 0;
}

UHardwareBiometryRequestStatus u_hardware_biometry_cancel(UHardwareBiometry self)
{
    return self ? self->backend->cancel() : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_enumerate(UHardwareBiometry self)
{
    return self ? self->backend->enumerate() : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_remove(UHardwareBiometry self, uint32_t gid, uint32_t fid)
{
    return self ? self->backend->remove(gid, fid) : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_setActiveGroup(UHardwareBiometry self, uint32_t gid, char *storePath)
{
    return self ? self->backend->setActiveGroup(gid, storePath) : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_authenticate(UHardwareBiometry self, uint64_t operationId, uint32_t gid)
{
    return self ? self->backend->authenticate(operationId, gid) : SYS_UNKNOWN;
}
