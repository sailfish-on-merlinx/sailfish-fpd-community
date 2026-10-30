/*
 * Gatekeeper half of an enrolment, shared by the HIDL and AIDL fingerprint
 * backends.
 *
 * Enrolling a fingerprint needs a hardware auth token for the HAL's challenge.
 * The daemon has no Android lock screen credential, so - as the HIDL backend
 * always did - a fixed password is enrolled in Gatekeeper for the uid and then
 * verified against the challenge, which yields the token.
 *
 * Which Gatekeeper a device has is independent of its fingerprint HAL (an
 * AIDL fingerprint HAL next to a HIDL gatekeeper@1.0 is common on older
 * vendors, and newer vendors may have only the AIDL gatekeeper), so both are
 * supported here and chosen at runtime.
 */

#ifndef BIOMETRY_GATEKEEPER_H_
#define BIOMETRY_GATEKEEPER_H_

#include <stdint.h>
#include <stddef.h>

namespace biometry {

/* The fields of hw_auth_token_t, in host byte order. */
struct AuthToken
{
    uint64_t challenge;
    uint64_t userId;
    uint64_t authenticatorId;
    uint32_t authenticatorType;
    uint64_t timestampMs;
    uint8_t  mac[32];
};

/* Enrol the fixed password for uid and verify it against challenge. */
bool gatekeeperAuthToken(uint32_t uid, uint64_t challenge, AuthToken *out);

/* hw_auth_token_t wire format (69 bytes; type and timestamp big endian). */
static const size_t kHwAuthTokenSize = 69;
void packHwAuthToken(const AuthToken &token, uint8_t out[kHwAuthTokenSize]);
bool parseHwAuthToken(const uint8_t *data, size_t len, AuthToken *out);

} // namespace biometry

#endif // BIOMETRY_GATEKEEPER_H_
