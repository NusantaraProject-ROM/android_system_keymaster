/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SYSTEM_KEYMASTER_ATTESTATION_RECORD_H_
#define SYSTEM_KEYMASTER_ATTESTATION_RECORD_H_

#include <hardware/keymaster_defs.h>

#include <keymaster/authorization_set.h>

namespace keymaster {

class AttestationRecordContext {
protected:
    virtual ~AttestationRecordContext() {}
public:
    /**
     * Returns the security level (SW or TEE) of this keymaster implementation.
     */
    virtual keymaster_security_level_t GetSecurityLevel() const {
        return KM_SECURITY_LEVEL_SOFTWARE;
    }

    /**
     * Verify that the device IDs provided in the attestation_params match the device's actual IDs
     * and copy them to attestation. If *any* of the IDs do not match or verification is not
     * possible, return KM_ERROR_CANNOT_ATTEST_IDS. If *all* IDs provided are successfully verified
     * or no IDs were provided, return KM_ERROR_OK.
     *
     * If you do not support device ID attestation, ignore all arguments and return
     * KM_ERROR_UNIMPLEMENTED.
     */
    virtual keymaster_error_t VerifyAndCopyDeviceIds(
        const AuthorizationSet& /* attestation_params */,
        AuthorizationSet* /* attestation */) const {
        return KM_ERROR_UNIMPLEMENTED;
    }
    /**
     * Generate the current unique ID.
     */
    virtual keymaster_error_t GenerateUniqueId(uint64_t /*creation_date_time*/,
                                               const keymaster_blob_t& /*application_id*/,
                                               bool /*reset_since_rotation*/,
                                               Buffer* /*unique_id*/) const {
        return KM_ERROR_UNIMPLEMENTED;
    }

    /**
     * Returns verified boot parameters for the Attestation Extension.  For hardware-based
     * implementations, these will be the values reported by the bootloader. By default,  verified
     * boot state is unknown, and KM_ERROR_UNIMPLEMENTED is returned.
     */
    virtual keymaster_error_t
    GetVerifiedBootParams(keymaster_blob_t* /* verified_boot_key */,
                          keymaster_verified_boot_t* /* verified_boot_state */,
                          bool* /* device_locked */) const {
        return KM_ERROR_UNIMPLEMENTED;
    }
};

/**
 * The OID for Android attestation records.  For the curious, it breaks down as follows:
 *
 * 1 = ISO
 * 3 = org
 * 6 = DoD (Huh? OIDs are weird.)
 * 1 = IANA
 * 4 = Private
 * 1 = Enterprises
 * 11129 = Google
 * 2 = Google security
 * 1 = certificate extension
 * 17 = Android attestation extension.
 */
static const char kAttestionRecordOid[] = "1.3.6.1.4.1.11129.2.1.17";

keymaster_error_t build_attestation_record(const AuthorizationSet& attestation_params,
                                           AuthorizationSet software_enforced,
                                           AuthorizationSet tee_enforced,
                                           const AttestationRecordContext& context,
                                           UniquePtr<uint8_t[]>* asn1_key_desc,
                                           size_t* asn1_key_desc_len);

/**
 * helper function for attestation record test.
 */
keymaster_error_t parse_attestation_record(const uint8_t* asn1_key_desc, size_t asn1_key_desc_len,
                                           uint32_t* attestation_version,  //
                                           keymaster_security_level_t* attestation_security_level,
                                           uint32_t* keymaster_version,
                                           keymaster_security_level_t* keymaster_security_level,
                                           keymaster_blob_t* attestation_challenge,
                                           AuthorizationSet* software_enforced,
                                           AuthorizationSet* tee_enforced,
                                           keymaster_blob_t* unique_id);
}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_ATTESTATION_RECORD_H_
