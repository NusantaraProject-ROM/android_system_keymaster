/*
 * Copyright 2017 The Android Open Source Project
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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bytestring.h>

#include "wrapped_key.h"

namespace keymaster {

typedef struct km_wrapped_key {
    ASN1_OCTET_STRING* encrypted_ephemeral_key;
    ASN1_OCTET_STRING* iv;
    ASN1_INTEGER* key_format;
    // FIXME KM_AUTH_LIST* auth_list;
    ASN1_OCTET_STRING* secure_key;
    ASN1_OCTET_STRING* tag;
} KM_WRAPPED_KEY;

ASN1_SEQUENCE(KM_WRAPPED_KEY) = {
    ASN1_SIMPLE(KM_WRAPPED_KEY, encrypted_ephemeral_key, ASN1_OCTET_STRING),
    ASN1_SIMPLE(KM_WRAPPED_KEY, iv, ASN1_BOOLEAN),
    ASN1_SIMPLE(KM_WRAPPED_KEY, key_format, ASN1_INTEGER),
    // FIXME ASN1_SIMPLE(KM_WRAPPED_KEY, auth_list, KM_AUTH_LIST),
    ASN1_SIMPLE(KM_WRAPPED_KEY, secure_key, ASN1_INTEGER),
    ASN1_SIMPLE(KM_WRAPPED_KEY, tag, ASN1_INTEGER),
} ASN1_SEQUENCE_END(KM_WRAPPED_KEY);
IMPLEMENT_ASN1_FUNCTIONS(KM_WRAPPED_KEY);

// TODO replace with ASN1 structures defined in the style of attestation_record
void parseWrappedKey(const uint8_t* wrappedKeyData, size_t wrappedKeyDataLen, WrappedKeyData* wkd) {
    CBS cbs, sequence;
    CBS_init(&cbs, wrappedKeyData, wrappedKeyDataLen);

    CBS_get_asn1(&cbs, &sequence, CBS_ASN1_SEQUENCE);
    CBS_get_asn1(&sequence, &wkd->encryptedEphemeralKeys, CBS_ASN1_OCTETSTRING);
    CBS_get_asn1(&sequence, &wkd->iv, CBS_ASN1_OCTETSTRING);
    CBS_get_asn1_uint64(&sequence, &wkd->keyFormat);
    CBS_get_asn1(&sequence, &wkd->authList, CBS_ASN1_SEQUENCE);
    CBS_get_asn1(&sequence, &wkd->secureKey, CBS_ASN1_OCTETSTRING);
    CBS_get_asn1(&sequence, &wkd->tag, CBS_ASN1_OCTETSTRING);
}

} // namespace keymaster
