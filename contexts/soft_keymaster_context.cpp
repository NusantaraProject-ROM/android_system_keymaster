/*
 * Copyright 2015 The Android Open Source Project
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

#include <keymaster/contexts/soft_keymaster_context.h>

#include <memory>

#include <openssl/rand.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/key_blob_utils/auth_encrypted_key_blob.h>
#include <keymaster/key_blob_utils/integrity_assured_key_blob.h>
#include <keymaster/key_blob_utils/ocb_utils.h>
#include <keymaster/legacy_support/ec_keymaster0_key.h>
#include <keymaster/legacy_support/ec_keymaster1_key.h>
#include <keymaster/legacy_support/keymaster0_engine.h>
#include <keymaster/legacy_support/rsa_keymaster0_key.h>
#include <keymaster/legacy_support/rsa_keymaster1_key.h>
#include <keymaster/km_openssl/aes_key.h>
#include <keymaster/km_openssl/asymmetric_key.h>
#include <keymaster/km_openssl/attestation_utils.h>
#include <keymaster/km_openssl/hmac_key.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/logger.h>

#include "soft_attestation_cert.h"

using std::unique_ptr;

namespace keymaster {

namespace {
static uint8_t master_key_bytes[AES_BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const KeymasterKeyBlob MASTER_KEY(master_key_bytes, array_length(master_key_bytes));

bool UpgradeIntegerTag(keymaster_tag_t tag, uint32_t value, AuthorizationSet* set,
                       bool* set_changed) {
    int index = set->find(tag);
    if (index == -1) {
        keymaster_key_param_t param;
        param.tag = tag;
        param.integer = value;
        set->push_back(param);
        *set_changed = true;
        return true;
    }

    if (set->params[index].integer > value)
        return false;

    if (set->params[index].integer != value) {
        set->params[index].integer = value;
        *set_changed = true;
    }
    return true;
}

}  // anonymous namespace

SoftKeymasterContext::SoftKeymasterContext(const std::string& root_of_trust)
    : rsa_factory_(new RsaKeyFactory(this)), ec_factory_(new EcKeyFactory(this)),
      aes_factory_(new AesKeyFactory(this, this)), hmac_factory_(new HmacKeyFactory(this, this)),
      km1_dev_(nullptr), root_of_trust_(root_of_trust), os_version_(0), os_patchlevel_(0) {}

SoftKeymasterContext::~SoftKeymasterContext() {}

keymaster_error_t SoftKeymasterContext::SetHardwareDevice(keymaster0_device_t* keymaster0_device) {
    if (!keymaster0_device)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if ((keymaster0_device->flags & KEYMASTER_SOFTWARE_ONLY) != 0) {
        LOG_E("SoftKeymasterContext only wraps hardware keymaster0 devices", 0);
        return KM_ERROR_INVALID_ARGUMENT;
    }

    km0_engine_.reset(new Keymaster0Engine(keymaster0_device));
    rsa_factory_.reset(new RsaKeymaster0KeyFactory(this, km0_engine_.get()));
    ec_factory_.reset(new EcdsaKeymaster0KeyFactory(this, km0_engine_.get()));
    // Keep AES and HMAC factories.

    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::SetHardwareDevice(keymaster1_device_t* keymaster1_device) {
    if (!keymaster1_device)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    km1_dev_ = keymaster1_device;

    km1_engine_.reset(new Keymaster1Engine(keymaster1_device));
    rsa_factory_.reset(new RsaKeymaster1KeyFactory(this, km1_engine_.get()));
    ec_factory_.reset(new EcdsaKeymaster1KeyFactory(this, km1_engine_.get()));

    // Use default HMAC and AES key factories. Higher layers will pass HMAC/AES keys/ops that are
    // supported by the hardware to it and other ones to the software-only factory.

    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::SetSystemVersion(uint32_t os_version,
                                                         uint32_t os_patchlevel) {
    os_version_ = os_version;
    os_patchlevel_ = os_patchlevel;
    return KM_ERROR_OK;
}

void SoftKeymasterContext::GetSystemVersion(uint32_t* os_version, uint32_t* os_patchlevel) const {
    *os_version = os_version_;
    *os_patchlevel = os_patchlevel_;
}

KeyFactory* SoftKeymasterContext::GetKeyFactory(keymaster_algorithm_t algorithm) const {
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return rsa_factory_.get();
    case KM_ALGORITHM_EC:
        return ec_factory_.get();
    case KM_ALGORITHM_AES:
        return aes_factory_.get();
    case KM_ALGORITHM_HMAC:
        return hmac_factory_.get();
    default:
        return nullptr;
    }
}

static keymaster_algorithm_t supported_algorithms[] = {KM_ALGORITHM_RSA, KM_ALGORITHM_EC,
                                                       KM_ALGORITHM_AES, KM_ALGORITHM_HMAC};

keymaster_algorithm_t*
SoftKeymasterContext::GetSupportedAlgorithms(size_t* algorithms_count) const {
    *algorithms_count = array_length(supported_algorithms);
    return supported_algorithms;
}

OperationFactory* SoftKeymasterContext::GetOperationFactory(keymaster_algorithm_t algorithm,
                                                            keymaster_purpose_t purpose) const {
    KeyFactory* key_factory = GetKeyFactory(algorithm);
    if (!key_factory)
        return nullptr;
    return key_factory->GetOperationFactory(purpose);
}

static keymaster_error_t TranslateAuthorizationSetError(AuthorizationSet::Error err) {
    switch (err) {
    case AuthorizationSet::OK:
        return KM_ERROR_OK;
    case AuthorizationSet::ALLOCATION_FAILURE:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    case AuthorizationSet::MALFORMED_DATA:
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t SetAuthorizations(const AuthorizationSet& key_description,
                                           keymaster_key_origin_t origin, uint32_t os_version,
                                           uint32_t os_patchlevel, AuthorizationSet* hw_enforced,
                                           AuthorizationSet* sw_enforced) {
    sw_enforced->Clear();

    for (auto& entry : key_description) {
        switch (entry.tag) {
        // These cannot be specified by the client.
        case KM_TAG_ROOT_OF_TRUST:
        case KM_TAG_ORIGIN:
            LOG_E("Root of trust and origin tags may not be specified", 0);
            return KM_ERROR_INVALID_TAG;

        // These don't work.
        case KM_TAG_ROLLBACK_RESISTANT:
            LOG_E("KM_TAG_ROLLBACK_RESISTANT not supported", 0);
            return KM_ERROR_UNSUPPORTED_TAG;

        // These are hidden.
        case KM_TAG_APPLICATION_ID:
        case KM_TAG_APPLICATION_DATA:
            break;

        // Everything else we just copy into sw_enforced, unless the KeyFactory has placed it in
        // hw_enforced, in which case we defer to its decision.
        default:
            if (hw_enforced->GetTagCount(entry.tag) == 0)
                sw_enforced->push_back(entry);
            break;
        }
    }

    sw_enforced->push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));
    sw_enforced->push_back(TAG_ORIGIN, origin);
    sw_enforced->push_back(TAG_OS_VERSION, os_version);
    sw_enforced->push_back(TAG_OS_PATCHLEVEL, os_patchlevel);

    return TranslateAuthorizationSetError(sw_enforced->is_valid());
}

keymaster_error_t SoftKeymasterContext::CreateKeyBlob(const AuthorizationSet& key_description,
                                                      const keymaster_key_origin_t origin,
                                                      const KeymasterKeyBlob& key_material,
                                                      KeymasterKeyBlob* blob,
                                                      AuthorizationSet* hw_enforced,
                                                      AuthorizationSet* sw_enforced) const {
    keymaster_error_t error = SetAuthorizations(key_description, origin, os_version_,
                                                os_patchlevel_, hw_enforced, sw_enforced);
    if (error != KM_ERROR_OK)
        return error;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(key_description, &hidden);
    if (error != KM_ERROR_OK)
        return error;

    return SerializeIntegrityAssuredBlob(key_material, hidden, *hw_enforced, *sw_enforced, blob);
}

keymaster_error_t SoftKeymasterContext::UpgradeKeyBlob(const KeymasterKeyBlob& key_to_upgrade,
                                                       const AuthorizationSet& upgrade_params,
                                                       KeymasterKeyBlob* upgraded_key) const {
    KeymasterKeyBlob key_material;
    AuthorizationSet tee_enforced;
    AuthorizationSet sw_enforced;
    keymaster_error_t error =
        ParseKeyBlob(key_to_upgrade, upgrade_params, &key_material, &tee_enforced, &sw_enforced);
    if (error != KM_ERROR_OK)
        return error;

    // Three cases here:
    //
    // 1. Software key blob.  Version info, if present, is in sw_enforced.  If not present, we
    //    should add it.
    //
    // 2. Keymaster0 hardware key blob.  Version info, if present, is in sw_enforced.  If not
    //    present we should add it.
    //
    // 3. Keymaster1 hardware key blob.  Version info is not present and we shouldn't have been
    //    asked to upgrade.

    // Handle case 3.
    if (km1_dev_ && tee_enforced.Contains(TAG_PURPOSE) && !tee_enforced.Contains(TAG_OS_PATCHLEVEL))
        return KM_ERROR_INVALID_ARGUMENT;

    // Handle cases 1 & 2.
    bool set_changed = false;

    if (os_version_ == 0) {
        // We need to allow "upgrading" OS version to zero, to support upgrading from proper
        // numbered releases to unnumbered development and preview releases.

        int key_os_version_pos = sw_enforced.find(TAG_OS_VERSION);
        if (key_os_version_pos != -1) {
            uint32_t key_os_version = sw_enforced[key_os_version_pos].integer;
            if (key_os_version != 0) {
                sw_enforced[key_os_version_pos].integer = os_version_;
                set_changed = true;
            }
        }
    }

    if (!UpgradeIntegerTag(TAG_OS_VERSION, os_version_, &sw_enforced, &set_changed) ||
        !UpgradeIntegerTag(TAG_OS_PATCHLEVEL, os_patchlevel_, &sw_enforced, &set_changed))
        // One of the version fields would have been a downgrade. Not allowed.
        return KM_ERROR_INVALID_ARGUMENT;

    if (!set_changed)
        // Dont' need an upgrade.
        return KM_ERROR_OK;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(upgrade_params, &hidden);
    if (error != KM_ERROR_OK)
        return error;
    return SerializeIntegrityAssuredBlob(key_material, hidden, tee_enforced, sw_enforced,
                                         upgraded_key);
}

static keymaster_error_t ParseOcbAuthEncryptedBlob(const KeymasterKeyBlob& blob,
                                                   const AuthorizationSet& hidden,
                                                   KeymasterKeyBlob* key_material,
                                                   AuthorizationSet* hw_enforced,
                                                   AuthorizationSet* sw_enforced) {
    Buffer nonce, tag;
    KeymasterKeyBlob encrypted_key_material;
    keymaster_error_t error = DeserializeAuthEncryptedBlob(blob, &encrypted_key_material,
                                                           hw_enforced, sw_enforced, &nonce, &tag);
    if (error != KM_ERROR_OK)
        return error;

    if (nonce.available_read() != OCB_NONCE_LENGTH || tag.available_read() != OCB_TAG_LENGTH)
        return KM_ERROR_INVALID_KEY_BLOB;

    return OcbDecryptKey(*hw_enforced, *sw_enforced, hidden, MASTER_KEY, encrypted_key_material,
                         nonce, tag, key_material);
}

// Note: This parsing code in below is from system/security/softkeymaster/keymaster_openssl.cpp's
// unwrap_key function, modified for the preferred function signature and formatting.  It does some
// odd things, but they have been left unchanged to avoid breaking compatibility.
static const uint8_t SOFT_KEY_MAGIC[] = {'P', 'K', '#', '8'};
keymaster_error_t SoftKeymasterContext::ParseOldSoftkeymasterBlob(
    const KeymasterKeyBlob& blob, KeymasterKeyBlob* key_material, AuthorizationSet* hw_enforced,
    AuthorizationSet* sw_enforced) const {
    long publicLen = 0;
    long privateLen = 0;
    const uint8_t* p = blob.key_material;
    const uint8_t* end = blob.key_material + blob.key_material_size;

    int type = 0;
    ptrdiff_t min_size =
        sizeof(SOFT_KEY_MAGIC) + sizeof(type) + sizeof(publicLen) + 1 + sizeof(privateLen) + 1;
    if (end - p < min_size) {
        LOG_W("key blob appears to be truncated (if an old SW key)", 0);
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    if (memcmp(p, SOFT_KEY_MAGIC, sizeof(SOFT_KEY_MAGIC)) != 0)
        return KM_ERROR_INVALID_KEY_BLOB;
    p += sizeof(SOFT_KEY_MAGIC);

    for (size_t i = 0; i < sizeof(type); i++)
        type = (type << 8) | *p++;

    for (size_t i = 0; i < sizeof(type); i++)
        publicLen = (publicLen << 8) | *p++;

    if (p + publicLen > end) {
        LOG_W("public key length encoding error: size=%ld, end=%td", publicLen, end - p);
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    p += publicLen;

    if (end - p < 2) {
        LOG_W("key blob appears to be truncated (if an old SW key)", 0);
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    for (size_t i = 0; i < sizeof(type); i++)
        privateLen = (privateLen << 8) | *p++;

    if (p + privateLen > end) {
        LOG_W("private key length encoding error: size=%ld, end=%td", privateLen, end - p);
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    // Just to be sure, make sure that the ASN.1 structure parses correctly.  We don't actually use
    // the EVP_PKEY here.
    const uint8_t* key_start = p;
    unique_ptr<EVP_PKEY, EVP_PKEY_Delete> pkey(d2i_PrivateKey(type, nullptr, &p, privateLen));
    if (pkey.get() == nullptr) {
        LOG_W("Failed to parse PKCS#8 key material (if old SW key)", 0);
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    // All auths go into sw_enforced, including those that would be HW-enforced if we were faking
    // auths for a HW-backed key.
    hw_enforced->Clear();
    keymaster_error_t error = FakeKeyAuthorizations(pkey.get(), sw_enforced, sw_enforced);
    if (error != KM_ERROR_OK)
        return error;

    if (!key_material->Reset(privateLen))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(key_material->writable_data(), key_start, privateLen);

    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::ParseKeyBlob(const KeymasterKeyBlob& blob,
                                                     const AuthorizationSet& additional_params,
                                                     KeymasterKeyBlob* key_material,
                                                     AuthorizationSet* hw_enforced,
                                                     AuthorizationSet* sw_enforced) const {
    // This is a little bit complicated.
    //
    // The SoftKeymasterContext has to handle a lot of different kinds of key blobs.
    //
    // 1.  New keymaster1 software key blobs.  These are integrity-assured but not encrypted.  The
    //     raw key material and auth sets should be extracted and returned.  This is the kind
    //     produced by this context when the KeyFactory doesn't use keymaster0 to back the keys.
    //
    // 2.  Old keymaster1 software key blobs.  These are OCB-encrypted with an all-zero master key.
    //     They should be decrypted and the key material and auth sets extracted and returned.
    //
    // 3.  Old keymaster0 software key blobs.  These are raw key material with a small header tacked
    //     on the front.  They don't have auth sets, so reasonable defaults are generated and
    //     returned along with the raw key material.
    //
    // 4.  New keymaster0 hardware key blobs.  These are integrity-assured but not encrypted (though
    //     they're protected by the keymaster0 hardware implementation).  The keymaster0 key blob
    //     and auth sets should be extracted and returned.
    //
    // 5.  Keymaster1 hardware key blobs.  These are raw hardware key blobs.  They contain auth
    //     sets, which we retrieve from the hardware module.
    //
    // 6.  Old keymaster0 hardware key blobs.  These are raw hardware key blobs.  They don't have
    //     auth sets so reasonable defaults are generated and returned along with the key blob.
    //
    // Determining what kind of blob has arrived is somewhat tricky.  What helps is that
    // integrity-assured and OCB-encrypted blobs are self-consistent and effectively impossible to
    // parse as anything else.  Old keymaster0 software key blobs have a header.  It's reasonably
    // unlikely that hardware keys would have the same header.  So anything that is neither
    // integrity-assured nor OCB-encrypted and lacks the old software key header is assumed to be
    // keymaster0 hardware.

    AuthorizationSet hidden;
    keymaster_error_t error = BuildHiddenAuthorizations(additional_params, &hidden);
    if (error != KM_ERROR_OK)
        return error;

    // Assume it's an integrity-assured blob (new software-only blob, or new keymaster0-backed
    // blob).
    error = DeserializeIntegrityAssuredBlob(blob, hidden, key_material, hw_enforced, sw_enforced);
    if (error != KM_ERROR_INVALID_KEY_BLOB)
        return error;

    // Wasn't an integrity-assured blob.  Maybe it's an OCB-encrypted blob.
    error = ParseOcbAuthEncryptedBlob(blob, hidden, key_material, hw_enforced, sw_enforced);
    if (error == KM_ERROR_OK)
        LOG_D("Parsed an old keymaster1 software key", 0);
    if (error != KM_ERROR_INVALID_KEY_BLOB)
        return error;

    // Wasn't an OCB-encrypted blob.  Maybe it's an old softkeymaster blob.
    error = ParseOldSoftkeymasterBlob(blob, key_material, hw_enforced, sw_enforced);
    if (error == KM_ERROR_OK)
        LOG_D("Parsed an old sofkeymaster key", 0);
    if (error != KM_ERROR_INVALID_KEY_BLOB)
        return error;

    if (km1_dev_)
        return ParseKeymaster1HwBlob(blob, additional_params, key_material, hw_enforced,
                                     sw_enforced);
    else if (km0_engine_)
        return ParseKeymaster0HwBlob(blob, key_material, hw_enforced, sw_enforced);

    return KM_ERROR_INVALID_KEY_BLOB;
}

keymaster_error_t SoftKeymasterContext::DeleteKey(const KeymasterKeyBlob& blob) const {
    if (km1_engine_) {
        // HACK. Due to a bug with Qualcomm's Keymaster implementation, which causes the device to
        // reboot if we pass it a key blob it doesn't understand, we need to check for software
        // keys.  If it looks like a software key there's nothing to do so we just return.
        KeymasterKeyBlob key_material;
        AuthorizationSet hw_enforced, sw_enforced;
        keymaster_error_t error = DeserializeIntegrityAssuredBlob_NoHmacCheck(
            blob, &key_material, &hw_enforced, &sw_enforced);
        if (error == KM_ERROR_OK) {
            return KM_ERROR_OK;
        }

        return km1_engine_->DeleteKey(blob);
    }

    if (km0_engine_) {
        // This could be a keymaster0 hardware key, and it could be either raw or encapsulated in an
        // integrity-assured blob.  If it's integrity-assured, we can't validate it strongly,
        // because we don't have the necessary additional_params data.  However, the probability
        // that anything other than an integrity-assured blob would have all of the structure
        // required to decode as a valid blob is low -- unless it's maliciously-constructed, but the
        // deserializer should be proof against bad data, as should the keymaster0 hardware.
        //
        // Thus, we first try to parse it as integrity-assured.  If that works, we pass the result
        // to the underlying hardware.  If not, we pass blob unmodified to the underlying hardware.
        KeymasterKeyBlob key_material;
        AuthorizationSet hw_enforced, sw_enforced;
        keymaster_error_t error = DeserializeIntegrityAssuredBlob_NoHmacCheck(
            blob, &key_material, &hw_enforced, &sw_enforced);
        if (error == KM_ERROR_OK && km0_engine_->DeleteKey(key_material))
            return KM_ERROR_OK;

        km0_engine_->DeleteKey(blob);

        // We succeed unconditionally at this point, even if delete failed.  Failure indicates that
        // either the blob is a software blob (which we can't distinguish with certainty without
        // additional_params) or because it is a hardware blob and the hardware failed.  In the
        // first case, there is no error.  In the second case, the client can't do anything to fix
        // it anyway, so it's not too harmful to simply swallow the error.  This is not ideal, but
        // it's the least-bad alternative.
        return KM_ERROR_OK;
    }

    // Nothing to do for software-only contexts.
    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::DeleteAllKeys() const {
    if (km1_engine_)
        return km1_engine_->DeleteAllKeys();

    if (km0_engine_ && !km0_engine_->DeleteAllKeys())
        return KM_ERROR_UNKNOWN_ERROR;

    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::AddRngEntropy(const uint8_t* buf, size_t length) const {
    RAND_add(buf, length, 0 /* Don't assume any entropy is added to the pool. */);
    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::ParseKeymaster1HwBlob(
    const KeymasterKeyBlob& blob, const AuthorizationSet& additional_params,
    KeymasterKeyBlob* key_material, AuthorizationSet* hw_enforced,
    AuthorizationSet* sw_enforced) const {
    assert(km1_dev_);

    keymaster_blob_t client_id = {nullptr, 0};
    keymaster_blob_t app_data = {nullptr, 0};
    keymaster_blob_t* client_id_ptr = nullptr;
    keymaster_blob_t* app_data_ptr = nullptr;
    if (additional_params.GetTagValue(TAG_APPLICATION_ID, &client_id))
        client_id_ptr = &client_id;
    if (additional_params.GetTagValue(TAG_APPLICATION_DATA, &app_data))
        app_data_ptr = &app_data;

    // Get key characteristics, which incidentally verifies that the HW recognizes the key.
    keymaster_key_characteristics_t* characteristics;
    keymaster_error_t error = km1_dev_->get_key_characteristics(km1_dev_, &blob, client_id_ptr,
                                                                app_data_ptr, &characteristics);
    if (error != KM_ERROR_OK)
        return error;
    unique_ptr<keymaster_key_characteristics_t, Characteristics_Delete> characteristics_deleter(
        characteristics);

    LOG_D("Module \"%s\" accepted key", km1_dev_->common.module->name);

    hw_enforced->Reinitialize(characteristics->hw_enforced);
    sw_enforced->Reinitialize(characteristics->sw_enforced);
    *key_material = blob;
    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::ParseKeymaster0HwBlob(const KeymasterKeyBlob& blob,
                                                              KeymasterKeyBlob* key_material,
                                                              AuthorizationSet* hw_enforced,
                                                              AuthorizationSet* sw_enforced) const {
    assert(km0_engine_);

    unique_ptr<EVP_PKEY, EVP_PKEY_Delete> tmp_key(km0_engine_->GetKeymaster0PublicKey(blob));

    if (!tmp_key)
        return KM_ERROR_INVALID_KEY_BLOB;

    LOG_D("Module \"%s\" accepted key", km0_engine_->device()->common.module->name);
    keymaster_error_t error = FakeKeyAuthorizations(tmp_key.get(), hw_enforced, sw_enforced);
    if (error == KM_ERROR_OK)
        *key_material = blob;

    return error;
}

keymaster_error_t SoftKeymasterContext::FakeKeyAuthorizations(EVP_PKEY* pubkey,
                                                              AuthorizationSet* hw_enforced,
                                                              AuthorizationSet* sw_enforced) const {
    hw_enforced->Clear();
    sw_enforced->Clear();

    switch (EVP_PKEY_type(pubkey->type)) {
    case EVP_PKEY_RSA: {
        hw_enforced->push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_NONE);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_MD5);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA1);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_224);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_384);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_512);
        hw_enforced->push_back(TAG_PADDING, KM_PAD_NONE);
        hw_enforced->push_back(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_SIGN);
        hw_enforced->push_back(TAG_PADDING, KM_PAD_RSA_PKCS1_1_5_ENCRYPT);
        hw_enforced->push_back(TAG_PADDING, KM_PAD_RSA_PSS);
        hw_enforced->push_back(TAG_PADDING, KM_PAD_RSA_OAEP);

        sw_enforced->push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
        sw_enforced->push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);
        sw_enforced->push_back(TAG_PURPOSE, KM_PURPOSE_ENCRYPT);
        sw_enforced->push_back(TAG_PURPOSE, KM_PURPOSE_DECRYPT);

        unique_ptr<RSA, RSA_Delete> rsa(EVP_PKEY_get1_RSA(pubkey));
        if (!rsa)
            return TranslateLastOpenSslError();
        hw_enforced->push_back(TAG_KEY_SIZE, RSA_size(rsa.get()) * 8);
        uint64_t public_exponent = BN_get_word(rsa->e);
        if (public_exponent == 0xffffffffL)
            return KM_ERROR_INVALID_KEY_BLOB;
        hw_enforced->push_back(TAG_RSA_PUBLIC_EXPONENT, public_exponent);
        break;
    }

    case EVP_PKEY_EC: {
        hw_enforced->push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_NONE);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_MD5);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA1);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_224);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_256);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_384);
        hw_enforced->push_back(TAG_DIGEST, KM_DIGEST_SHA_2_512);

        sw_enforced->push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
        sw_enforced->push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);

        UniquePtr<EC_KEY, EC_KEY_Delete> ec_key(EVP_PKEY_get1_EC_KEY(pubkey));
        if (!ec_key.get())
            return TranslateLastOpenSslError();
        size_t key_size_bits;
        keymaster_error_t error =
            ec_get_group_size(EC_KEY_get0_group(ec_key.get()), &key_size_bits);
        if (error != KM_ERROR_OK)
            return error;
        hw_enforced->push_back(TAG_KEY_SIZE, key_size_bits);
        break;
    }

    default:
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }

    sw_enforced->push_back(TAG_ALL_USERS);
    sw_enforced->push_back(TAG_NO_AUTH_REQUIRED);

    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::BuildHiddenAuthorizations(const AuthorizationSet& input_set,
                                                                  AuthorizationSet* hidden) const {
    keymaster_blob_t entry;
    if (input_set.GetTagValue(TAG_APPLICATION_ID, &entry))
        hidden->push_back(TAG_APPLICATION_ID, entry.data, entry.data_length);
    if (input_set.GetTagValue(TAG_APPLICATION_DATA, &entry))
        hidden->push_back(TAG_APPLICATION_DATA, entry.data, entry.data_length);

    hidden->push_back(TAG_ROOT_OF_TRUST, reinterpret_cast<const uint8_t*>(root_of_trust_.data()),
                      root_of_trust_.size());

    return TranslateAuthorizationSetError(hidden->is_valid());
}


keymaster_error_t SoftKeymasterContext::GenerateAttestation(const Key& key,
        const AuthorizationSet& attest_params, const AuthorizationSet& tee_enforced,
        const AuthorizationSet& sw_enforced, CertChainPtr* cert_chain) const {

    keymaster_error_t error = KM_ERROR_OK;
    keymaster_algorithm_t key_algorithm;
    if (!key.authorizations().GetTagValue(TAG_ALGORITHM, &key_algorithm)) {
        return KM_ERROR_UNKNOWN_ERROR;
    }

    if ((key_algorithm != KM_ALGORITHM_RSA && key_algorithm != KM_ALGORITHM_EC))
        return KM_ERROR_INCOMPATIBLE_ALGORITHM;

    // We have established that the given key has the correct algorithm, and because this is the
    // SoftKeymasterContext we can assume that the Key is an AsymmetricKey. So we can downcast.
    const AsymmetricKey& asymmetric_key = static_cast<const AsymmetricKey&>(key);

    auto attestation_chain = getAttestationChain(key_algorithm, &error);
    if (error != KM_ERROR_OK) return error;

    auto attestation_key = getAttestationKey(key_algorithm, &error);
    if (error != KM_ERROR_OK) return error;

    return generate_attestation(asymmetric_key, attest_params, tee_enforced, sw_enforced,
            *attestation_chain, *attestation_key, *this, cert_chain);
}


}  // namespace keymaster
