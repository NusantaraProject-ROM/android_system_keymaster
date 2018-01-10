/*
**
** Copyright 2017, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <keymaster/km_openssl/soft_keymaster_enforcement.h>

#include <assert.h>
#include <time.h>

#include <limits>

#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <keymaster/km_openssl/ckdf.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>

namespace keymaster {

namespace {

constexpr uint8_t kFakeKeyAgreementKey[32] = {};
constexpr const char* kSharedHmacLabel = "KeymasterSharedMac";
constexpr const char* kMacVerificationString = "Keymaster HMAC Verification";

class EvpMdCtx {
  public:
    EvpMdCtx() { EVP_MD_CTX_init(&ctx_); }
    ~EvpMdCtx() { EVP_MD_CTX_cleanup(&ctx_); }

    EVP_MD_CTX* get() { return &ctx_; }

  private:
    EVP_MD_CTX ctx_;
};

}  // anonymous namespace

uint32_t SoftKeymasterEnforcement::get_current_time() const {
    struct timespec tp;
    int err = clock_gettime(CLOCK_MONOTONIC, &tp);
    if (err || tp.tv_sec < 0 ||
        static_cast<unsigned long>(tp.tv_sec) > std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    return static_cast<uint32_t>(tp.tv_sec);
}

bool SoftKeymasterEnforcement::CreateKeyId(const keymaster_key_blob_t& key_blob,
                                           km_id_t* keyid) const {
    EvpMdCtx ctx;

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr /* ENGINE */) &&
        EVP_DigestUpdate(ctx.get(), key_blob.key_material, key_blob.key_material_size) &&
        EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
        assert(hash_len >= sizeof(*keyid));
        memcpy(keyid, hash, sizeof(*keyid));
        return true;
    }

    return false;
}

keymaster_error_t
SoftKeymasterEnforcement::GetHmacSharingParameters(HmacSharingParameters* params) {
    if (!have_saved_params_) {
        saved_params_.seed = {};
        RAND_bytes(saved_params_.nonce, 32);
        have_saved_params_ = true;
    }
    params->seed = saved_params_.seed;
    memcpy(params->nonce, saved_params_.nonce, sizeof(params->nonce));
    return KM_ERROR_OK;
}

keymaster_error_t hmacSha256(const keymaster_key_blob_t& key, const keymaster_blob_t& data,
                             KeymasterBlob* output) {
    if (!output) return KM_ERROR_UNEXPECTED_NULL_POINTER;

    unsigned digest_len = SHA256_DIGEST_LENGTH;
    if (!output->Reset(digest_len)) return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!::HMAC(EVP_sha256(), key.key_material, key.key_material_size, data.data, data.data_length,
                output->writable_data(), &digest_len)) {
        return TranslateLastOpenSslError();
    }
    if (digest_len != output->data_length) return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

namespace {

// Perhaps this shoud be in utils, but the impact of that needs to be considred carefully.  For now,
// just define it here.
inline bool operator==(const keymaster_blob_t& a, const keymaster_blob_t& b) {
    if (!a.data_length && !b.data_length) return true;
    if (!(a.data && b.data)) return a.data == b.data;
    return (a.data_length == b.data_length && !memcmp(a.data, b.data, a.data_length));
}

bool operator==(const HmacSharingParameters& a, const HmacSharingParameters& b) {
    return a.seed == b.seed && !memcmp(a.nonce, b.nonce, sizeof(a.nonce));
}

}  // namespace

keymaster_error_t
SoftKeymasterEnforcement::ComputeSharedHmac(const HmacSharingParametersArray& params_array,
                                            KeymasterBlob* sharingCheck) {
    size_t num_chunks = params_array.num_params * 2;
    UniquePtr<keymaster_blob_t[]> context_chunks(new (std::nothrow) keymaster_blob_t[num_chunks]);
    if (!context_chunks.get()) return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    bool found_mine = false;
    auto context_chunks_pos = context_chunks.get();
    for (auto& params : array_range(params_array.params_array, params_array.num_params)) {
        *context_chunks_pos++ = params.seed;
        *context_chunks_pos++ = {params.nonce, sizeof(params.nonce)};
        found_mine = found_mine || params == saved_params_;
    }
    assert(context_chunks_pos - num_chunks == context_chunks.get());

    if (!found_mine) return KM_ERROR_INVALID_ARGUMENT;

    if (!hmac_key_.Reset(SHA256_DIGEST_LENGTH)) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    keymaster_error_t error = ckdf(
        KeymasterKeyBlob(kFakeKeyAgreementKey, sizeof(kFakeKeyAgreementKey)),
        KeymasterBlob(reinterpret_cast<const uint8_t*>(kSharedHmacLabel), strlen(kSharedHmacLabel)),
        context_chunks.get(), num_chunks,  //
        &hmac_key_);
    if (error != KM_ERROR_OK) return error;

    keymaster_blob_t data = {reinterpret_cast<const uint8_t*>(kMacVerificationString),
                             strlen(kMacVerificationString)};
    return hmacSha256(hmac_key_, data, sharingCheck);
}

}  // namespace keymaster
