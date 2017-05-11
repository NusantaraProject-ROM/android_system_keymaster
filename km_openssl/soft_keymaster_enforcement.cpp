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

#include <openssl/evp.h>

namespace keymaster {

namespace {

class EvpMdCtx {
  public:
    EvpMdCtx() { EVP_MD_CTX_init(&ctx_); }
    ~EvpMdCtx() { EVP_MD_CTX_cleanup(&ctx_); }

    EVP_MD_CTX* get() { return &ctx_; }

  private:
    EVP_MD_CTX ctx_;
};

} // anonymous namespace

uint32_t SoftKeymasterEnforcement::get_current_time() const {
    struct timespec tp;
    int err = clock_gettime(CLOCK_MONOTONIC, &tp);
    if (err || tp.tv_sec < 0 ||
            static_cast<unsigned long>(tp.tv_sec) > std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    return static_cast<uint32_t>(tp.tv_sec);
}

bool SoftKeymasterEnforcement::CreateKeyId(const keymaster_key_blob_t& key_blob, km_id_t* keyid) const {
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

} // namespace keymaster
