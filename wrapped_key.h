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

#ifndef SYSTEM_KEYMASTER_WRAPPED_KEY_H_
#define SYSTEM_KEYMASTER_WRAPPED_KEY_H_

namespace keymaster {

typedef struct wrapped_key_data {
    CBS encryptedEphemeralKeys, iv, authList, secureKey, tag;
    uint64_t keyFormat;
} WrappedKeyData;

void parseWrappedKey(const uint8_t* wrappedKeyData, size_t wrappedKeyDataLen, WrappedKeyData* wkd);

}  // namespace keymaster
#endif // SYSTEM_KEYMASTER_WRAPPED_KEY_H_
