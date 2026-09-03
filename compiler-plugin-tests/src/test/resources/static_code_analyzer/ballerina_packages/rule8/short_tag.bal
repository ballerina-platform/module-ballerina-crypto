// Copyright (c) 2026 WSO2 LLC. (http://www.wso2.com)
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/crypto;

const int SHORT_TAG = 32;

function shortTagInline(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = 64);
}

function shortTagConstant(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = SHORT_TAG);
}

function shortTagOnDecrypt(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:decryptAesGcm(data, key, iv, tagSize = 32);
}

// Negative cases - the documented minimum and the default are not flagged
function documentedMinimumTag(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = 96);
}

function defaultTag(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv);
}
