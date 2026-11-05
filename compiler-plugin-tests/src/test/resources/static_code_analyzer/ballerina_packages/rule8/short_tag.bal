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

configurable int configuredTagSize = 32;

int moduleTagSize = 32;

function shortTagInline(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = 32);
}

function shortTagConstant(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = SHORT_TAG);
}

function shortTagOnDecrypt(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:decryptAesGcm(data, key, iv, tagSize = 32);
}

function shortTagHexLiteral(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = 0x20);
}

function shortTagInLocalVariable(byte[] data, byte[] key, byte[] iv) returns error? {
    int tagSize = 32;
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = tagSize);
}

function shortTagInNestedCall(byte[] data, byte[] key, byte[] iv) returns error? {
    int _ = consume(check crypto:encryptAesGcm(data, key, iv, tagSize = 32));
}

function shortTagUnderTrap(byte[] data, byte[] key, byte[] iv) returns byte[]|error {
    return trap crypto:encryptAesGcm(data, key, iv, tagSize = 32);
}

// Negative cases - the documented minimum and the default are not flagged
function documentedMinimumTag(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = 96);
}

function defaultTag(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv);
}

// Negative cases - values that can change outside the analysed code are not resolved
function configurableTag(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = configuredTagSize);
}

function moduleVariableTag(byte[] data, byte[] key, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = moduleTagSize);
}

function shadowedTag(byte[] data, byte[] key, byte[] iv, int moduleTagSize) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = moduleTagSize);
}

function compoundAssignedTag(byte[] data, byte[] key, byte[] iv) returns error? {
    int tagSize = 32;
    tagSize += 96;
    byte[] _ = check crypto:encryptAesGcm(data, key, iv, tagSize = tagSize);
}

function consume(byte[] value) returns int => value.length();
