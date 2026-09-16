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

configurable byte[] configuredKey = ?;

function hardcodedHmacKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
}

function hardcodedAesKey(string data, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data.toBytes(), [9, 9, 9, 9, 9, 9, 9, 9], iv);
}

function hardcodedPassphrase(byte[] cipherText, string privateKeyPath) returns error? {
    byte[] _ = check crypto:decryptPgp(cipherText, privateKeyPath, "my-passphrase".toBytes());
}

// Negative case - key material supplied at deployment is the correct usage
function configuredHmacKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), configuredKey);
}
