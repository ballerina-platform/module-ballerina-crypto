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

const SECRET = "module-secret";

final byte[] FINAL_KEY = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

byte[] mutableKey = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

final byte[] moduleLevelMac = check crypto:hmacSha256("payload".toBytes(), [1, 2, 3, 4]);

function hardcodedHmacKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
}

function hardcodedAesKey(string data, byte[] iv) returns error? {
    byte[] _ = check crypto:encryptAesGcm(data.toBytes(), [9, 9, 9, 9, 9, 9, 9, 9], iv);
}

function hardcodedPassphrase(byte[] cipherText, string privateKeyPath) returns error? {
    byte[] _ = check crypto:decryptPgp(cipherText, privateKeyPath, "my-passphrase".toBytes());
}

function literalKeyInLocalVariable(string data) returns error? {
    byte[] key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    byte[] _ = check crypto:hmacSha256(data.toBytes(), key);
}

function stringKeyInLocalVariable(byte[] data) returns error? {
    byte[] keyBytes = "key".toBytes();
    byte[] _ = check crypto:encryptAesEcb(data, keyBytes);
}

function byteArrayLiteralKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), base16 `00112233445566778899aabbccddeeff`);
}

function constantKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), SECRET.toBytes());
}

function finalModuleKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), FINAL_KEY);
}

function embeddedPrivateKey() returns error? {
    crypto:PrivateKey _ = check crypto:decodeRsaPrivateKeyFromContent("-----BEGIN PRIVATE KEY-----".toBytes());
}

function hardcodedKeyingMaterial() returns error? {
    byte[] _ = check crypto:hkdfSha256([1, 2, 3, 4, 5, 6, 7, 8], 32);
}

function keyInNestedExpression(string data) returns error? {
    string _ = (check crypto:hmacSha256(data.toBytes(), [1, 2, 3, 4])).toBase16();
}

// Negative case - key material supplied at deployment is the correct usage
function configuredHmacKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), configuredKey);
}

// Negative case - a non-final module variable can be replaced before use
function mutableModuleKey(string data) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), mutableKey);
}

// Negative case - the key is overwritten element by element before use
function keyOverwrittenByElement(string data, byte[] randomBytes) returns error? {
    byte[] key = [0, 0, 0, 0];
    key[0] = randomBytes[0];
    byte[] _ = check crypto:hmacSha256(data.toBytes(), key);
}

// Negative case - the parameter shadows the module-level key
function shadowedKey(string data, byte[] FINAL_KEY) returns error? {
    byte[] _ = check crypto:hmacSha256(data.toBytes(), FINAL_KEY);
}
