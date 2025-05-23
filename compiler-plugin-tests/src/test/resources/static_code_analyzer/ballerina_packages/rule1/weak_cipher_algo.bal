// Copyright (c) 2025 WSO2 LLC. (http://www.wso2.com)
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

public function main() returns error? {
    byte[] inputBytes = "input".toBytes();
    byte[] keyBytes = "key".toBytes();

    // Encrypt using AES ECB mode is not secure
    _ = check crypto:encryptAesEcb(inputBytes, keyBytes);

    byte[] iv = "1234567890123456".toBytes();
    // Encrypt using AES CBC mode is secure
    _ = check crypto:encryptAesCbc(inputBytes, keyBytes, iv);

    crypto:KeyStore keyStore = {
        path: "/path/to/keyStore.p12",
        password: "keyStorePassword"
    };
    crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
    // Encrypt using RSA ECB with PKCS1 padding is not secure
    _ = check crypto:encryptRsaEcb(inputBytes, publicKey, crypto:PKCS1);
    _ = check crypto:encryptRsaEcb(inputBytes, publicKey, "PKCS1");

    // Default RSA ECB encryption uses PKCS1 padding. Hence, it is not secure
    _ = check crypto:encryptRsaEcb(inputBytes, publicKey);

    // Encrypt using RSA ECB with OAEP padding is secure
    _ = check crypto:encryptRsaEcb(inputBytes, publicKey, crypto:OAEPWithSHA1AndMGF1);
    _ = check crypto:encryptRsaEcb(inputBytes, publicKey, "OAEPWithSHA1AndMGF1");

}
