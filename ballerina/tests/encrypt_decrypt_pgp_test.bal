// Copyright (c) 2020 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
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

import ballerina/test;
import ballerina/io;

@test:Config {}
isolated function testEncryptAndDecryptWithPgp() returns error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] passphrase = check io:fileReadBytes(PGP_PRIVATE_KEY_PASSPHRASE_PATH);
    byte[] publicKey = check io:fileReadBytes(PGP_PUBLIC_KEY_PATH);
    byte[] privateKey = check io:fileReadBytes(PGP_PRIVATE_KEY_PATH);
    byte[] cipherText = check encryptPgp(message, publicKey);
    byte[] plainText = check decryptPgp(cipherText, privateKey, passphrase);
    test:assertEquals(plainText.toBase16(), message.toBase16());
}

@test:Config {}
isolated function testEncryptAndDecryptWithPgpWithOptions() returns error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] passphrase = check io:fileReadBytes(PGP_PRIVATE_KEY_PASSPHRASE_PATH);
    byte[] publicKey = check io:fileReadBytes(PGP_PUBLIC_KEY_PATH);
    byte[] privateKey = check io:fileReadBytes(PGP_PRIVATE_KEY_PATH);
    byte[] cipherText = check encryptPgp(message, publicKey, symmetricKeyAlgorithm = AES_128, armor = false);
    byte[] plainText = check decryptPgp(cipherText, privateKey, passphrase);
    test:assertEquals(plainText.toBase16(), message.toBase16());
}
