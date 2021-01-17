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

@test:Config {}
isolated function testEncryptAndDecryptWithAesGcmNoPadding() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while (i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while (i < 16) {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = checkpanic encryptAesGcm(message, key, iv, NONE, 128);
    byte[] plainText = checkpanic decryptAesGcm(cipherText, key, iv, NONE, 128);
    test:assertEquals(plainText.toBase16(), message.toBase16(), msg = "Error while Encrypt/Decrypt with AES GCM.");
}

@test:Config {
    enable: false
}
isolated function testEncryptWithAesGcmNoPaddingUsingInvalidInputLength() {
    byte[] invalidMessage = "Ballerina crypto test".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while (i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while (i < 16) {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[]|Error result = encryptAesGcm(invalidMessage, key, iv, NONE);
    if (result is Error) {
        test:assertEquals(result.message(), "Invalid key size. valid key sizes in bytes: [16, 24, 32]",
            msg = "Incorrect error for invalid key while No Padding Encryption with AES GCM.");
    } else {
        test:assertFail(msg = "No error for invalid input length while No Padding Encryption with AES GCM.");
    }
}

@test:Config {}
isolated function testEncryptAndDecryptWithAesGcmNoPaddingUsingInvalidKeySize() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] iv = [];
    int i = 0;
    byte[] invalidKey = [];
    while (i < 31) {
        invalidKey[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while (i < 16) {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[]|Error result = encryptAesGcm(message, invalidKey, iv, NONE, 128);
    if (result is Error) {
        test:assertEquals(result.message(), "Invalid key size. valid key sizes in bytes: [16, 24, 32]",
            msg = "Incorrect error for invalid key while No Padding Encryption with AES GCM.");
    } else {
        test:assertFail(msg = "No error for invalid key while No Padding Encryption with AES GCM.");
    }
}

@test:Config {}
isolated function testEncryptAndDecryptWithAesGcmPkcs5() {
    byte[] message = "Ballerina crypto test".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while (i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while (i < 16) {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = checkpanic encryptAesGcm(message, key, iv, "PKCS5");
    byte[] plainText = checkpanic decryptAesGcm(cipherText, key, iv, "PKCS5");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with AES GCM PKCS5.");
}

@test:Config {}
isolated function testEncryptAndDecryptWithAesGcmPkcs5WithInvalidTagValue() {
    byte[] message = "Ballerina crypto test".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while (i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while (i < 16) {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[]|Error result = encryptAesGcm(message, key, iv, "PKCS5", 500);
    if (result is Error) {
        test:assertTrue(result.message().includes("Invalid tag size. valid tag sizes in bytes:"),
            msg = "Incorrect error for invalid key while Encryption with AES GCM PKCS5.");
    } else {
        test:assertFail(msg = "No error for invalid tag size while Encryption with AES GCM PKCS5.");
    }
}
