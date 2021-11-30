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
isolated function testEncryptAndDecryptWithAesCbcNoPadding() returns Error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while i < 16 {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while i < 16 {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = check encryptAesCbc(message, key, iv, NONE);
    byte[] plainText = check decryptAesCbc(cipherText, key, iv, NONE);
    test:assertEquals(plainText.toBase16(), message.toBase16());
}

@test:Config {}
isolated function testEncryptAndDecryptWithAesCbcNoPaddingUsingInvalidKeySize() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] iv = [];
    int i = 0;
    byte[] invalidKey = [];
    while i < 31 {
        invalidKey[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while i < 16 {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[]|Error result = encryptAesCbc(message, invalidKey, iv, NONE);
    if result is Error {
        test:assertEquals(result.message(), "Invalid key size. Valid key sizes in bytes: [16, 24, 32]");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testEncryptAndDecryptWithAesCbcNoPaddingUsingInvalidIVLength() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    int i = 0;
    while i < 16 {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    byte[] invalidIv = [];
    while i < 15 {
        invalidIv[i] = <byte> i;
        i = i + 1;
    }
    byte[]|Error result = encryptAesCbc(message, key, invalidIv, NONE);
    if result is Error {
        test:assertEquals(result.message(),
            "Error occurred while AES encrypt/decrypt: Wrong IV length: must be 16 bytes long");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testEncryptAndDecryptWithAesCbcNoPaddingUsingInvalidInputLength() {
    byte[] invalidMessage = "Ballerina crypto test".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while i < 16 {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while i < 16 {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[]|Error result = encryptAesCbc(invalidMessage, key, iv, NONE);
    if result is Error {
        test:assertEquals(result.message(),
            "Error occurred while AES encrypt/decrypt: Input length not multiple of 16 bytes");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testEncryptAndDecryptWithAesCbcPkcs5() returns Error? {
    byte[] message = "Ballerina crypto test".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while i < 16 {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while i < 16 {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = check encryptAesCbc(message, key, iv, "PKCS5");
    byte[] plainText = check decryptAesCbc(cipherText, key, iv, "PKCS5");
    test:assertEquals(plainText.toBase16(), message.toBase16());
}
