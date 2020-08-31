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
function testEncryptAndDecryptWithAesEcbNoPadding() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    int i = 0;
    while(i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = checkpanic encryptAesEcb(message, key, NONE);
    byte[] plainText = checkpanic decryptAesEcb(cipherText, key, NONE);
    test:assertEquals(plainText.toBase16(), message.toBase16(), msg = "Error while Encrypt/Decrypt with AES ECB.");
}

@test:Config {}
function testEncryptAndDecryptWithAesEcbNoPaddingUsingInvalidKeySize() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    int i = 0;
    byte[] invalidKey = [];
    while(i < 31) {
        invalidKey[i] = <byte> i;
        i = i + 1;
    }
    byte[]|error result = encryptAesEcb(message, invalidKey, NONE);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result), "Invalid key size. valid key sizes in bytes: [16, 24, 32]",
            msg = "Incorrect error for invalid key while No Padding Encryption with AES ECB.");
    } else {
        test:assertFail(msg = "No error for invalid key while No Padding Encryption with AES ECB.");
    }
}

@test:Config {}
function testEncryptAndDecryptWithAesEcbNoPaddingUsingInvalidInputLength() {
    byte[] invalidMessage = "Ballerina crypto test".toBytes();
    byte[] key = [];
    int i = 0;
    while(i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    byte[]|error result = encryptAesEcb(invalidMessage, key, NONE);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result),
            "Error occurred while AES encrypt/decrypt: Input length not multiple of 16 bytes",
            msg = "Incorrect error for for invalid input length while No Padding Encryption with AES ECB.");
    } else {
        test:assertFail(msg = "No error for invalid input length while No Padding Encryption with AES ECB.");
    }
}

@test:Config {}
function testEncryptAndDecryptWithAesEcbPkcs5() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    int i = 0;
    while(i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    message = "Ballerina crypto test".toBytes();
    byte[] cipherText = checkpanic encryptAesEcb(message, key, "PKCS5");
    byte[] plainText = checkpanic decryptAesEcb(cipherText, key, "PKCS5");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with AES ECB PKCS5.");
}
