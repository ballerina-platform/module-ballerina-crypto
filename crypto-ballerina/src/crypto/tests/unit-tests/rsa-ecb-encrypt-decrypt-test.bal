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
function testEncryptAndDecryptWithRsaEcbPkcs1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, puk, "PKCS1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, prk, "PKCS1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB PKCS1.");
}

@test:Config {}
function testEncryptAndDecryptWithRsaEcbOAEPwithMd5andMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPwithMD5andMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPwithMD5andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithMD5andMGF1.");
}

@test:Config {}
function testEncryptAndDecryptWithRsaEcbOaepWithSha1AndMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPWithSHA1AndMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPWithSHA1AndMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPWithSHA1AndMGF1.");
}

@test:Config {}
function testEncryptAndDecryptWithRsaEcbOaepWithSha256AndMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPWithSHA256AndMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPWithSHA256AndMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPWithSHA256AndMGF1.");
}

@test:Config {}
function testEncryptAndDecryptWithRsaEcbOaepWithSha384andMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPwithSHA384andMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPwithSHA384andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithSHA384andMGF1.");
}

@test:Config {}
function testEncryptAndDecryptWithRsaEcbOaepWithSha512andMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPwithSHA512andMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPwithSHA512andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithSHA512andMGF1.");
}

@test:Config {}
function testEncryptWithPrivateKeyAndDecryptWithPublicKeyUsingRsaEcbPkcs1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, prk, "PKCS1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, puk, "PKCS1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB PKCS1.");
}

@test:Config {}
function testEncryptAndDecryptWithRsaEcbPkcs1WithAnInvalidKey() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    PrivateKey invalidPrk = {algorithm:"RSA"};
    byte[]|error result = encryptRsaEcb(message, invalidPrk, "PKCS1");
    if (result is error) {
        test:assertEquals(extractErrorMessage(result), "Uninitialized private/public key",
            msg = "Incorrect error for for invalid key while Encryption with RSA ECB.");
    } else {
        test:assertFail(msg = "No error for invalid key Encryption with RSA ECB PKCS1.");
    }
}

function extractErrorMessage(byte[]|error result) returns string {
    if (result is error) {
        return <string>result.message();
    } else {
        return "";
    }
}
