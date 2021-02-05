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
isolated function testEncryptAndDecryptWithRsaEcbPkcs1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKey({ trustStore: keyStore, certAlias: "ballerina" });
    PrivateKey privateKey = checkpanic decodeRsaPrivateKey({ keyStore: keyStore, keyAlias: "ballerina", keyPassword: "ballerina" });
    byte[] cipherText = checkpanic encryptRsaEcb(message, publicKey, "PKCS1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, privateKey, "PKCS1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB PKCS1.");
}

@test:Config {}
isolated function testEncryptAndDecryptWithRsaEcbOAEPwithMd5andMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKey({ trustStore: keyStore, certAlias: "ballerina" });
    PrivateKey privateKey = checkpanic decodeRsaPrivateKey({ keyStore: keyStore, keyAlias: "ballerina", keyPassword: "ballerina" });
    byte[] cipherText = checkpanic encryptRsaEcb(message, publicKey, "OAEPwithMD5andMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, privateKey, "OAEPwithMD5andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithMD5andMGF1.");
}

@test:Config {}
isolated function testEncryptAndDecryptWithRsaEcbOaepWithSha1AndMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKey({ trustStore: keyStore, certAlias: "ballerina" });
    PrivateKey privateKey = checkpanic decodeRsaPrivateKey({ keyStore: keyStore, keyAlias: "ballerina", keyPassword: "ballerina" });
    byte[] cipherText = checkpanic encryptRsaEcb(message, publicKey, "OAEPWithSHA1AndMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, privateKey, "OAEPWithSHA1AndMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPWithSHA1AndMGF1.");
}

@test:Config {}
isolated function testEncryptAndDecryptWithRsaEcbOaepWithSha256AndMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKey({ trustStore: keyStore, certAlias: "ballerina" });
    PrivateKey privateKey = checkpanic decodeRsaPrivateKey({ keyStore: keyStore, keyAlias: "ballerina", keyPassword: "ballerina" });
    byte[] cipherText = checkpanic encryptRsaEcb(message, publicKey, "OAEPWithSHA256AndMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, privateKey, "OAEPWithSHA256AndMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPWithSHA256AndMGF1.");
}

@test:Config {}
isolated function testEncryptAndDecryptWithRsaEcbOaepWithSha384andMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKey({ trustStore: keyStore, certAlias: "ballerina" });
    PrivateKey privateKey = checkpanic decodeRsaPrivateKey({ keyStore: keyStore, keyAlias: "ballerina", keyPassword: "ballerina" });
    byte[] cipherText = checkpanic encryptRsaEcb(message, publicKey, "OAEPwithSHA384andMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, privateKey, "OAEPwithSHA384andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithSHA384andMGF1.");
}

@test:Config {}
isolated function testEncryptAndDecryptWithRsaEcbOaepWithSha512andMgf1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKey({ trustStore: keyStore, certAlias: "ballerina" });
    PrivateKey privateKey = checkpanic decodeRsaPrivateKey({ keyStore: keyStore, keyAlias: "ballerina", keyPassword: "ballerina" });
    byte[] cipherText = checkpanic encryptRsaEcb(message, publicKey, "OAEPwithSHA512andMGF1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, privateKey, "OAEPwithSHA512andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithSHA512andMGF1.");
}

@test:Config {}
isolated function testEncryptWithPrivateKeyAndDecryptWithPublicKeyUsingRsaEcbPkcs1() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKey({ trustStore: keyStore, certAlias: "ballerina" });
    PrivateKey privateKey = checkpanic decodeRsaPrivateKey({ keyStore: keyStore, keyAlias: "ballerina", keyPassword: "ballerina" });
    byte[] cipherText = checkpanic encryptRsaEcb(message, privateKey, "PKCS1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, publicKey, "PKCS1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB PKCS1.");
}

@test:Config {}
isolated function testEncryptAndDecryptWithRsaEcbPkcs1WithAnInvalidKey() {
    byte[] message = "Ballerina crypto test           ".toBytes();
    PrivateKey invalidPrk = {algorithm:"RSA"};
    byte[]|Error result = encryptRsaEcb(message, invalidPrk, "PKCS1");
    if (result is Error) {
        test:assertEquals(result.message(), "Uninitialized private/public key",
            msg = "Incorrect error for for invalid key while Encryption with RSA ECB.");
    } else {
        test:assertFail(msg = "No error for invalid key Encryption with RSA ECB PKCS1.");
    }
}
