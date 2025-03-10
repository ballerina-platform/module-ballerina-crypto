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
isolated function testParseEncryptedPrivateKeyFromP12() returns Error? {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey result = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParseEncryptedMlKem768PrivateKeyFromP12() returns Error? {
    KeyStore keyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey result = check decodeMlKem768PrivateKeyFromKeyStore(keyStore, "mlkem-keypair", "ballerina");
    test:assertEquals(result.algorithm, "ML-KEM-768");
}

@test:Config {}
isolated function testParseEncryptedMlDsa65PrivateKeyFromP12() returns Error? {
    KeyStore keyStore = {
        path: MLDSA_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey result = check decodeMlDsa65PrivateKeyFromKeyStore(keyStore, "mldsa-keypair", "ballerina");
    test:assertEquals(result.algorithm, "ML-DSA-65");
}

@test:Config {}
isolated function testReadPrivateKeyFromNonExistingP12() {
    KeyStore keyStore = {
        path: INVALID_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("PKCS12 KeyStore not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadPrivateKeyFromP12WithInvalidKeyStorePassword() {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "invalid"
    };
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyStore(keyStore, "invalid", "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadEcPrivateKeyFromP12WithInvalidKeyStorePassword() {
    KeyStore keyStore = {
        path: EC_KEYSTORE_PATH,
        password: "invalid"
    };
    PrivateKey|Error result = decodeEcPrivateKeyFromKeyStore(keyStore, "ec-keypair", "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlKemPrivateKeyFromP12WithInvalidKeyStorePassword() {
    KeyStore keyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "invalid"
    };
    PrivateKey|Error result = decodeMlKem768PrivateKeyFromKeyStore(keyStore, "mlkem-keypair", "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlDsaPrivateKeyFromP12WithInvalidKeyStorePassword() {
    KeyStore keyStore = {
        path: MLDSA_KEYSTORE_PATH,
        password: "invalid"
    };
    PrivateKey|Error result = decodeMlDsa65PrivateKeyFromKeyStore(keyStore, "mldsa-keypair", "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadPrivateKeyFromP12WithInvalidAlias() {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyStore(keyStore, "invalid", "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("Key cannot be recovered by using given key alias:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadPrivateKeyFromP12WithInvalidKeyPassword() {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "invalid");
    if result is Error {
        test:assertTrue(result.message().includes("Key cannot be recovered:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testParsePrivateKeyFromKeyFile() returns Error? {
    PrivateKey result = check decodeRsaPrivateKeyFromKeyFile(PRIVATE_KEY_PATH);
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParsePrivateKeyFromContent() returns Error? {
    byte[] bytes = [45,45,45,45,45,66,69,71,73,78,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10,77,73,73,69,118,81,73,66,65,68,65,78,66,103,107,113,104,107,105,71,57,119,48,66,65,81,69,70,65,65,83,67,66,75,99,119,103,103,83,106,65,103,69,65,65,111,73,66,65,81,67,66,88,75,76,112,57,87,74,85,117,74,107,111,10,83,102,68,110,51,72,77,50,76,87,86,120,105,72,114,80,49,49,109,101,54,68,52,88,50,65,113,111,85,105,67,90,49,119,57,55,54,113,49,76,117,66,108,122,87,78,104,79,78,89,119,74,118,72,88,101,119,85,117,82,109,111,48,100,10,52,78,82,112,50,109,97,48,113,106,100,77,78,50,52,54,88,87,121,111,122,112,122,80,102,74,100,118,111,118,102,105,84,43,86,54,72,110,83,98,77,103,56,50,90,112,112,102,70,51,101,56,53,67,103,114,103,54,109,83,65,55,87,102,10,102,97,97,72,114,54,50,83,110,101,120,115,101,90,57,105,111,78,67,117,82,85,114,87,50,90,103,50,48,56,108,57,57,73,73,116,80,52,75,52,105,71,99,108,81,108,121,106,115,51,83,54,100,114,72,55,74,74,107,51,114,118,56,66,10,102,55,54,119,109,109,111,67,69,65,104,107,110,79,116,71,76,113,53,52,51,100,69,85,73,106,70,103,78,100,73,121,47,71,115,83,89,53,50,102,105,65,52,76,83,106,85,67,118,50,55,107,71,110,48,51,110,97,121,113,111,90,115,51,10,88,72,113,77,48,113,76,100,116,57,83,80,88,98,89,101,55,108,55,53,106,48,111,54,90,57,116,121,71,70,67,75,88,89,47,122,86,119,105,76,102,82,85,113,68,73,79,102,107,78,53,89,83,52,79,104,105,116,53,50,84,106,55,113,10,111,66,109,118,69,122,68,55,65,103,77,66,65,65,69,67,103,103,69,65,88,77,47,70,52,117,50,51,79,117,109,109,109,81,49,84,49,107,97,73,77,112,113,110,97,97,108,116,48,54,106,67,71,65,121,119,89,66,77,85,115,109,99,97,10,70,77,89,68,121,102,103,53,108,86,88,107,106,75,108,49,112,56,99,114,84,101,68,49,65,72,106,87,97,119,84,106,115,107,103,89,110,107,109,102,51,111,99,120,88,88,70,51,109,70,66,110,73,85,88,55,111,55,72,85,82,76,103,55,10,43,82,99,120,111,85,103,119,105,82,105,70,97,90,90,55,115,122,88,51,74,111,76,98,102,122,122,98,99,72,78,81,51,55,107,97,118,99,99,66,86,87,119,81,115,70,77,105,85,51,84,108,119,43,76,98,75,119,75,54,47,114,111,119,10,76,89,115,81,80,120,55,103,84,52,117,55,104,86,105,97,116,52,118,81,68,84,89,99,103,121,106,118,118,70,67,105,101,107,52,110,100,76,54,79,57,75,52,57,77,120,73,77,85,54,55,56,85,88,66,54,105,97,53,105,85,101,118,121,10,118,103,69,102,99,89,107,75,81,53,69,81,51,56,113,83,51,90,119,115,117,98,80,118,106,52,54,51,51,106,118,65,74,82,114,47,104,74,68,56,88,73,78,90,67,55,52,107,84,88,101,86,51,66,71,72,50,76,108,112,81,79,69,113,10,107,87,107,79,121,112,119,89,78,106,110,88,116,116,49,74,79,56,43,73,117,54,109,69,88,75,85,111,105,73,66,80,102,71,114,74,51,118,68,83,81,81,75,66,103,81,68,109,89,80,99,55,107,102,89,97,110,47,76,72,106,74,82,118,10,105,69,50,67,119,98,67,50,54,121,86,65,54,43,66,69,80,81,118,57,122,55,106,67,104,79,57,81,54,99,85,98,71,118,77,56,69,69,86,78,112,67,57,110,109,70,111,103,107,115,108,122,74,104,122,53,53,72,80,56,52,81,90,76,10,117,51,112,116,85,43,68,57,54,110,99,113,54,122,107,66,113,120,66,102,82,110,90,71,43,43,68,51,54,43,88,82,88,73,119,122,122,51,104,43,103,49,78,119,114,108,48,121,48,77,70,98,119,108,107,77,109,51,90,113,74,100,100,54,10,112,90,122,49,70,90,71,100,54,122,118,81,102,116,87,56,109,55,106,80,83,75,72,117,115,119,75,66,103,81,67,80,118,54,99,122,70,79,90,82,54,98,73,43,113,67,81,100,97,79,82,112,101,57,74,71,111,65,100,117,79,68,43,52,10,89,75,108,57,54,115,48,101,105,65,75,104,107,71,104,70,67,114,77,100,54,71,74,119,87,82,107,112,78,99,102,119,66,43,74,57,115,77,97,104,79,82,98,102,118,119,105,89,97,110,73,53,54,104,55,86,105,51,48,68,70,80,82,98,10,109,49,109,56,100,76,107,114,54,122,43,56,98,120,77,120,75,74,97,77,88,73,73,106,121,51,85,68,97,109,103,68,114,55,81,72,73,110,78,85,105,104,50,105,71,118,116,66,56,81,113,90,48,97,111,98,115,66,50,88,73,120,90,103,10,113,69,83,84,77,99,112,89,109,81,75,66,103,72,83,119,83,113,110,101,114,97,81,103,118,103,122,55,70,76,104,70,100,116,85,122,72,68,111,97,99,114,48,109,102,71,113,122,55,82,51,55,70,57,57,88,68,65,121,85,121,43,83,70,10,121,119,118,121,82,100,103,107,119,71,111,100,106,104,69,80,113,72,47,116,110,121,71,110,54,71,80,43,54,110,120,122,107,110,104,76,48,120,116,112,112,107,67,84,56,107,84,53,67,52,114,109,109,115,81,114,107,110,67,104,67,76,47,53,10,117,51,52,71,113,85,97,84,97,68,69,98,56,70,76,114,122,47,83,86,82,82,117,81,112,118,76,118,66,101,121,50,100,65,68,106,107,117,86,70,72,47,47,107,76,111,105,103,54,52,80,54,105,121,76,110,65,111,71,66,65,73,108,70,10,103,43,50,76,55,56,89,90,88,86,88,111,83,49,83,113,98,106,85,116,81,85,105,103,87,88,103,118,122,117,110,76,112,81,47,82,119,98,57,43,77,115,85,71,109,103,119,85,103,54,102,122,50,115,49,101,121,71,66,75,77,51,120,77,10,105,48,86,115,73,115,75,106,79,101,122,66,67,80,120,68,54,111,68,84,121,107,52,121,118,108,98,76,69,43,55,72,69,53,75,99,66,74,105,107,78,109,70,68,48,82,103,73,111,110,117,51,101,54,43,106,65,48,77,88,119,101,121,68,10,82,87,47,113,118,105,102,108,72,82,100,73,110,78,103,68,122,120,80,69,51,75,86,69,77,88,50,54,122,65,118,82,112,71,114,77,67,87,100,66,65,111,71,65,100,81,53,83,118,88,43,109,65,67,51,99,75,113,111,81,57,90,97,108,10,108,83,113,87,111,121,106,102,122,80,53,69,97,86,82,71,56,100,116,111,76,120,98,122,110,81,71,84,84,118,116,72,88,99,54,53,47,77,122,110,88,47,76,57,113,107,87,67,83,54,69,98,52,72,72,53,77,51,104,70,78,89,52,54,10,76,78,73,122,71,81,76,122,110,69,49,111,100,119,118,55,72,53,66,56,99,48,47,109,51,68,114,75,84,120,98,104,56,98,89,99,114,82,49,66,87,53,47,110,75,90,78,78,87,55,107,49,79,54,79,106,69,111,122,118,65,97,106,75,10,74,81,100,112,51,75,66,85,57,83,56,67,109,66,106,71,114,82,112,74,50,113,119,61,10,45,45,45,45,45,69,78,68,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10];
    PrivateKey result = check decodeRsaPrivateKeyFromContent(bytes);
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromContent() returns error? {
    byte[] bytes = [45,45,45,45,45,66,69,71,73,78,32,69,78,67,82,89,80,84,69,68,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10,77,73,73,69,54,106,65,99,66,103,111,113,104,107,105,71,57,119,48,66,68,65,69,69,77,65,52,69,67,74,49,65,86,69,79,70,84,43,115,49,65,103,73,70,68,65,83,67,66,77,105,72,71,55,48,80,118,97,107,98,117,86,104,97,10,57,74,66,99,88,87,122,106,101,49,66,51,48,76,73,116,86,100,112,105,69,84,98,117,53,76,78,71,51,118,48,73,73,88,55,68,109,82,81,67,66,74,120,88,107,107,67,101,90,51,66,99,119,47,65,49,99,106,107,71,73,82,48,106,10,54,80,49,65,121,85,65,108,90,66,85,57,43,71,99,67,70,50,66,99,112,121,97,77,79,120,78,86,81,117,72,85,90,65,57,47,47,102,110,108,102,79,54,75,77,84,100,73,103,57,98,47,77,117,116,72,43,43,98,76,83,111,104,57,10,74,107,72,105,118,116,103,69,81,86,69,65,117,55,57,78,112,84,100,75,104,57,88,107,108,73,87,85,66,101,53,103,85,52,79,116,101,66,76,48,47,102,101,75,103,66,54,78,70,101,89,109,55,118,78,98,56,98,52,56,54,106,83,66,10,111,88,87,67,55,108,56,89,53,86,111,85,52,103,114,104,68,84,57,100,76,49,80,81,113,76,81,118,73,82,87,84,110,66,49,66,104,85,69,57,79,113,117,87,114,82,82,97,71,69,55,87,101,87,65,66,122,122,70,104,72,66,52,88,10,68,100,72,65,66,113,115,78,69,57,113,101,69,71,72,114,85,66,75,102,106,102,103,54,43,56,71,73,69,106,106,74,99,112,74,116,57,119,71,66,105,52,121,72,98,85,97,97,111,55,120,117,101,117,48,97,65,57,110,86,86,111,55,53,10,54,80,74,79,119,99,74,113,111,80,104,119,107,68,70,112,65,89,65,68,76,74,84,86,120,104,56,69,113,98,97,105,104,83,101,51,72,86,113,106,115,70,51,97,117,53,110,117,51,51,56,86,98,74,117,56,86,90,50,114,65,103,84,118,10,86,50,73,120,115,86,47,66,87,114,118,56,82,73,98,116,47,69,73,78,122,56,50,117,85,48,117,109,98,104,112,118,85,97,107,77,106,90,71,68,48,49,78,67,118,120,54,109,115,104,102,75,65,51,122,73,69,97,99,55,97,112,109,99,10,54,119,119,111,113,104,52,50,115,69,72,107,51,105,55,72,47,120,81,104,117,83,51,50,65,67,122,82,68,119,88,122,88,89,102,50,102,56,67,90,86,114,83,107,55,65,106,99,52,119,52,109,119,89,53,89,121,108,67,109,110,43,80,53,10,89,75,54,102,82,67,97,74,65,78,50,74,52,67,71,118,73,117,116,51,76,118,106,71,88,56,112,78,117,117,57,109,115,70,77,114,70,106,98,73,84,76,47,120,101,85,122,73,114,74,111,69,49,67,57,79,50,86,49,100,81,53,76,85,10,79,52,119,86,70,71,75,72,107,70,112,66,66,122,120,120,68,81,119,82,98,89,110,54,54,69,98,76,52,47,100,67,119,116,73,107,106,55,107,110,99,122,55,89,43,113,89,66,105,43,86,111,101,56,49,82,83,76,49,109,66,116,82,47,10,110,79,81,80,73,72,78,79,76,83,85,118,73,80,65,50,97,106,52,117,102,99,100,83,114,98,88,97,112,77,102,114,84,79,105,79,43,69,85,117,66,79,71,69,54,70,110,99,97,71,109,51,104,102,75,110,80,97,49,67,52,102,117,90,10,121,111,107,118,112,69,77,78,79,85,115,53,101,74,106,83,67,48,116,99,80,43,122,105,98,84,107,105,77,72,121,50,118,104,118,114,73,51,120,109,101,54,111,73,70,71,55,78,118,120,105,50,77,120,99,87,111,108,85,78,109,88,108,107,10,85,86,71,121,74,74,117,114,76,57,81,104,75,102,106,71,83,73,117,69,90,103,74,100,55,47,80,114,68,75,48,103,122,69,81,66,77,83,47,49,48,66,85,80,82,101,49,112,69,43,48,53,71,69,79,118,74,66,98,104,119,49,66,116,10,54,98,51,76,106,98,86,116,78,110,82,47,50,47,71,51,73,57,76,108,119,82,76,97,99,52,73,72,108,85,47,74,77,121,53,56,69,51,85,120,105,109,48,47,114,74,74,55,117,71,71,98,88,115,120,100,119,70,83,52,57,54,56,73,10,47,101,107,65,49,80,99,90,103,118,78,101,116,54,48,114,77,89,120,83,88,122,54,81,80,119,89,110,118,77,57,52,103,70,68,54,73,53,80,103,85,104,74,74,80,101,81,90,105,119,57,107,70,76,66,113,75,115,85,106,66,114,106,89,10,106,70,65,99,84,86,87,54,115,87,69,111,49,67,77,115,85,67,57,52,103,119,118,72,118,112,79,76,116,80,72,106,105,107,47,105,80,65,102,72,88,101,71,81,57,98,97,84,97,65,114,77,65,74,105,81,79,43,48,104,57,79,51,89,10,48,114,88,77,56,103,69,122,52,122,65,73,68,51,78,52,110,101,86,106,106,77,100,97,55,67,47,50,97,118,65,102,74,82,111,66,120,89,65,70,77,99,117,77,78,84,116,97,52,109,77,109,88,79,67,115,43,77,54,120,52,53,71,73,10,119,47,75,80,65,90,98,115,82,84,99,82,87,76,106,85,53,81,103,117,113,80,54,101,65,120,83,103,104,72,73,84,114,117,87,48,72,69,113,115,99,84,50,48,75,51,99,82,87,88,88,68,69,79,114,56,90,113,73,100,57,48,120,89,10,80,81,111,53,90,69,118,97,74,76,71,103,120,78,52,81,55,67,85,80,74,74,49,109,75,72,114,117,84,109,77,109,43,85,79,120,73,117,88,82,82,50,101,97,113,115,74,68,110,76,111,118,109,117,52,106,71,79,83,76,86,89,86,52,10,70,70,74,55,80,120,68,43,116,120,57,98,56,87,83,56,116,99,107,83,47,80,106,109,50,80,99,85,65,74,122,51,73,54,47,68,70,99,51,105,75,119,111,101,67,88,66,73,71,47,100,106,119,87,102,97,98,82,99,111,71,98,48,85,10,83,113,56,116,105,113,118,67,106,84,47,76,117,117,98,112,81,103,75,104,107,69,110,120,87,67,66,82,82,43,81,110,115,52,113,117,74,74,50,75,101,97,100,47,103,56,69,49,57,99,85,120,111,108,71,80,84,87,57,106,114,50,71,70,10,49,88,87,117,71,121,116,75,48,80,113,85,79,73,77,115,117,74,107,104,87,78,51,100,69,114,70,109,102,116,99,102,109,102,104,113,70,70,117,108,79,118,69,55,101,87,114,43,90,84,111,121,70,69,83,109,78,75,43,77,78,110,65,76,10,109,109,90,70,79,116,55,122,84,78,119,111,111,81,107,122,112,86,111,104,76,116,75,80,119,101,51,107,55,49,100,104,104,115,75,51,103,81,66,111,115,99,75,81,70,110,77,81,83,109,75,76,77,55,99,52,65,54,72,80,99,113,50,48,10,88,70,116,82,77,51,48,79,53,99,83,79,50,106,76,90,43,115,65,99,74,83,56,49,117,73,114,99,80,87,87,102,56,121,89,53,108,77,90,49,105,114,72,70,114,105,54,106,110,119,99,118,55,83,98,101,51,114,113,90,74,70,101,114,10,57,99,107,86,122,52,114,113,51,57,57,85,72,79,121,117,106,78,84,50,103,106,73,97,70,110,69,119,109,72,102,77,48,121,97,90,48,100,89,71,50,74,85,47,106,88,100,98,113,115,84,76,75,115,72,83,79,90,115,114,107,107,76,53,10,57,66,97,72,79,56,119,102,122,86,120,47,67,110,81,102,80,54,77,61,10,45,45,45,45,45,69,78,68,32,69,78,67,82,89,80,84,69,68,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10];
    PrivateKey result = check decodeRsaPrivateKeyFromContent(bytes, "ballerina");
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyPairFromContent() returns error? {
    byte[] bytes = [45,45,45,45,45,66,69,71,73,78,32,82,83,65,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10,80,114,111,99,45,84,121,112,101,58,32,52,44,69,78,67,82,89,80,84,69,68,10,68,69,75,45,73,110,102,111,58,32,68,69,83,45,69,68,69,51,45,67,66,67,44,67,54,68,56,49,65,67,70,65,66,67,55,50,69,68,56,10,10,111,74,114,102,101,98,112,108,117,67,75,88,70,77,76,106,108,72,65,101,121,47,107,69,81,68,100,75,120,116,52,77,76,68,66,86,99,67,55,118,84,121,108,112,73,120,106,115,115,101,117,80,118,111,71,75,101,97,43,121,110,99,80,117,10,69,90,85,98,80,121,82,122,106,107,54,70,84,106,101,77,82,121,97,89,110,81,109,52,49,48,88,57,75,74,112,113,47,101,71,75,107,99,119,77,56,107,72,99,47,68,78,101,103,121,50,106,66,48,120,52,106,111,49,73,82,53,120,101,10,122,102,111,51,84,101,80,73,103,80,48,48,55,109,56,99,108,49,79,101,89,84,81,71,84,102,108,115,88,103,121,87,75,65,113,56,70,57,54,108,74,86,112,76,104,81,78,114,119,43,43,114,84,100,78,65,54,117,68,115,102,87,102,54,10,108,56,116,106,120,47,78,83,80,50,109,79,87,74,90,100,115,109,77,86,73,65,71,105,115,81,67,90,66,110,90,84,85,47,107,71,65,55,73,52,81,113,49,106,53,65,87,78,69,100,116,69,83,105,70,54,56,122,107,73,66,105,101,116,10,83,118,111,97,51,65,66,86,118,102,99,86,65,99,87,75,115,76,83,47,120,53,55,78,97,78,72,101,119,119,99,84,84,99,102,109,71,111,53,70,90,87,97,105,57,82,70,83,113,49,113,100,116,53,85,74,85,112,47,101,108,66,102,78,10,97,102,81,89,56,115,53,111,81,77,65,48,87,65,107,67,115,121,88,69,99,120,78,82,112,72,109,65,73,50,54,116,50,88,43,51,73,47,47,100,50,43,80,82,104,86,109,118,112,85,53,73,55,103,79,120,89,49,99,77,88,120,77,50,10,52,55,107,113,113,47,100,74,50,113,76,110,43,110,120,110,50,51,43,117,67,68,116,65,67,67,71,121,106,82,100,83,88,117,88,48,112,103,121,117,99,43,120,73,98,69,107,55,82,69,84,74,84,120,84,68,52,110,49,101,87,55,98,122,10,49,75,109,43,72,121,109,108,109,69,97,106,84,65,67,55,100,71,112,72,72,121,66,115,107,116,99,43,69,84,103,121,86,88,48,85,83,70,81,81,105,103,56,50,97,101,72,65,80,107,74,100,99,76,56,88,121,57,54,120,65,54,77,78,10,112,116,73,90,103,101,84,121,110,85,89,102,111,99,56,86,111,49,56,117,113,99,52,106,109,72,81,81,100,53,98,112,67,117,68,99,115,90,81,87,120,75,102,68,66,112,51,56,52,105,76,102,47,69,122,114,48,108,66,109,100,78,104,121,10,101,75,104,84,119,114,47,71,119,119,65,49,49,80,103,109,104,101,50,65,115,73,53,104,48,110,120,78,47,118,115,88,105,76,43,43,47,90,43,78,70,105,98,54,112,77,103,122,84,49,122,108,121,117,70,102,74,79,120,107,71,65,113,48,10,55,102,80,99,118,121,113,103,76,103,75,72,56,99,56,106,47,111,43,97,102,71,68,77,80,72,107,76,68,100,74,118,120,50,49,117,68,117,105,121,97,73,105,65,47,82,87,69,73,56,71,120,54,120,119,110,48,52,113,51,74,108,81,52,10,65,52,119,99,98,115,57,114,104,107,99,66,85,113,85,83,81,78,100,55,52,56,47,97,105,97,100,82,102,74,113,102,85,75,121,70,85,75,54,50,74,79,66,100,71,82,119,69,106,122,118,81,75,43,104,89,104,105,51,121,74,43,73,55,10,98,111,71,86,48,51,71,87,88,114,102,108,112,107,71,77,106,55,120,110,81,67,104,47,119,110,57,100,49,112,47,73,84,43,99,48,90,50,43,65,102,112,114,52,83,117,90,70,86,118,101,109,105,112,53,65,88,74,43,78,101,100,110,48,10,76,82,75,110,84,122,57,65,100,65,118,100,76,48,51,113,110,102,86,65,106,114,77,51,115,83,102,118,121,116,120,83,104,97,71,103,47,118,113,98,98,80,80,106,66,108,104,72,82,66,87,68,83,83,110,86,82,89,55,122,66,118,113,68,10,101,106,104,108,74,119,49,86,97,51,103,109,47,120,76,68,76,107,98,84,113,66,108,47,119,102,56,109,67,101,78,55,113,57,52,89,66,121,82,73,101,65,72,52,110,51,117,115,78,122,72,87,100,78,97,108,85,79,77,97,76,111,99,73,10,103,52,72,76,56,120,53,98,106,77,82,77,84,82,49,112,107,83,111,114,73,80,108,54,79,77,48,52,80,48,66,102,114,122,83,68,87,53,121,79,116,55,119,102,105,56,111,85,56,122,106,54,85,69,53,48,75,71,99,79,86,111,84,90,10,110,71,117,74,65,48,100,119,54,56,47,53,116,79,109,74,117,53,117,98,120,110,121,101,68,54,80,66,74,68,70,86,72,112,83,121,111,119,54,115,55,89,116,105,100,97,69,53,70,103,51,89,49,85,74,74,97,99,74,113,108,69,78,112,10,85,67,56,106,102,118,48,106,118,66,104,89,52,47,50,66,70,80,120,97,53,98,90,80,71,117,76,53,84,73,88,115,85,114,79,81,73,97,99,87,76,104,111,55,78,66,76,118,78,85,101,68,50,117,56,54,110,79,74,43,115,104,107,121,10,114,112,119,104,77,77,86,122,52,110,43,49,73,76,79,52,102,89,101,104,113,120,111,90,82,65,79,107,87,97,76,116,51,89,77,78,89,78,88,48,50,71,120,120,43,111,81,56,109,97,112,54,87,73,75,81,73,122,69,116,69,76,75,49,10,55,57,76,54,114,43,66,81,111,81,85,108,109,90,65,107,107,115,75,100,99,106,97,122,102,80,100,52,104,101,105,51,108,70,107,122,48,86,76,49,105,103,90,76,84,73,122,76,109,118,83,88,121,100,100,119,86,73,104,109,65,102,89,119,10,103,110,87,98,54,70,112,70,115,78,108,84,53,99,122,57,122,48,74,97,71,102,85,68,47,52,83,118,118,106,69,65,77,69,121,67,43,82,51,114,66,89,71,113,48,80,68,69,113,83,100,115,114,122,87,101,82,89,75,76,88,114,65,66,10,65,53,69,81,67,78,122,110,105,76,75,49,79,97,120,111,121,87,51,104,49,74,116,103,98,114,68,81,68,52,104,71,108,86,74,73,67,47,78,56,97,122,53,75,82,108,102,75,78,67,47,106,65,67,76,76,70,85,86,67,88,48,98,80,10,71,68,50,105,87,103,78,115,85,97,51,43,118,49,53,69,118,69,56,103,103,104,69,69,105,111,56,116,101,77,53,113,65,83,109,76,77,90,74,120,65,69,85,114,120,86,82,107,88,113,57,99,88,65,85,56,78,76,102,56,99,84,107,82,10,69,117,111,50,71,119,55,89,70,84,74,109,53,73,73,121,90,54,108,110,88,113,113,98,116,86,81,76,55,56,74,83,43,86,51,66,82,90,115,112,122,55,90,66,83,105,117,81,49,70,80,47,55,74,54,117,100,107,65,99,43,71,121,107,10,102,87,105,69,106,78,111,88,70,83,82,107,88,122,71,65,104,43,66,83,84,118,68,53,65,114,113,49,71,110,43,120,109,107,89,112,114,110,76,69,50,101,105,117,121,121,101,74,89,122,97,113,105,65,61,61,10,45,45,45,45,45,69,78,68,32,82,83,65,32,80,82,73,86,65,84,69,32,75,69,89,45,45,45,45,45,10];
    PrivateKey result = check decodeRsaPrivateKeyFromContent(bytes, "ballerina");
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromKeyFile() returns Error? {
    PrivateKey result = check decodeRsaPrivateKeyFromKeyFile(ENCRYPTED_PRIVATE_KEY_PATH, "ballerina");
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromKeyFileWithInvalidPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile(ENCRYPTED_PRIVATE_KEY_PATH, "invalid-password");
    if result is Error {
        test:assertEquals(result.message(), "Unable to do private key operations: unable to read encrypted data: Error finalising cipher");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromKeyFileWithNoPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile(ENCRYPTED_PRIVATE_KEY_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Failed to read the encrypted private key without a password.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromKeyPairFile() returns Error? {
    PrivateKey result = check decodeRsaPrivateKeyFromKeyFile(ENCRYPTED_KEY_PAIR_PATH, "ballerina");
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromKeyPairFileWithInvalidPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile(ENCRYPTED_KEY_PAIR_PATH, "invalid-password");
    if result is Error {
        test:assertEquals(result.message(), "Unable to do private key operations: exception using cipher - please check password and data.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromKeyPairFileWithNoPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile(ENCRYPTED_KEY_PAIR_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Failed to read the encrypted private key without a password.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testParsePrivateKeyFromKeyPairFile() returns Error? {
    PrivateKey result = check decodeRsaPrivateKeyFromKeyFile(KEY_PAIR_PATH);
    test:assertEquals(result.algorithm, "RSA");
}

@test:Config {}
isolated function testParseEcPrivateKeyFromKeyFile() returns Error? {
    PrivateKey result = check decodeEcPrivateKeyFromKeyFile(EC_PRIVATE_KEY_PATH);
    test:assertEquals(result.algorithm, "ECDSA");
}

@test:Config {}
isolated function testParseErrorEcPrivateKeyFromKeyFile() returns Error? {
    PrivateKey|Error result = decodeEcPrivateKeyFromKeyFile(PRIVATE_KEY_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Not a valid EC key");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testParseEncryptedMlDsa65PrivateKeyFromKeyFile() returns Error? {
    PrivateKey result = check decodeMlDsa65PrivateKeyFromKeyFile(MLDSA_PRIVATE_KEY_PATH, "ballerina");
    test:assertEquals(result.algorithm, "ML-DSA-65");
}

@test:Config {}
isolated function testParseErrorMlDsa65PrivateKeyFromKeyFile() returns Error? {
    PrivateKey|Error result = decodeMlDsa65PrivateKeyFromKeyFile(PRIVATE_KEY_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Not a valid ML-DSA-65 key");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testParseErrorMlKem768PrivateKeyFromKeyFile() returns Error? {
    PrivateKey|Error result = decodeMlKem768PrivateKeyFromKeyFile(PRIVATE_KEY_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Not a valid ML-KEM-768 key");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testParseErrorEcPublicKeyFromKeyFile() returns Error? {
    PublicKey|Error result = decodeEcPublicKeyFromCertFile(PRIVATE_KEY_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Unable to do public key operations: signed fields invalid");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testParseErrorMlDsa65PublicKeyFromKeyFile() returns Error? {
    PublicKey|Error result = decodeMlDsa65PublicKeyFromCertFile(PRIVATE_KEY_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Unable to do public key operations: signed fields invalid");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testParseErrorMlKem768PublicKeyFromKeyFile() returns Error? {
    PublicKey|Error result = decodeMlKem768PublicKeyFromCertFile(PRIVATE_KEY_PATH);
    if result is Error {
        test:assertEquals(result.message(), "Unable to do public key operations: signed fields invalid");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testReadPrivateKeyFromNonExistingKeyFile() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile(INVALID_PRIVATE_KEY_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Key file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadEcPrivateKeyFromNonExistingKeyFile() {
    PrivateKey|Error result = decodeEcPrivateKeyFromKeyFile(INVALID_PRIVATE_KEY_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Key file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlDsaPrivateKeyFromInvalidKeyFile() {
    PrivateKey|Error result = decodeMlDsa65PrivateKeyFromKeyFile(INVALID_PRIVATE_KEY_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Key file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlKemPrivateKeyFromInvalidKeyFile() {
    PrivateKey|Error result = decodeMlKem768PrivateKeyFromKeyFile(INVALID_PRIVATE_KEY_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Key file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testParsePublicKeyFromP12() returns Error? {
    TrustStore trustStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(trustStore, "ballerina");
    test:assertEquals(publicKey.algorithm, "RSA");
    Certificate certificate = <Certificate>publicKey.certificate;

    string serial = (<int>certificate.serial).toString();
    string issuer = <string>certificate.issuer;
    string subject = <string>certificate.subject;
    string signingAlgorithm = <string>certificate.signingAlgorithm;

    test:assertEquals(serial, "2097012467");
    test:assertEquals(issuer, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(subject, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(signingAlgorithm, "SHA256withRSA");
}

@test:Config {}
isolated function testReadPublicKeyFromNonExistingP12() {
    TrustStore trustStore = {
        path: INVALID_KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey|Error result = decodeRsaPublicKeyFromTrustStore(trustStore, "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("PKCS12 KeyStore not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadPublicKeyFromP12WithInvalidTrustStorePassword() {
    TrustStore trustStore = {
        path: KEYSTORE_PATH,
        password: "invalid"
    };
    PublicKey|Error result = decodeRsaPublicKeyFromTrustStore(trustStore, "ballerina");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadEcPublicKeyFromP12WithInvalidTrustStorePassword() {
    TrustStore trustStore = {
        path: EC_KEYSTORE_PATH,
        password: "invalid"
    };
    PublicKey|Error result = decodeEcPublicKeyFromTrustStore(trustStore, "ec-keypair");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlKemPublicKeyFromP12WithInvalidTrustStorePassword() {
    TrustStore trustStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "invalid"
    };
    PublicKey|Error result = decodeMlKem768PublicKeyFromTrustStore(trustStore, "mlkem-keypair");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlDsaPublicKeyFromP12WithInvalidTrustStorePassword() {
    TrustStore trustStore = {
        path: MLDSA_KEYSTORE_PATH,
        password: "invalid"
    };
    PublicKey|Error result = decodeMlDsa65PublicKeyFromTrustStore(trustStore, "mldsa-keypair");
    if result is Error {
        test:assertTrue(result.message().includes("Unable to open KeyStore:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadPublicKeyFromP12WithInvalidAlias() {
    TrustStore trustStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey|Error result = decodeRsaPublicKeyFromTrustStore(trustStore, "invalid");
    if result is Error {
        test:assertTrue(result.message().includes("Certificate cannot be recovered by using given key alias:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testParsePublicKeyFromX509CertFile() returns Error? {
    PublicKey publicKey = check decodeRsaPublicKeyFromCertFile(X509_PUBLIC_CERT_PATH);
    test:assertEquals(publicKey.algorithm, "RSA");
    Certificate certificate = <Certificate>publicKey.certificate;

    string serial = (<int>certificate.serial).toString();
    string issuer = <string>certificate.issuer;
    string subject = <string>certificate.subject;
    string signingAlgorithm = <string>certificate.signingAlgorithm;

    test:assertEquals(serial, "2097012467");
    test:assertEquals(issuer, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(subject, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(signingAlgorithm, "SHA256withRSA");
}

@test:Config {}
isolated function testParsePublicKeyFromX509CertContent() returns error? {
    byte[] bytes = [45,45,45,45,45,66,69,71,73,78,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10,77,73,73,68,100,122,67,67,65,108,43,103,65,119,73,66,65,103,73,69,102,80,51,101,56,122,65,78,66,103,107,113,104,107,105,71,57,119,48,66,65,81,115,70,65,68,66,107,77,81,115,119,67,81,89,68,86,81,81,71,69,119,74,86,10,85,122,69,76,77,65,107,71,65,49,85,69,67,66,77,67,81,48,69,120,70,106,65,85,66,103,78,86,66,65,99,84,68,85,49,118,100,87,53,48,89,87,108,117,73,70,90,112,90,88,99,120,68,84,65,76,66,103,78,86,66,65,111,84,10,66,70,100,84,84,122,73,120,68,84,65,76,66,103,78,86,66,65,115,84,66,70,100,84,84,122,73,120,69,106,65,81,66,103,78,86,66,65,77,84,67,87,120,118,89,50,70,115,97,71,57,122,100,68,65,101,70,119,48,120,78,122,69,119,10,77,106,81,119,78,84,81,51,78,84,104,97,70,119,48,122,78,122,69,119,77,84,107,119,78,84,81,51,78,84,104,97,77,71,81,120,67,122,65,74,66,103,78,86,66,65,89,84,65,108,86,84,77,81,115,119,67,81,89,68,86,81,81,73,10,69,119,74,68,81,84,69,87,77,66,81,71,65,49,85,69,66,120,77,78,84,87,57,49,98,110,82,104,97,87,52,103,86,109,108,108,100,122,69,78,77,65,115,71,65,49,85,69,67,104,77,69,86,49,78,80,77,106,69,78,77,65,115,71,10,65,49,85,69,67,120,77,69,86,49,78,80,77,106,69,83,77,66,65,71,65,49,85,69,65,120,77,74,98,71,57,106,89,87,120,111,98,51,78,48,77,73,73,66,73,106,65,78,66,103,107,113,104,107,105,71,57,119,48,66,65,81,69,70,10,65,65,79,67,65,81,56,65,77,73,73,66,67,103,75,67,65,81,69,65,103,86,121,105,54,102,86,105,86,76,105,90,75,69,110,119,53,57,120,122,78,105,49,108,99,89,104,54,122,57,100,90,110,117,103,43,70,57,103,75,113,70,73,103,10,109,100,99,80,101,43,113,116,83,55,103,90,99,49,106,89,84,106,87,77,67,98,120,49,51,115,70,76,107,90,113,78,72,101,68,85,97,100,112,109,116,75,111,51,84,68,100,117,79,108,49,115,113,77,54,99,122,51,121,88,98,54,76,51,10,52,107,47,108,101,104,53,48,109,122,73,80,78,109,97,97,88,120,100,51,118,79,81,111,75,52,79,112,107,103,79,49,110,51,50,109,104,54,43,116,107,112,51,115,98,72,109,102,89,113,68,81,114,107,86,75,49,116,109,89,78,116,80,74,10,102,102,83,67,76,84,43,67,117,73,104,110,74,85,74,99,111,55,78,48,117,110,97,120,43,121,83,90,78,54,55,47,65,88,43,43,115,74,112,113,65,104,65,73,90,74,122,114,82,105,54,117,101,78,51,82,70,67,73,120,89,68,88,83,10,77,118,120,114,69,109,79,100,110,52,103,79,67,48,111,49,65,114,57,117,53,66,112,57,78,53,50,115,113,113,71,98,78,49,120,54,106,78,75,105,51,98,102,85,106,49,50,50,72,117,53,101,43,89,57,75,79,109,102,98,99,104,104,81,10,105,108,50,80,56,49,99,73,105,51,48,86,75,103,121,68,110,53,68,101,87,69,117,68,111,89,114,101,100,107,52,43,54,113,65,90,114,120,77,119,43,119,73,68,65,81,65,66,111,122,69,119,76,122,65,79,66,103,78,86,72,81,56,66,10,65,102,56,69,66,65,77,67,66,97,65,119,72,81,89,68,86,82,48,79,66,66,89,69,70,78,109,116,114,81,51,54,106,54,116,85,71,104,75,114,102,87,57,113,87,87,69,55,75,70,122,77,77,65,48,71,67,83,113,71,83,73,98,51,10,68,81,69,66,67,119,85,65,65,52,73,66,65,81,65,118,51,121,79,119,103,98,116,79,117,55,54,101,74,77,108,49,66,67,99,103,84,70,103,97,77,85,66,90,111,85,106,75,57,85,110,54,72,71,106,75,69,103,89,122,47,89,87,83,10,90,70,108,89,47,113,72,53,114,84,48,49,68,87,81,101,118,85,90,66,54,50,54,100,53,90,78,100,122,83,66,90,82,108,112,115,120,98,102,57,73,69,47,117,114,115,78,72,119,72,120,57,117,97,54,102,66,55,121,72,85,67,122,67,10,49,90,77,112,49,108,118,66,72,65,66,105,55,119,99,65,43,53,110,98,86,54,122,81,55,72,68,109,66,88,70,104,74,102,98,103,72,49,105,86,109,65,49,75,99,118,68,101,66,80,83,74,47,115,99,82,71,97,115,90,53,113,50,87,10,51,73,101,110,68,78,114,102,80,73,85,104,68,55,52,116,70,105,67,105,113,78,74,79,57,49,113,68,47,76,79,43,43,43,51,88,101,90,122,102,80,104,56,78,82,75,107,105,80,88,55,100,66,56,87,74,51,89,78,66,117,81,65,118,10,103,82,87,84,73,83,112,83,83,88,76,109,113,77,98,43,55,77,80,81,86,103,101,99,115,101,112,90,100,107,56,67,119,107,82,76,120,104,51,82,75,80,74,77,106,105,103,109,67,103,121,118,107,83,97,111,68,77,75,65,89,67,51,105,10,89,106,102,85,84,105,74,53,55,85,101,113,111,83,108,48,73,97,79,70,74,48,119,102,90,82,70,104,43,85,121,116,108,68,90,97,10,45,45,45,45,45,69,78,68,32,67,69,82,84,73,70,73,67,65,84,69,45,45,45,45,45,10];
    PublicKey publicKey = check decodeRsaPublicKeyFromContent(bytes);
    test:assertEquals(publicKey.algorithm, "RSA");
    Certificate certificate = <Certificate>publicKey.certificate;

    test:assertEquals(certificate.serial, 2097012467);
    test:assertEquals(certificate.issuer, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(certificate.subject, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(certificate.signingAlgorithm, "SHA256withRSA");
}

@test:Config {}
isolated function testParseEcPublicKeyFromX509CertFile() returns Error? {
    PublicKey publicKey = check decodeEcPublicKeyFromCertFile(EC_CERT_PATH);
    test:assertEquals(publicKey.algorithm, "EC");
    Certificate certificate = <Certificate>publicKey.certificate;

    string serial = (<int>certificate.serial).toString();
    string issuer = <string>certificate.issuer;
    string subject = <string>certificate.subject;
    string signingAlgorithm = <string>certificate.signingAlgorithm;

    test:assertEquals(serial, "813081972327485475");
    test:assertEquals(issuer, "CN=sigstore-intermediate,O=sigstore.dev");
    test:assertEquals(signingAlgorithm, "SHA384withECDSA");
}

@test:Config {}
isolated function testParseMlDsa65PublicKeyFromX509CertFile() returns Error? {
    PublicKey publicKey = check decodeMlDsa65PublicKeyFromCertFile(MLDSA_CERT_PATH);
    test:assertEquals(publicKey.algorithm, "ML-DSA-65");
    Certificate certificate = <Certificate>publicKey.certificate;

    int serial = certificate.serial;
    string issuer = certificate.issuer;
    string subject = certificate.subject;
    string signingAlgorithm = certificate.signingAlgorithm;

    test:assertEquals(serial, 4818446483955774646);
    test:assertEquals(issuer, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(subject, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(signingAlgorithm, "ML-DSA-65");
}

@test:Config {}
isolated function testParseMlKem768PublicKeyFromX509CertFile() returns Error? {
    PublicKey publicKey = check decodeMlKem768PublicKeyFromCertFile(MLKEM_CERT_PATH);
    test:assertEquals(publicKey.algorithm, "ML-KEM-768");
    Certificate certificate = <Certificate>publicKey.certificate;

    int serial = certificate.serial;
    string issuer = certificate.issuer;
    string subject = certificate.subject;
    string signingAlgorithm = certificate.signingAlgorithm;

    test:assertEquals(serial, 787519857);
    test:assertEquals(issuer, "C=US,ST=CA,L=Mountain View,O=WSO2,OU=WSO2,CN=localhost");
    test:assertEquals(subject, "C=US,ST=CA,L=Mountain View,O=WSO2,OU=WSO2,CN=localhost");
    test:assertEquals(signingAlgorithm, "SHA256withRSA");
}

@test:Config {}
isolated function testReadPublicKeyFromNonExistingCertFile() {
    PublicKey|Error result = decodeRsaPublicKeyFromCertFile(INVALID_PUBLIC_CERT_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Certificate file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadEcPublicKeyFromNonExistingCertFile() {
    PublicKey|Error result = decodeEcPublicKeyFromCertFile(INVALID_PUBLIC_CERT_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Certificate file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlDsaPublicKeyFromInvalidCertFile() {
    PublicKey|Error result = decodeMlDsa65PublicKeyFromCertFile(INVALID_PUBLIC_CERT_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Certificate file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadMlKemPublicKeyFromInvalidCertFile() {
    PublicKey|Error result = decodeMlKem768PublicKeyFromCertFile(INVALID_PUBLIC_CERT_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Certificate file not found at:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testReadPublicKeyFromInvalidCertFile() {
    PublicKey|Error result = decodeRsaPublicKeyFromCertFile(KEYSTORE_PATH);
    if result is Error {
        test:assertTrue(result.message().includes("Unable to do public key operations:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testBuildPublicKeyFromJwk() returns Error? {
    string modulus = "luZFdW1ynitztkWLC6xKegbRWxky-5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9-" +
        "PmjdGtau4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0-s6kMl2EhB-rk7gXluEep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsy" +
        "L4tztS70vmmX121qm0sTJdKWP4HxXyqK9neolXI9fYyHOYILVNZ69z_73OOVhkh_mvTmWZLM7GM6sApmyLX6OXUp8z0pkY-v" +
        "T_9-zRxxQs7GurC4_C1nK3rI_0ySUgGEafO1atNjYmlFN-M3tZX6nEcA6g94IavyQ";
    string exponent = "AQAB";
    PublicKey publicKey = check buildRsaPublicKey(modulus, exponent);
    test:assertEquals(publicKey["algorithm"], "RSA");
}

@test:Config {}
isolated function testBuildPublicKeyFromJwkWithInvalidModulus() {
    string modulus = "invalid";
    string exponent = "AQAB";
    PublicKey|Error result = buildRsaPublicKey(modulus, exponent);
    if result is Error {
        test:assertTrue(result.message().includes("Invalid modulus or exponent:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}
