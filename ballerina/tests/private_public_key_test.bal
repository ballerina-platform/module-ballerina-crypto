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
    test:assertEquals(result["algorithm"], "RSA");
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
    test:assertEquals(result["algorithm"], "RSA");
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromKeyFile() returns Error? {
    PrivateKey result = check decodeRsaPrivateKeyFromKeyFile(ENCRYPTED_PRIVATE_KEY_PATH, "ballerina");
    test:assertEquals(result["algorithm"], "RSA");
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
    test:assertEquals(result["algorithm"], "RSA");
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
    test:assertEquals(result["algorithm"], "RSA");
}

@test:Config {}
isolated function testParseEcPrivateKeyFromKeyFile() returns Error? {
    PrivateKey result = check decodeEcPrivateKeyFromKeyFile(EC_PRIVATE_KEY_PATH);
    test:assertEquals(result["algorithm"], "ECDSA");
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
isolated function testParsePublicKeyFromP12() returns Error? {
    TrustStore trustStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(trustStore, "ballerina");
    test:assertEquals(publicKey["algorithm"], "RSA");
    Certificate certificate = <Certificate>publicKey["certificate"];

    string serial = (<int>certificate["serial"]).toString();
    string issuer = <string>certificate["issuer"];
    string subject = <string>certificate["subject"];
    string signingAlgorithm = <string>certificate["signingAlgorithm"];

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
    test:assertEquals(publicKey["algorithm"], "RSA");
    Certificate certificate = <Certificate>publicKey["certificate"];

    string serial = (<int>certificate["serial"]).toString();
    string issuer = <string>certificate["issuer"];
    string subject = <string>certificate["subject"];
    string signingAlgorithm = <string>certificate["signingAlgorithm"];

    test:assertEquals(serial, "2097012467");
    test:assertEquals(issuer, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(subject, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US");
    test:assertEquals(signingAlgorithm, "SHA256withRSA");
}

@test:Config {}
isolated function testParseEcPublicKeyFromX509CertFile() returns Error? {
    PublicKey publicKey = check decodeEcPublicKeyFromCertFile(EC_CERT_PATH);
    test:assertEquals(publicKey["algorithm"], "EC");
    Certificate certificate = <Certificate>publicKey["certificate"];

    string serial = (<int>certificate["serial"]).toString();
    string issuer = <string>certificate["issuer"];
    string subject = <string>certificate["subject"];
    string signingAlgorithm = <string>certificate["signingAlgorithm"];

    test:assertEquals(serial, "813081972327485475");
    test:assertEquals(issuer, "CN=sigstore-intermediate,O=sigstore.dev");
    test:assertEquals(signingAlgorithm, "SHA384withECDSA");
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
