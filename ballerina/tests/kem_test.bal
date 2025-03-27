// Copyright (c) 2024 WSO2 LLC. (https://www.wso2.com).
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

import ballerina/test;

@test:Config {
    groups: ["non-fips"]
}
isolated function testEncapsulateandDecapsulateMlKem768() returns Error? {
    KeyStore mlkemKeyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "mlkem-keypair");
    EncapsulationResult encapsulationResult = check encapsulateMlKem768(publicKey);

    PrivateKey privateKey = check decodeMlKem768PrivateKeyFromKeyStore(mlkemKeyStore, "mlkem-keypair", "ballerina");
    byte[] sharedSecret = check decapsulateMlKem768(encapsulationResult.encapsulatedSecret, privateKey);

    test:assertEquals(sharedSecret, encapsulationResult.sharedSecret);
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testEncapsulateMlKem768WithInvalidPublicKey() returns Error? {
    KeyStore rsaKeyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "ballerina");
    EncapsulationResult|Error encapsulationResult = encapsulateMlKem768(publicKey);
    if encapsulationResult is Error {
        test:assertEquals(encapsulationResult.message(), "Error occurred while generating encapsulated key: key generator locked to ML-KEM-768");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testDecapsulateMlKem768WithInvalidPrivateKey() returns Error? {
    KeyStore mlkemKeyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    KeyStore rsaKeyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "mlkem-keypair");
    EncapsulationResult encapsulationResult = check encapsulateMlKem768(publicKey);

    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "ballerina", "ballerina");
    byte[]|Error sharedSecret = decapsulateMlKem768(encapsulationResult.encapsulatedSecret, privateKey);
    
    if sharedSecret is Error {
        test:assertEquals(sharedSecret.message(), "Error occurred while extracting secret: key generator locked to ML-KEM-768");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testEncapsulateAndDecapsulateRsaKem() returns Error? {
    KeyStore rsaKeyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "ballerina");
    EncapsulationResult encapsulationResult = check encapsulateRsaKem(publicKey);

    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "ballerina", "ballerina");
    byte[] sharedSecret = check decapsulateRsaKem(encapsulationResult.encapsulatedSecret, privateKey);

    test:assertEquals(sharedSecret, encapsulationResult.sharedSecret);
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testEncapsulateRsaKemWithInvalidPublicKey() returns Error? {
    KeyStore mlkemKeyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "mlkem-keypair");
    EncapsulationResult|Error encapsulationResult = encapsulateRsaKem(publicKey);
    if encapsulationResult is Error {
        test:assertEquals(encapsulationResult.message(), "Error occurred while generating encapsulated key: " + 
                            "valid RSA public key expected");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testDecapsulateRsaKemWithInvalidPrivateKey() returns Error? {
    KeyStore rsaKeyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    KeyStore mlkemKeyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "ballerina");
    EncapsulationResult encapsulationResult = check encapsulateRsaKem(publicKey);

    PrivateKey privateKey = check decodeMlKem768PrivateKeyFromKeyStore(mlkemKeyStore, "mlkem-keypair", "ballerina");
    byte[]|Error sharedSecret = decapsulateRsaKem(encapsulationResult.encapsulatedSecret, privateKey);

    if sharedSecret is Error {
        test:assertEquals(sharedSecret.message(), "Error occurred while extracting secret: valid RSA privatekey expected");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testEncapsulateAndDecapsulateRsaKemMlKem768() returns Error? {
    KeyStore mlkemKeyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    KeyStore rsaKeyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey mlkemPublicKey = check decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "mlkem-keypair");
    PublicKey rsaPublicKey = check decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "ballerina");
    EncapsulationResult encapsulationResult = check encapsulateRsaKemMlKem768(rsaPublicKey, mlkemPublicKey);
    
    PrivateKey mlkemPrivateKey = check decodeMlKem768PrivateKeyFromKeyStore(mlkemKeyStore, "mlkem-keypair", "ballerina");
    PrivateKey rsaPrivateKey = check decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "ballerina", "ballerina");
    byte[] sharedSecret = check decapsulateRsaKemMlKem768(encapsulationResult.encapsulatedSecret, rsaPrivateKey, mlkemPrivateKey);

    test:assertEquals(sharedSecret, encapsulationResult.sharedSecret);
}
