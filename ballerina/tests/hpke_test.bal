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

@test:Config {}
isolated function testEncryptAndDecryptMlKem768Hpke() returns Error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore mlkemKeyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey publicKey = check decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "mlkem-keypair");
    HybridEncryptionResult hybridEncryptionResult = check encryptMlKem768Hpke(message, publicKey);

    PrivateKey privateKey = check decodeMlKem768PrivateKeyFromKeyStore(mlkemKeyStore, "mlkem-keypair", "ballerina");
    byte[] decryptedMessage = check decryptMlKem768Hpke(hybridEncryptionResult.cipherText, hybridEncryptionResult.encapsulatedSecret, privateKey);

    test:assertEquals(decryptedMessage, message);
}

@test:Config {}
isolated function testEncryptAndDecryptRsaMlKem768Hpke() returns Error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore mlkemKeyStore = {
        path: MLKEM_KEYSTORE_PATH,
        password: "ballerina"
    };
    KeyStore rsaKeyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey mlKemPublicKey = check decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "mlkem-keypair");
    PublicKey rsaPublicKey = check decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "ballerina");
    HybridEncryptionResult hybridEncryptionResult = check encryptRsaKemMlKem768Hpke(message, rsaPublicKey, mlKemPublicKey);

    PrivateKey mlKemPrivateKey = check decodeMlKem768PrivateKeyFromKeyStore(mlkemKeyStore, "mlkem-keypair", "ballerina");
    PrivateKey rsaPrivateKey = check decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "ballerina", "ballerina");
    byte[] decryptedMessage = check decryptRsaKemMlKem768Hpke(hybridEncryptionResult.cipherText, hybridEncryptionResult.encapsulatedSecret, 
                                                            rsaPrivateKey, mlKemPrivateKey);

    test:assertEquals(decryptedMessage, message);
}
