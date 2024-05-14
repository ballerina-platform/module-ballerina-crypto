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

import ballerina/jballerina.java;

# Represents the shared secret and its encapsulation used in Key Encapsulation Mechanism (KEM).
#
# + encapsulatedSecret - Encapsulated secret 
# + sharedSecret - Shared secret
public type EncapsulationResult record {|
    byte[] encapsulatedSecret;
    byte[] sharedSecret;
|};

# Creates a shared secret and its encapsulation used for Key Encapsulation Mechanism (KEM) using the ML-KEM-768 (Kyber768) public key.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeMlKem768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateMlKem768(publicKey);
# ```
# + publicKey - Public key
# + return - Encapsulated secret or else a `crypto:Error` if the public key is invalid
public isolated function encapsulateMlKem768(PublicKey publicKey)
                                    returns EncapsulationResult|Error = @java:Method {
    name: "encapsulateMlKem768",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;

# Decapsulates the ML-KEM-768 (Kyber768) shared secret used for Key Encapsulation Mechanism (KEM) from the given encapsulation for the given data.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeMlKem768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateMlKem768(publicKey);
# byte[] encapsulatedSecret = encapsulationResult.encapsulatedSecret;
# crypto:PrivateKey privateKey = check crypto:decodeMlKem768PrivateKeyFromKeyStore(keyStore, "keyAlias", "keyStorePassword");
# byte[] sharedSecret = check crypto:decapsulateMlKem768(encapsulatedSecret, privateKey);
# ```
# + encapsulatedSecret - Encapsulated secret
# + privateKey - Private key
# + return - Shared secret or else a `crypto:Error` if the encapsulatedSecret or the private key is invalid
public isolated function decapsulateMlKem768(byte[] encapsulatedSecret, PrivateKey privateKey)
                                        returns byte[]|Error = @java:Method {
    name: "decapsulateMlKem768",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;

# Creates a shared secret and its encapsulation used for Key Encapsulation Mechanism (KEM) using RSA and ML-KEM-768 (Kyber768) public keys.
# ```ballerina
# crypto:KeyStore mlkemKeyStore = {
#     path: "/path/to/mlkem/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:KeyStore rsaKeyStore = {
#     path: "/path/to/rsa/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey mlkemPublicKey = check crypto:decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "keyAlias");
# crypto:PublicKey rsaPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateRsaKemMlKem768(rsaPublicKey, mlkemPublicKey);
# ```
# + rsaPublicKey - RSA public key
# + mlkemPublicKey - MlKem public key
# + return - Encapsulated secret or else a `crypto:Error` if the keysize or public keys are invalid
public isolated function encapsulateRsaKemMlKem768(PublicKey rsaPublicKey, PublicKey mlkemPublicKey)
                                        returns EncapsulationResult|Error {
    EncapsulationResult rsaEncapsulationResult = check encapsulateRsaKem(rsaPublicKey);
    EncapsulationResult mlkemEncapsulationResult = check encapsulateMlKem768(mlkemPublicKey);
    EncapsulationResult encapsulationResult = {
        sharedSecret: [...rsaEncapsulationResult.sharedSecret, ...mlkemEncapsulationResult.sharedSecret],
        encapsulatedSecret: [...rsaEncapsulationResult.encapsulatedSecret, ...mlkemEncapsulationResult.encapsulatedSecret]
    };
    return encapsulationResult;
}

# Decapsulates the shared secret used for Key Encapsulation Mechanism (KEM) using RSA and ML-KEM-768 (Kyber768) private keys.
# ```ballerina
# crypto:KeyStore mlkemKeyStore = {
#     path: "/path/to/mlkem/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:KeyStore rsaKeyStore = {
#     path: "/path/to/rsa/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey mlkemPublicKey = check crypto:decodeMlKem768PublicKeyFromTrustStore(mlkemKeyStore, "keyAlias");
# crypto:PublicKey rsaPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateRsaKemMlKem768(rsaPublicKey, mlkemPublicKey);
# byte[] encapsulatedSecret = encapsulationResult.encapsulatedSecret;
# crypto:PrivateKey mlkemPrivateKey = check crypto:decodeMlKem768PrivateKeyFromKeyStore(mlkemKeyStore, "keyAlias", "keyStorePassword");
# crypto:PrivateKey rsaPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "keyAlias", "keyStorePassword");
# byte[] sharedSecret = check crypto:decapsulateRsaKemMlKem768(encapsulatedSecret, rsaPrivateKey, mlkemPrivateKey);
# ```
# + encapsulatedSecret - Encapsulated secret
# + rsaPrivateKey - RSA private key
# + mlkemPrivateKey - MlKem private key
# + return - Shared secret or else a `crypto:Error` if the keysize or private keys are invalid
public isolated function decapsulateRsaKemMlKem768(byte[] encapsulatedSecret, PrivateKey rsaPrivateKey, PrivateKey mlkemPrivateKey)
                                        returns byte[]|Error {
    byte[] rsaEncapsulatedSecret = encapsulatedSecret.slice(0, 256);
    byte[] mlkemEncapsulatedSecret = encapsulatedSecret.slice(256);
    byte[] rsaSharedSecret = check decapsulateRsaKem(rsaEncapsulatedSecret, rsaPrivateKey);
    byte[] mlkemSharedSecret = check decapsulateMlKem768(mlkemEncapsulatedSecret, mlkemPrivateKey);
    return [...rsaSharedSecret, ...mlkemSharedSecret];
}

# Creates a shared secret and its encapsulation used for Key Encapsulation Mechanism (KEM) using the RSA public key.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateRsaKem(publicKey);
# ```
# + publicKey - Public key
# + return - Encapsulated secret or else a `crypto:Error` if the public key is invalid
public isolated function encapsulateRsaKem(PublicKey publicKey)
                                    returns EncapsulationResult|Error = @java:Method {
    name: "encapsulateRsaKem",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;

# Decapsulates the shared secret used for Key Encapsulation Mechanism (KEM) from the given encapsulation for the given data.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateRsaKem(publicKey);
# byte[] encapsulatedSecret = encapsulationResult.encapsulatedSecret;
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyStorePassword");
# byte[] sharedSecret = check crypto:decapsulateRsaKem(encapsulatedSecret, privateKey);
# ```
# + encapsulatedSecret - Encapsulated secret
# + privateKey - Private key
# + return - Shared secret or else a `crypto:Error` if the encapsulatedSecret or the private key is invalid
public isolated function decapsulateRsaKem(byte[] encapsulatedSecret, PrivateKey privateKey)
                                    returns byte[]|Error = @java:Method {
    name: "decapsulateRsaKem",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;
