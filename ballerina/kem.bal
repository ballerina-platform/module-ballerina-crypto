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

# Represents the supported KEM algorithms.
public type KemAlgorithm RSA|KYBER768|RSA_KYBER768;

# The `RSA-Kyber768` KEM algorithm.
public const RSA_KYBER768 = "RSA_KYBER768";

# Represents the shared secret and its encapsulation used in Key Encapsulation Mechanism (KEM)
#
# + algorithm - KEM algorithm
# + encapsulatedSecret - Encapsulated secret 
# + sharedSecret - Shared secret
public type EncapsulationResult record {|
    KemAlgorithm algorithm;
    byte[] encapsulatedSecret;
    byte[] sharedSecret;
|};

# Creates a shared secret and its encapsulation used for Key Encapsulation Mechanism (KEM) using the Kyber768 public key.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(keyStore, "keyAlias", "keyStorePassword");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateKyber768Kem(publicKey);
# ```
# + publicKey - Public key
# + return - Encapsulated secret or else a `crypto:Error` if the public key is invalid
public isolated function encapsulateKyber768Kem(PublicKey publicKey)
                                    returns EncapsulationResult|Error = @java:Method {
    name: "encapsulateKyber768Kem",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;

# Decapsulates the Kyber768 shared secret used for Key Encapsulation Mechanism (KEM) from the given encapsulation for the given data.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateKyber768Kem(publicKey);
# byte[] encapsulatedSecret = encapsulationResult.encapsulatedSecret;
# crypto:PrivateKey privateKey = check crypto:decodeKyber768PrivateKeyFromKeyStore(keyStore, "keyAlias");
# byte[] sharedSecret = check crypto:decapsulateKyber768Kem(encapsulatedSecret, privateKey);
# ```
# + encapsulatedSecret - Encapsulated secret
# + privateKey - Private key
# + return - Shared secret or else a `crypto:Error` if the encapsulatedSecret or the private key is invalid
public isolated function decapsulateKyber768Kem(byte[] encapsulatedSecret, PrivateKey privateKey)
                                        returns byte[]|Error = @java:Method {
    name: "decapsulateKyber768Kem",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;

# Creates a shared secret and its encapsulation used for Key Encapsulation Mechanism (KEM) using RSA and Kyber768 public keys.
# ```ballerina
# crypto:KeyStore kyberKeyStore = {
#     path: "/path/to/kyber/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:KeyStore rsaKeyStore = {
#     path: "/path/to/rsa/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey kyberPublicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(kyberKeyStore, "keyAlias");
# crypto:PublicKey rsaPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateRsaKyber768Kem(rsaPublicKey, kyberPublicKey);
# ```
# + rsaPublicKey - RSA public key
# + kyberPublicKey - Kyber public key
# + return - Encapsulated secret or else a `crypto:Error` if the keysize or public keys are invalid
public isolated function encapsulateRsaKyber768Kem(PublicKey rsaPublicKey, PublicKey kyberPublicKey)
                                        returns EncapsulationResult|Error {
    EncapsulationResult rsaEncapsulationResult = check encapsulateRsaKem(rsaPublicKey);
    EncapsulationResult kyberEncapsulationResult = check encapsulateKyber768Kem(kyberPublicKey);
    EncapsulationResult encapsulationResult = {
        algorithm: RSA_KYBER768,
        sharedSecret: [...rsaEncapsulationResult.sharedSecret, ...kyberEncapsulationResult.sharedSecret],
        encapsulatedSecret: [...rsaEncapsulationResult.encapsulatedSecret, ...kyberEncapsulationResult.encapsulatedSecret]
    };
    return encapsulationResult;
}

# Decapsulates the shared secret used for Key Encapsulation Mechanism (KEM) using RSA and Kyber768 private keys.
# ```ballerina
# crypto:KeyStore kyberKeyStore = {
#     path: "/path/to/kyber/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:KeyStore rsaKeyStore = {
#     path: "/path/to/rsa/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey kyberPublicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(kyberKeyStore, "keyAlias");
# crypto:PublicKey rsaPublicKey = check crypto:decodeRsaPublicKeyFromTrustStore(rsaKeyStore, "keyAlias");
# crypto:EncapsulationResult encapsulationResult = check crypto:encapsulateRsaKyber768Kem(rsaPublicKey, kyberPublicKey);
# byte[] encapsulatedSecret = encapsulationResult.encapsulatedSecret;
# crypto:PrivateKey kyberPrivateKey = check crypto:decodeKyber768PrivateKeyFromKeyStore(kyberKeyStore, "keyAlias");
# crypto:PrivateKey rsaPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "keyAlias");
# byte[] sharedSecret = check crypto:decapsulateRsaKyber768Kem(encapsulatedSecret, rsaPrivateKey, kyberPrivateKey);
# ```
# + encapsulatedSecret - Encapsulated secret
# + rsaPrivateKey - RSA private key
# + kyberPrivateKey - Kyber private key
# + return - Shared secret or else a `crypto:Error` if the keysize or private keys are invalid
public isolated function decapsulateRsaKyber768Kem(byte[] encapsulatedSecret, PrivateKey rsaPrivateKey, PrivateKey kyberPrivateKey)
                                        returns byte[]|Error {
    byte[] rsaEncapsulatedSecret = encapsulatedSecret.slice(0, 256);
    byte[] kyberEncapsulatedSecret = encapsulatedSecret.slice(256);
    byte[] rsaSharedSecret = check decapsulateRsaKem(rsaEncapsulatedSecret, rsaPrivateKey);
    byte[] kyberSharedSecret = check decapsulateKyber768Kem(kyberEncapsulatedSecret, kyberPrivateKey);
    return [...rsaSharedSecret, ...kyberSharedSecret];
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
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias");
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
