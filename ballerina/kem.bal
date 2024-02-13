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

# Represents the secret key and its encapsulation used in Key Encapsulation Mechanism (KEM)
#
# + algorithm - KEM algorithm
# + encapsulatedSecret - Encapsulated secret key
# + secret - Secret key
public type EncapsulatedKey record {
    string algorithm?;
    byte[] encapsulatedSecret;
    byte[] secret;
};

# Creates a Kyber768 encapsulated secret used for Key Encapsulation Mechanism (KEM) from the given public key.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(keyStore, "keyAlias", "keyStorePassword");
# crypto:EncapsulatedKey encapsulatedKey = check crypto:generateKyber768EncapsulatedKey(publicKey);
# ```
# + publicKey - Public key
# + return - Encapsulated secret or else a `crypto:Error` if the public key is invalid
public isolated function generateKyber768EncapsulatedKey(PublicKey publicKey)
                                   returns EncapsulatedKey|Error = @java:Method {
    name: "generateKyber768EncapsulatedKey",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;

# Decapsulates the Kyber768 shared secret used for Key Encapsulation Mechanism (KEM) from the given encapsulation for the given data.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:EncapsulatedKey encapsulatedKey = check crypto:generateKyber768EncapsulatedKey(publicKey);
# byte[] encapsulatedSecret = encapsulatedKey.encapsulatedSecret;
# crypto:PrivateKey privateKey = check crypto:decodeKyber768PrivateKeyFromKeyStore(keyStore, "keyAlias");
# byte[] sharedSecret = check crypto:decapsulateKyber768SharedSecret(encapsulatedSecret, privateKey);
# ```
# + encapsulation - Encapsulated secret
# + privateKey - Private key
# + return - Shared secret or else a `crypto:Error` if the encapsulation or the private key is invalid
public isolated function decapsulateKyber768SharedSecret(byte[] encapsulation, PrivateKey privateKey)
                                       returns byte[]|Error = @java:Method {
    name: "decapsulateKyber768SharedSecret",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kem"
} external;
