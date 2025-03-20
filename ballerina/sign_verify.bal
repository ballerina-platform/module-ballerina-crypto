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

import ballerina/jballerina.java;

# Returns the RSA-MD5 based signature value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaMd5(data, privateKey);
# ```
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signRsaMd5(byte[] input, PrivateKey privateKey) returns byte[]|Error = @java:Method {
    name: "signRsaMd5",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Returns the RSA-SHA1 based signature value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha1(data, privateKey);
# ```
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signRsaSha1(byte[] input, PrivateKey privateKey) returns byte[]|Error = @java:Method {
    name: "signRsaSha1",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Returns the RSA-SHA256 based signature value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha256(data, privateKey);
# ```
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signRsaSha256(byte[] input, PrivateKey privateKey) returns byte[]|Error = @java:Method {
    name: "signRsaSha256",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Returns the RSA-SHA384 based signature value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha384(data, privateKey);
# ```
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signRsaSha384(byte[] input, PrivateKey privateKey) returns byte[]|Error = @java:Method {
    name: "signRsaSha384",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Returns the RSA-SHA512 based signature value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha512(data, privateKey);
# ```
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signRsaSha512(byte[] input, PrivateKey privateKey) returns byte[]|Error = @java:Method {
    name: "signRsaSha512",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Returns the SHA384withECDSA based signature value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeEcPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signSha384withEcdsa(data, privateKey);
# ```
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signSha384withEcdsa(byte[] input, PrivateKey privateKey) returns byte[]|Error = @java:Method {
    name: "signSha384withEcdsa",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Returns the SHA256withECDSA based signature value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeEcPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signSha256withEcdsa(data, privateKey);
# ```
#
# + input - The content to be signed
# + privateKey - Private key used for signing
# + return - The generated signature or else a `crypto:Error` if the private key is invalid
public isolated function signSha256withEcdsa(byte[] input, PrivateKey privateKey) returns byte[]|Error = @java:Method {
    name: "signSha256withEcdsa",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Verifies the RSA-MD5 based signature.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaMd5(data, privateKey);
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# boolean validity = check crypto:verifyRsaMd5Signature(data, signature, publicKey);
# ```
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the public key is invalid
public isolated function verifyRsaMd5Signature(byte[] data, byte[] signature, PublicKey publicKey)
                                               returns boolean|Error = @java:Method {
    name: "verifyRsaMd5Signature",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Verifies the RSA-SHA1 based signature.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha1(data, privateKey);
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# boolean validity = check crypto:verifyRsaSha1Signature(data, signature, publicKey);
# ```
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the public key is invalid
public isolated function verifyRsaSha1Signature(byte[] data, byte[] signature, PublicKey publicKey)
                                                returns boolean|Error = @java:Method {
    name: "verifyRsaSha1Signature",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Verifies the RSA-SHA256 based signature.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha256(data, privateKey);
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# boolean validity = check crypto:verifyRsaSha256Signature(data, signature, publicKey);
# ```
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the public key is invalid
public isolated function verifyRsaSha256Signature(byte[] data, byte[] signature, PublicKey publicKey)
                                                  returns boolean|Error = @java:Method {
    name: "verifyRsaSha256Signature",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Verifies the RSA-SHA384 based signature.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha384(data, privateKey);
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# boolean validity = check crypto:verifyRsaSha384Signature(data, signature, publicKey);
# ```
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the public key is invalid
public isolated function verifyRsaSha384Signature(byte[] data, byte[] signature, PublicKey publicKey)
                                                  returns boolean|Error = @java:Method {
    name: "verifyRsaSha384Signature",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Verifies the RSA-SHA512 based signature.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signRsaSha512(data, privateKey);
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# boolean validity = check crypto:verifyRsaSha512Signature(data, signature, publicKey);
# ```
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the public key is invalid
public isolated function verifyRsaSha512Signature(byte[] data, byte[] signature, PublicKey publicKey)
                                                  returns boolean|Error = @java:Method {
    name: "verifyRsaSha512Signature",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Verifies the SHA384withECDSA based signature.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeEcPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signSha384withEcdsa(data, privateKey);
# crypto:PublicKey publicKey = check crypto:decodeEcPublicKeyFromTrustStore(keyStore, "keyAlias");
# boolean validity = check crypto:verifySha384withEcdsaSignature(data, signature, publicKey);
# ```
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the public key is invalid
public isolated function verifySha384withEcdsaSignature(byte[] data, byte[] signature, PublicKey publicKey)
                                                  returns boolean|Error = @java:Method {
    name: "verifySha384withEcdsaSignature",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;

# Verifies the SHA256withECDSA based signature.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeEcPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] signature = check crypto:signSha256withEcdsa(data, privateKey);
# crypto:PublicKey publicKey = check crypto:decodeEcPublicKeyFromTrustStore(keyStore, "keyAlias");
# boolean validity = check crypto:verifySha256withEcdsaSignature(data, signature, publicKey);
# ```
#
# + data - The content to be verified
# + signature - Signature value
# + publicKey - Public key used for verification
# + return - Validity of the signature or else a `crypto:Error` if the public key is invalid
public isolated function verifySha256withEcdsaSignature(byte[] data, byte[] signature, PublicKey publicKey)
                                                  returns boolean|Error = @java:Method {
    name: "verifySha256withEcdsaSignature",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Sign"
} external;
