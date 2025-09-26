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

# Represents the supported symmetric key sizes for AES algorithm.
public type AesKeySize 16|24|32;

# Represents the encapsulated secret and the ciphertext used in Hybrid Public Key Encryption (HPKE).
#
# + encapsulatedSecret - The encapsulated secret as a byte array
# + cipherText - The encrypted data as a byte array
public type HybridEncryptionResult record {|
    byte[] encapsulatedSecret;
    byte[] cipherText;
|};

# Returns the ML-KEM-768-AES-hybrid-encrypted value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeMlKem768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:HybridEncryptionResult encryptionResult = check crypto:encryptMlKem768Hpke(data, publicKey);
# ```
# + input - The content to be encrypted, provided as a byte array
# + publicKey - The public key used for encryption, provided as a `crypto:PublicKey` record
# + symmetricKeySize - The length of the symmetric key in bytes
# + return - The encrypted data as a `crypto:HybridEncryptionResult`, or a `crypto:Error` if an error occurs
public isolated function encryptMlKem768Hpke(byte[] input, PublicKey publicKey, AesKeySize symmetricKeySize = 32) returns HybridEncryptionResult|Error {
    EncapsulationResult encapsulationResult = check encapsulateMlKem768(publicKey);
    byte[] sharedSecret = check hkdfSha256(encapsulationResult.sharedSecret, symmetricKeySize);
    byte[] encapsulatedSecret = encapsulationResult.encapsulatedSecret;
    byte[] ciphertext = check encryptAesEcb(input, sharedSecret);
    return {
        encapsulatedSecret: encapsulatedSecret,
        cipherText: ciphertext
    };
}

# Returns the ML-KEM-768-AES-hybrid-encrypted value for the given encrypted data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeMlKem768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:HybridEncryptionResult encryptionResult = check crypto:encryptMlKem768Hpke(data, publicKey);
# byte[] cipherText = encryptionResult.cipherText;
# byte[] encapsulatedKey = encryptionResult.encapsulatedSecret;
# crypto:PrivateKey privateKey = check crypto:decodeMlKem768PrivateKeyFromKeyStore(keyStore, "keyAlias", "keyStorePassword");
# byte[] decryptedData = check crypto:decryptMlKem768Hpke(cipherText, encapsulatedKey, privateKey);
# ```
# + input - The content to be decrypted, provided as a byte array
# + encapsulatedKey - The encapsulated secret, provided as a byte array representing the encrypted key material
# + privateKey - The MlKem private key used for decryption, provided as a `crypto:PrivateKey` record
# + symmetricKeySize - The length of the symmetric key in bytes
# + return - The decrypted data as a byte array, or a `crypto:Error` if an error occurs.
public isolated function decryptMlKem768Hpke(byte[] input, byte[] encapsulatedKey, PrivateKey privateKey, AesKeySize symmetricKeySize = 32) returns byte[]|Error {
    byte[] key = check decapsulateMlKem768(encapsulatedKey, privateKey);
    key = check hkdfSha256(key, symmetricKeySize);
    return check decryptAesEcb(input, key);
}

# Returns the RSA-KEM-ML-KEM-768-AES-hybrid-encrypted value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
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
# crypto:HybridEncryptionResult encryptionResult = check crypto:encryptRsaKemMlKem768Hpke(data, rsaPublicKey, mlkemPublicKey);
# ```
# + input - The content to be encrypted, provided as a byte array
# + rsaPublicKey - The RSA public key used for encryption, provided as a `crypto:PublicKey` record
# + mlkemPublicKey - The ML-KEM public key used for encryption, provided as a `crypto:PublicKey` record
# + symmetricKeySize - The length of the symmetric key in bytes
# + return - The encrypted data as a `crypto:HybridEncryptionResult`, or a `crypto:Error` if an error occurs
public isolated function encryptRsaKemMlKem768Hpke(byte[] input, PublicKey rsaPublicKey, PublicKey mlkemPublicKey, AesKeySize symmetricKeySize = 32) returns HybridEncryptionResult|Error {
    EncapsulationResult hybridEncapsulationResult = check encapsulateRsaKemMlKem768(rsaPublicKey, mlkemPublicKey);
    byte[] sharedSecret = check hkdfSha256(hybridEncapsulationResult.sharedSecret, symmetricKeySize);
    byte[] ciphertext = check encryptAesEcb(input, sharedSecret);
    return {
        encapsulatedSecret: hybridEncapsulationResult.encapsulatedSecret,
        cipherText: ciphertext
    };
}

# Returns the RSA-KEM-ML-KEM-768-AES-hybrid-encrypted value for the given encrypted data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
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
# crypto:HybridEncryptionResult encryptionResult = check crypto:encryptRsaKemMlKem768Hpke(data, rsaPublicKey, mlkemPublicKey);
# byte[] cipherText = encryptionResult.cipherText;
# byte[] encapsulatedKey = encryptionResult.encapsulatedSecret;
# crypto:PrivateKey mlkemPrivateKey = check crypto:decodeMlKem768PrivateKeyFromKeyStore(mlkemKeyStore, "keyAlias", "keyStorePassword");
# crypto:PrivateKey rsaPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "keyAlias", "keyStorePassword");
# byte[] decryptedData = check crypto:decryptRsaKemMlKem768Hpke(cipherText, encapsulatedKey, rsaPrivateKey, mlkemPrivateKey);
# ```
# + input - The content to be decrypted, provided as a byte array
# + encapsulatedKey - The encapsulated secret, provided as a byte array representing the encrypted key material
# + rsaPrivateKey - The RSA private key used for decryption, provided as a `crypto:PrivateKey` record
# + mlkemPrivateKey - The MlKem private key used for decryption, provided as a `crypto:PrivateKey` record
# + symmetricKeySize - The length of the symmetric key in bytes
# + return - The decrypted data as a byte array, or a `crypto:Error` if an error occurs.
public isolated function decryptRsaKemMlKem768Hpke(byte[] input, byte[] encapsulatedKey, PrivateKey rsaPrivateKey, PrivateKey mlkemPrivateKey, AesKeySize symmetricKeySize = 32) returns byte[]|Error {
    byte[] key = check decapsulateRsaKemMlKem768(encapsulatedKey, rsaPrivateKey, mlkemPrivateKey);
    key = check hkdfSha256(key, symmetricKeySize);
    return check decryptAesEcb(input, key);
}
