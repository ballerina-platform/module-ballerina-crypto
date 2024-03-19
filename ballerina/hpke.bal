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

# Represents the supported HPKE algorithms.
public type HpkeAlgorithm KYBER768|RSA_KYBER768;

# Represent the supported symmetric key sizes for AES algorithm.
public type AesKeySize 16|24|32;

# Represents the encapsulated secret and the ciphertext used in Hybrid Public Key Encryption (HPKE).
#
# + algorithm - The hybrid public key encryption algorithm used
# + encapsulatedSecret - The encapsulated secret
# + cipherText - The encrypted data
public type HybridEncryptionResult record {|
    HpkeAlgorithm algorithm;
    byte[] encapsulatedSecret;
    byte[] cipherText;
|};

# Returns the Kyber768-HPKE-encrypted value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:HybridEncryptionResult encryptionResult =  crypto:encryptKyber768Hpke(data, publicKey);
# ```
# + input - The content to be encrypted
# + publicKey - Public key used for encryption
# + symmetricKeySize - The length of the symmetric key (in bytes)
# + return - Encrypted data or else a `crypto:Error` if an error occurs
public isolated function encryptKyber768Hpke(byte[] input, PublicKey publicKey, AesKeySize symmetricKeySize = 32) returns HybridEncryptionResult|error {
    EncapsulationResult encapsulationResult = check encapsulateKyber768Kem(publicKey);
    byte[] sharedSecret = check hkdfSha256(encapsulationResult.sharedSecret, symmetricKeySize);
    byte[] encapsulatedSecret = encapsulationResult.encapsulatedSecret;
    byte[] ciphertext = check encryptAesEcb(input, sharedSecret);
    return {
        algorithm: KYBER768,
        encapsulatedSecret: encapsulatedSecret,
        cipherText: ciphertext
    };
}

# Returns the Kyber768-HPKE-decrypted value for the given Kyber768-encrypted data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:HybridEncryptionResult encryptionResult =  crypto:encryptKyber768Hpke(data, publicKey);
# byte[] cipherText = encryptionResult.cipherText;
# byte[] encapsulatedKey = encryptionResult.encapsulatedSecret;
# crypto:PrivateKey privateKey = check crypto:decodeKyber768PrivateKeyFromKeyStore(keyStore, "keyAlias");
# byte[] decryptedData = check crypto:decryptKyber768Hpke(cipherText, encapsulatedKey, privateKey);
# ```
# + input - The content to be decrypted
# + encapsulatedKey - The encapsulated secret
# + privateKey - The Kyber private key used for decryption
# + length - The length of the output (in bytes)
# + return - Decrypted data or else a `crypto:Error` if error occurs
public isolated function decryptKyber768Hpke(byte[] input, byte[] encapsulatedKey, PrivateKey privateKey, int length = 32) returns byte[]|error {
    byte[] key = check decapsulateKyber768Kem(encapsulatedKey, privateKey);
    key = check hkdfSha256(key, length);
    return check decryptAesEcb(input, key);
}


# Returns the RsaKyber768-HPKE-encrypted value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
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
# crypto:HybridEncryptionResult encryptionResult =  crypto:encryptRsaKyber768Hpke(data, rsaPublicKey, kyberPublicKey);
# ```
# + input - The content to be encrypted
# + rsaPublicKey - The RSA public key used for encryption
# + kyberPublicKey - The Kyber public key used for encryption
# + symmetricKeySize - The length of the symmetric key (in bytes)
# + return - Encrypted data or else a `crypto:Error` if an error occurs
public isolated function encryptRsaKyber768Hpke(byte[] input, PublicKey rsaPublicKey, PublicKey kyberPublicKey, AesKeySize symmetricKeySize = 32) returns HybridEncryptionResult|error {
    EncapsulationResult hybridEncapsulationResult = check encapsulateRsaKyber768Kem(rsaPublicKey, kyberPublicKey);
    byte[] sharedSecret = check hkdfSha256(hybridEncapsulationResult.sharedSecret, symmetricKeySize);
    byte[] encapsulatedSecret = hybridEncapsulationResult.encapsulatedSecret;
    byte[] ciphertext = check encryptAesEcb(input, sharedSecret);
    return {
        algorithm: RSA_KYBER768,
        encapsulatedSecret: encapsulatedSecret,
        cipherText: ciphertext
    };
}

# Returns the RsaKyber768-HPKE-decrypted value for the given RSAKyber768-encrypted data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
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
# crypto:HybridEncryptionResult encryptionResult =  crypto:encryptRsaKyber768Hpke(data, rsaPublicKey, kyberPublicKey);
# byte[] cipherText = encryptionResult.cipherText;
# byte[] encapsulatedKey = encryptionResult.encapsulatedSecret;
# crypto:PrivateKey kyberPrivateKey = check crypto:decodeKyber768PrivateKeyFromKeyStore(kyberKeyStore, "keyAlias");
# crypto:PrivateKey rsaPrivateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(rsaKeyStore, "keyAlias");
# byte[] decryptedData = check crypto:decryptRsaKyber768Hpke(cipherText, encapsulatedKey, rsaPrivateKey, kyberPrivateKey);
# ```
# + input - The content to be decrypted
# + encapsulatedKey - The encapsulated secret
# + rsaPrivateKey - The RSA private key used for decryption
# + kyberPrivateKey - The Kyber private key used for decryption
# + length - The length of the output (in bytes)
# + return - Decrypted data or else a `crypto:Error` if error occurs
public isolated function decryptRsaKyber768Hpke(byte[] input, byte[] encapsulatedKey, PrivateKey rsaPrivateKey, PrivateKey kyberPrivateKey, int length = 32) returns byte[]|error {
    byte[] key = check decapsulateRsaKyber768Kem(encapsulatedKey, rsaPrivateKey, kyberPrivateKey);
    key = check hkdfSha256(key, length);
    return check decryptAesEcb(input, key);
}
