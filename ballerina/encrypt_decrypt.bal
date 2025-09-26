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

# Represents the padding algorithms supported by AES encryption and decryption.
public type AesPadding NONE|PKCS5;

# Represents the padding algorithms supported with RSA encryption and decryption.
public type RsaPadding PKCS1|OAEPwithMD5andMGF1|OAEPWithSHA1AndMGF1|OAEPWithSHA256AndMGF1|OAEPwithSHA384andMGF1|
                       OAEPwithSHA512andMGF1;

# Represents no padding for encryption or decryption.
public const NONE = "NONE";

# Represents the PKCS1 padding mode for RSA encryption and decryption.
public const PKCS1 = "PKCS1";

# Represents the PKCS5 padding mode for AES encryption and decryption.
public const PKCS5 = "PKCS5";

# Represents the OAEP padding mode with MD5 and MGF1 for RSA encryption and decryption.
public const OAEPwithMD5andMGF1 = "OAEPwithMD5andMGF1";

# Represents the OAEP padding mode with SHA-1 and MGF1 for RSA encryption and decryption.
public const OAEPWithSHA1AndMGF1 = "OAEPWithSHA1AndMGF1";

# Represents the OAEP padding mode with SHA-256 and MGF1 for RSA encryption and decryption.
public const OAEPWithSHA256AndMGF1 = "OAEPWithSHA256AndMGF1";

# Represents the OAEP padding mode with SHA-384 and MGF1 for RSA encryption and decryption.
public const OAEPwithSHA384andMGF1 = "OAEPwithSHA384andMGF1";

# Represents the OAEP padding mode with SHA-512 and MGF1 for RSA encryption and decryption.
public const OAEPwithSHA512andMGF1 = "OAEPwithSHA512andMGF1";

# Returns the RSA-encrypted value for the given data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# byte[] cipherText = check crypto:encryptRsaEcb(data, publicKey);
# ```
#
# + input - The content to be encrypted, provided as a byte array
# + key - The RSA key (private or public) used for encryption. The key must be compatible with the RSA algorithm
# + padding - The padding algorithm to use. Supported values are `PKCS1`, `OAEPwithMD5andMGF1`, `OAEPWithSHA1AndMGF1`, `OAEPWithSHA256AndMGF1`, `OAEPwithSHA384andMGF1`, and `OAEPwithSHA512andMGF1`
# + return - The encrypted data as a byte array, or a `crypto:Error` if the key is invalid or an error occurs during encryption
public isolated function encryptRsaEcb(byte[] input, PrivateKey|PublicKey key, RsaPadding padding = PKCS1)
                                       returns byte[]|Error = @java:Method {
    name: "encryptRsaEcb",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the AES-CBC-encrypted value for the given data.
# ```ballerina
# string dataString = "Hello Ballerina!";
# byte[] data = dataString.toBytes();
# byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     key[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     initialVector[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[] cipherText = check crypto:encryptAesCbc(data, key, initialVector);
# ```
#
# + input - The content to be encrypted, provided as a byte array
# + key - The encryption key used for AES-CBC encryption
# + iv - The initialization vector used to initialize the AES-CBC encryption process
# + padding - The padding algorithm to use. Supported value is `PKCS5`
# + return - The encrypted data as a byte array, or a `crypto:Error` if the key, IV, or padding is invalid
public isolated function encryptAesCbc(byte[] input, byte[] key, byte[] iv, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "encryptAesCbc",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the AES-ECB-encrypted value for the given data.
# ```ballerina
# string dataString = "Hello Ballerina!";
# byte[] data = dataString.toBytes();
# byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     key[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[] cipherText = check crypto:encryptAesEcb(data, key);
# ```
#
# + input - The content to be encrypted, provided as a byte array
# + key - The encryption key used for AES-ECB encryption
# + padding - The padding algorithm to use. Supported value is `PKCS5`
# + return - The encrypted data as a byte array, or a `crypto:Error` if the key or padding is invalid
public isolated function encryptAesEcb(byte[] input, byte[] key, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "encryptAesEcb",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the AES-GCM-encrypted value for the given data.
# ```ballerina
# string dataString = "Hello Ballerina!";
# byte[] data = dataString.toBytes();
# byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     key[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     initialVector[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[] cipherText = check crypto:encryptAesGcm(data, key, initialVector);
# ```
#
# + input - The content to be encrypted, provided as a byte array
# + key - The encryption key used for AES-GCM encryption
# + iv - The initialization vector used to initialize the AES-GCM encryption process
# + padding - The padding algorithm to use. Supported value is `PKCS5`
# + tagSize - The size of the authentication tag in bits. Valid values are 128, 120, 112, 104, or 96
# + return - The encrypted data as a byte array, or a `crypto:Error` if the key, IV, or tag size is invalid
public isolated function encryptAesGcm(byte[] input, byte[] key, byte[] iv, AesPadding padding = NONE,
                                       int tagSize = 128) returns byte[]|Error = @java:Method {
    name: "encryptAesGcm",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the RSA-decrypted value for the given RSA-encrypted data.
# ```ballerina
# string input = "Hello Ballerina";
# byte[] data = input.toBytes();
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(keyStore, "keyAlias");
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# byte[] cipherText = check crypto:encryptRsaEcb(data, publicKey);
# byte[] plainText = check crypto:decryptRsaEcb(cipherText, privateKey);
# ```
#
# + input - The content to be decrypted, provided as a byte array
# + key - The RSA key (private or public) used for decryption. The key must be compatible with the RSA algorithm
# + padding - The padding algorithm to use. Supported values are `PKCS1`, `OAEPwithMD5andMGF1`, `OAEPWithSHA1AndMGF1`, `OAEPWithSHA256AndMGF1`, `OAEPwithSHA384andMGF1`, and `OAEPwithSHA512andMGF1`
# + return - The decrypted data as a byte array, or a `crypto:Error` if the key is invalid or an error occurs during decryption
public isolated function decryptRsaEcb(byte[] input, PrivateKey|PublicKey key, RsaPadding padding = PKCS1)
                                       returns byte[]|Error = @java:Method {
    name: "decryptRsaEcb",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the AES-CBC-decrypted value for the given AES-CBC-encrypted data.
# ```ballerina
# string dataString = "Hello Ballerina!";
# byte[] data = dataString.toBytes();
# byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     key[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     initialVector[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[] cipherText = check crypto:encryptAesCbc(data, key, initialVector);
# byte[] plainText = check crypto:decryptAesCbc(cipherText, key, initialVector);
# ```
#
# + input - The content to be decrypted, provided as a byte array
# + key - The encryption key used for AES-CBC decryption
# + iv - The initialization vector used to initialize the AES-CBC decryption process
# + padding - The padding algorithm to use. Supported value is `PKCS5`
# + return - The decrypted data as a byte array, or a `crypto:Error` if the key, IV, or padding is invalid
public isolated function decryptAesCbc(byte[] input, byte[] key, byte[] iv, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "decryptAesCbc",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the AES-ECB-decrypted value for the given AES-ECB-encrypted data.
# ```ballerina
# string dataString = "Hello Ballerina!";
# byte[] data = dataString.toBytes();
# byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     key[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[] cipherText = check crypto:encryptAesEcb(data, key);
# byte[] plainText = check crypto:decryptAesEcb(cipherText, key);
# ```
#
# + input - The content to be decrypted, provided as a byte array
# + key - The encryption key used for AES-ECB decryption
# + padding - The padding algorithm to use. Supported value is `PKCS5`
# + return - The decrypted data as a byte array, or a `crypto:Error` if the key or padding is invalid
public isolated function decryptAesEcb(byte[] input, byte[] key, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "decryptAesEcb",
   'class: "io.ballerina.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the AES-GCM-decrypted value for the given AES-GCM-encrypted data.
# ```ballerina
# string dataString = "Hello Ballerina!";
# byte[] data = dataString.toBytes();
# byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     key[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
# foreach int i in 0...15 {
#     initialVector[i] = <byte>(check random:createIntInRange(0, 255));
# }
# byte[] cipherText = check crypto:encryptAesGcm(data, key, initialVector);
# byte[] plainText = check crypto:decryptAesGcm(cipherText, key, initialVector);
# ```
#
# + input - The content to be decrypted, provided as a byte array
# + key - The encryption key used for AES-GCM decryption
# + iv - The initialization vector used to initialize the AES-GCM decryption process
# + padding - The padding algorithm to use. Supported value is `PKCS5`
# + tagSize - The size of the authentication tag in bits. Valid values are 128, 120, 112, 104, or 96
# + return - The decrypted data as a byte array, or a `crypto:Error` if the key, IV, or tag size is invalid
public isolated function decryptAesGcm(byte[] input, byte[] key, byte[] iv, AesPadding padding = PKCS5,
                                       int tagSize = 128) returns byte[]|Error = @java:Method {
    name: "decryptAesGcm",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the PGP-encrypted value for the given data.
# ```ballerina
# byte[] message = "Hello Ballerina!".toBytes();
# byte[] cipherText = check crypto:encryptPgp(message, "public_key.asc");
# ```
#
# + plainText - The content to be encrypted, provided as a byte array
# + publicKey - Path to the public key file in ASCII-armored format
# + options - Optional PGP encryption options, such as compression or cipher preferences
# + return - The encrypted data as a byte array, or a `crypto:Error` if the public key is invalid or an error occurs during encryption
public isolated function encryptPgp(byte[] plainText, string publicKey, *Options options)
                                       returns byte[]|Error = @java:Method {
    name: "encryptPgp",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the PGP-encrypted stream of the content given in the input stream.
# ```ballerina
# stream<byte[], error?> inputStream = check io:fileReadBlocksAsStream("input.txt");
# stream<byte[], crypto:Error?>|crypto:Error encryptedStream = crypto:encryptStreamAsPgp(inputStream, "public_key.asc");
# ```
#
# + inputStream - The content to be encrypted, provided as a stream of byte arrays
# + publicKey - Path to the public key file in ASCII-armored format
# + options - Optional PGP encryption options, such as compression or cipher preferences
# + return - The encrypted content as a stream of byte arrays, or a `crypto:Error` if the public key is invalid or an error occurs during encryption
public isolated function encryptStreamAsPgp(stream<byte[], error?> inputStream, string publicKey,
        *Options options) returns stream<byte[], Error?>|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the PGP-decrypted value of the given PGP-encrypted data.
# ```ballerina
# byte[] message = "Hello Ballerina!".toBytes();
# byte[] cipherText = check crypto:encryptPgp(message, "public_key.asc");
# 
# byte[] passphrase = check io:fileReadBytes("pass_phrase.txt");
# byte[] decryptedMessage = check crypto:decryptPgp(cipherText, "private_key.asc", passphrase);
# ```
#
# + cipherText - The encrypted content to be decrypted, provided as a byte array
# + privateKey - Path to the private key file in ASCII-armored format
# + passphrase - The passphrase used to unlock the private key
# + return - The decrypted data as a byte array, or a `crypto:Error` if the key or passphrase is invalid
public isolated function decryptPgp(byte[] cipherText, string privateKey, byte[] passphrase)
                                       returns byte[]|Error = @java:Method {
    name: "decryptPgp",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the PGP-decrypted stream of the content given in the input stream.
# ```ballerina
# byte[] passphrase = check io:fileReadBytes("pass_phrase.txt");
# stream<byte[], error?> inputStream = check io:fileReadBlocksAsStream("pgb_encrypted.txt");
# stream<byte[], crypto:Error?>|crypto:Error decryptedStream = crypto:decryptStreamFromPgp(inputStream, "private_key.asc", passphrase);
# ```
#
# + inputStream - The encrypted content provided as a stream of byte arrays
# + privateKey - Path to the private key file in ASCII-armored format
# + passphrase - The passphrase used to unlock the private key
# + return - The decrypted content as a stream of byte arrays, or a `crypto:Error` if the key or passphrase is invalid
public isolated function decryptStreamFromPgp(stream<byte[], error?> inputStream, string privateKey,
        byte[] passphrase) returns stream<byte[], Error?>|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decrypt"
} external;
