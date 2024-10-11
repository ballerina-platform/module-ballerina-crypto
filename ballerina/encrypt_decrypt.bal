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

# No padding.
public const NONE = "NONE";

# The `PKCS1` padding mode.
public const PKCS1 = "PKCS1";

# The `PKCS5` padding mode.
public const PKCS5 = "PKCS5";

# The `OAEPwithMD5andMGF1` padding mode.
public const OAEPwithMD5andMGF1 = "OAEPwithMD5andMGF1";

# The `OAEPWithSHA1AndMGF1` padding mode.
public const OAEPWithSHA1AndMGF1 = "OAEPWithSHA1AndMGF1";

# The `OAEPWithSHA256AndMGF1` padding mode.
public const OAEPWithSHA256AndMGF1 = "OAEPWithSHA256AndMGF1";

# The `OAEPwithSHA384andMGF1` padding mode.
public const OAEPwithSHA384andMGF1 = "OAEPwithSHA384andMGF1";

# The `OAEPwithSHA512andMGF1` padding mode.
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
# + input - The content to be encrypted
# + key - Private or public key used for encryption
# + padding - The padding algorithm
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
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
# + input - The content to be encrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding algorithm
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
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
# + input - The content to be encrypted
# + key - Encryption key
# + padding - The padding algorithm
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
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
# + input - The content to be encrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding algorithm
# + tagSize - Tag size
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
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
# + input - The content to be decrypted
# + key - Private or public key used for encryption
# + padding - The padding algorithm
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
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
# + input - The content to be decrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding algorithm
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
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
# + input - The content to be decrypted
# + key - Encryption key
# + padding - The padding algorithm
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
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
# + input - The content to be decrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding algorithm
# + tagSize - Tag size
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
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
# + plainText - The content to be encrypted
# + publicKeyPath - Path to the public key
# + options - PGP encryption options
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
public isolated function encryptPgp(byte[] plainText, string publicKeyPath, *Options options)
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
# + inputStream - The content to be encrypted as a stream
# + privateKeyPath - Path to the private key
# + return - Encrypted stream or else a `crypto:Error` if the key is invalid
public isolated function encryptStreamAsPgp(stream<byte[], error?> inputStream, string publicKeyPath,
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
# + cipherText - The encrypted content to be decrypted
# + privateKey -
# + passphrase - passphrase of the private key
# + return - Decrypted data or else a `crypto:Error` if the key or passphrase is invalid
public isolated function decryptPgp(byte[] cipherText, string privateKeyPath, byte[] passphrase)
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
# + inputStream - The encrypted content as a stream
# + privateKeyPath - Path to the private key
# + passphrase - passphrase of the private key
# + return - Decrypted stream or else a `crypto:Error` if the key or passphrase is invalid
public isolated function decryptStreamFromPgp(stream<byte[], error?> inputStream, string privateKeyPath,
        byte[] passphrase) returns stream<byte[], Error?>|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decrypt"
} external;
