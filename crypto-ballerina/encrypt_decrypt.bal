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

# Padding algorithms supported by AES encryption and decryption.
public type AesPadding NONE|PKCS5;

# Padding algorithms supported with RSA encryption and decryption.
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
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  crypto:KeyStore keyStore = {
#      path: "/home/ballerina/keystore.p12",
#      password: "keystorePassword"
#  };
#  crypto:PublicKey publicKey = check crypto:decodePublicKey(keyStore, "keyAlias");
#  byte[]|crypto:Error cipherText = crypto:encryptRsaEcb(data, publicKey);
# ```
#
# + input - The content to be encrypted
# + key - Private or public key used for encryption
# + padding - The padding
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
public isolated function encryptRsaEcb(byte[] input, PrivateKey|PublicKey key, RsaPadding padding = PKCS1)
                                       returns byte[]|Error = @java:Method {
    name: "encryptRsaEcb",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the AES-CBC-encrypted value for the given data.
# ```ballerina
#  string dataString = "Hello Ballerina!";
#  byte[] data = dataString.toBytes();
#  byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      key[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      initialVector[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[]|crypto:Error cipherText = crypto:encryptAesCbc(data, key, initialVector);
# ```
#
# + input - The content to be encrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
public isolated function encryptAesCbc(byte[] input, byte[] key, byte[] iv, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "encryptAesCbc",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the AES-ECB-encrypted value for the given data.
# ```ballerina
#  string dataString = "Hello Ballerina!";
#  byte[] data = dataString.toBytes();
#  byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      key[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[]|crypto:Error cipherText = crypto:encryptAesEcb(data, key);
# ```
#
# + input - The content to be encrypted
# + key - Encryption key
# + padding - The padding
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
public isolated function encryptAesEcb(byte[] input, byte[] key, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "encryptAesEcb",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the AES-GCM-encrypted value for the given data.
# ```ballerina
#  string dataString = "Hello Ballerina!";
#  byte[] data = dataString.toBytes();
#  byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      key[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      initialVector[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[]|crypto:Error cipherText = crypto:encryptAesGcm(data, key, initialVector);
# ```
#
# + input - The content to be encrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding
# + tagSize - Tag size
# + return - Encrypted data or else a `crypto:Error` if the key is invalid
public isolated function encryptAesGcm(byte[] input, byte[] key, byte[] iv, AesPadding padding = PKCS5,
                                       int tagSize = 128) returns byte[]|Error = @java:Method {
    name: "encryptAesGcm",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Encrypt"
} external;

# Returns the RSA-decrypted value for the given RSA-encrypted data.
# ```ballerina
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  crypto:KeyStore keyStore = {
#      path: "/home/ballerina/keystore.p12",
#      password: "keystorePassword"
#  };
#  crypto:PublicKey publicKey = check crypto:decodePublicKey(keyStore, "keyAlias");
#  crypto:PrivateKey privateKey = check crypto:decodePrivateKey(keyStore, "keyAlias", "keyPassword");
#  byte[] cipherText = check crypto:encryptRsaEcb(data, publicKey);
#  byte[]|crypto:Error plainText = check crypto:decryptRsaEcb(cipherText, privateKey);
# ```
#
# + input - The content to be decrypted
# + key - Private or public key used for encryption
# + padding - The padding
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
public isolated function decryptRsaEcb(byte[] input, PrivateKey|PublicKey key, RsaPadding padding = PKCS1)
                                       returns byte[]|Error = @java:Method {
    name: "decryptRsaEcb",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the AES-CBC-decrypted value for the given AES-CBC-encrypted data.
# ```ballerina
#  string dataString = "Hello Ballerina!";
#  byte[] data = dataString.toBytes();
#  byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      key[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      initialVector[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[] cipherText = check crypto:encryptAesCbc(data, key, initialVector);
#  byte[]|crypto:Error plainText = crypto:decryptAesCbc(cipherText, key, initialVector);
# ```
#
# + input - The content to be decrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
public isolated function decryptAesCbc(byte[] input, byte[] key, byte[] iv, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "decryptAesCbc",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the AES-ECB-decrypted value for the given AES-ECB-encrypted data.
# ```ballerina
#  string dataString = "Hello Ballerina!";
#  byte[] data = dataString.toBytes();
#  byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      key[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[] cipherText = check crypto:encryptAesEcb(data, key);
#  byte[]|crypto:Error plainText = crypto:decryptAesEcb(cipherText, key);
# ```
#
# + input - The content to be decrypted
# + key - Encryption key
# + padding - The padding
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
public isolated function decryptAesEcb(byte[] input, byte[] key, AesPadding padding = PKCS5)
                                       returns byte[]|Error = @java:Method {
    name: "decryptAesEcb",
   'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Decrypt"
} external;

# Returns the AES-GCM-decrypted value for the given AES-GCM-encrypted data.
# ```ballerina
#  string dataString = "Hello Ballerina!";
#  byte[] data = dataString.toBytes();
#  byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      key[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#  foreach var i in 0...15 {
#      initialVector[i] = <byte>(check random:createIntInRange(0, 255);
#  }
#  byte[] cipherText = check crypto:encryptAesGcm(data, key, initialVector);
#  byte[]|crypto:Error plainText = crypto:decryptAesGcm(cipherText, key, initialVector);
# ```
#
# + input - The content to be decrypted
# + key - Encryption key
# + iv - Initialization vector
# + padding - The padding
# + tagSize - Tag size
# + return - Decrypted data or else a `crypto:Error` if the key is invalid
public isolated function decryptAesGcm(byte[] input, byte[] key, byte[] iv, AesPadding padding = PKCS5,
                                       int tagSize = 128) returns byte[]|Error = @java:Method {
    name: "decryptAesGcm",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Decrypt"
} external;
