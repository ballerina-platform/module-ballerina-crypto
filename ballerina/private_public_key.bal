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
import ballerina/time;

# Represents the supported public key algorithms.
public type KeyAlgorithm RSA|MLKEM768|MLDSA65;

# Represents the `RSA` algorithm.
public const RSA = "RSA";

# Represents the `ML-KEM-768` algorithm.
public const MLKEM768 = "ML-KEM-768";

# Represents the `ML-DSA-65` algorithm.
public const MLDSA65 = "ML-DSA-65";

# Represents the KeyStore-related configurations.
#
# + path - The KeyStore file path
# + password - The KeyStore password
public type KeyStore record {|
    string path;
    string password;
|};

# Represents the truststore-related configurations.
#
# + path - The TrustStore file path
# + password - The TrustStore password
public type TrustStore record {|
    string path;
    string password;
|};

# Represents the private key used in cryptographic operations.
#
# + algorithm - Specifies the cryptographic algorithm used for the private key. Must be one of the supported algorithms(RSA, MLKEM768, MLDSA65)
public type PrivateKey record {|
    KeyAlgorithm algorithm;
|};

# Represents the public key used in cryptographic operations.
#
# + algorithm - Specifies the cryptographic algorithm used for the public key. Must be one of the supported algorithms(RSA, MLKEM768, MLDSA65)
# + certificate - Optional X.509 certificate associated with the public key
public type PublicKey record {|
    KeyAlgorithm algorithm;
    Certificate certificate?;
|};

# Represents the X509 public key certificate information.
#
# + version0 - Version number of the certificate
# + serial - Serial number of the certificate
# + issuer - Issuer name of the certificate
# + subject - Subject name of the certificate
# + notBefore - The start of the validity period of the certificate
# + notAfter - The end of the validity period of the certificate
# + signature - Raw signature bits of the certificate
# + signingAlgorithm - The algorithm used to sign the certificate
public type Certificate record {|
    int version0;
    int serial;
    string issuer;
    string subject;
    time:Utc notBefore;
    time:Utc notAfter;
    byte[] signature;
    string signingAlgorithm;
|};

# Decodes the RSA private key from the given PKCS#12 archive file.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# ```
#
# + keyStore - The KeyStore configurations containing the file path and password
# + keyAlias - The alias of the private key in the KeyStore
# + keyPassword - The password used to access the private key in the KeyStore
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeRsaPrivateKeyFromKeyStore(KeyStore keyStore, string keyAlias, string keyPassword)
                                                         returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the EC private key from the given PKCS#12 archive file.
# ```ballerina
# crypto:KeyStore keyStore = {
#     path: "/path/to/keyStore.p12",
#     password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeEcPrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# ```
#
# + keyStore - The KeyStore configurations containing the file path and password
# + keyAlias - The alias of the private key in the KeyStore
# + keyPassword - The password used to access the private key in the KeyStore
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeEcPrivateKeyFromKeyStore(KeyStore keyStore, string keyAlias, string keyPassword)
                                                         returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-DSA-65 (Dilithium3) private key from the given PKCS#12 archive file.
# ```ballerina
# crypto:KeyStore keyStore = {
#    path: "/path/to/keyStore.p12",
#    password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeMlDsa65PrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# ```
#
# + keyStore - The KeyStore configurations containing the file path and password
# + keyAlias - The alias of the private key in the KeyStore
# + keyPassword - The password used to access the private key in the KeyStore
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeMlDsa65PrivateKeyFromKeyStore(KeyStore keyStore, string keyAlias, string keyPassword)
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-KEM-768 (Kyber768) private key from the given PKCS#12 archive file.
# ```ballerina
# crypto:KeyStore keyStore = {
#    path: "/path/to/keyStore.p12",
#    password: "keyStorePassword"
# };
# crypto:PrivateKey privateKey = check crypto:decodeMlKem768PrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# ```
#
# + keyStore - The KeyStore configurations containing the file path and password
# + keyAlias - The alias of the private key in the KeyStore
# + keyPassword - The password used to access the private key in the KeyStore
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeMlKem768PrivateKeyFromKeyStore(KeyStore keyStore, string keyAlias, string keyPassword)
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the RSA private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - The private key file path
# + keyPassword - The password used to decrypt the private key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeRsaPrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the RSA private key from the given private key content as a byte array.
# ```ballerina
# byte[] keyFileContent = [45,45,45,45,45,66,69,71,73,78,...];
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromContent(keyFileContent, "keyPassword");
# ```
#
# + content - Private key content as a byte array
# + keyPassword - Password of the private key if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeRsaPrivateKeyFromContent(byte[] content, string? keyPassword = ()) returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the EC private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeEcPrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - The private key file path
# + keyPassword - The password used to decrypt the private key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeEcPrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-DSA-65 (Dilithium3) private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeMlDsa65PrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - The private key file path
# + keyPassword - The password used to decrypt the private key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeMlDsa65PrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-KEM-768 (Kyber768) private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeMlKem768PrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - The private key file path
# + keyPassword - The password used to decrypt the private key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeMlKem768PrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the RSA public key from the given PKCS#12 archive file.
# ```ballerina
# crypto:TrustStore trustStore = {
#     path: "/path/tp/truststore.p12",
#     password: "truststorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromTrustStore(trustStore, "keyAlias");
# ```
#
# + trustStore - The trustStore configurations containing the file path and password
# + keyAlias - The alias of the public key in the TrustStore
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeRsaPublicKeyFromTrustStore(TrustStore trustStore, string keyAlias)
                                                          returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the EC public key from the given PKCS#12 archive file.
# ```ballerina
# crypto:TrustStore trustStore = {
#     path: "/path/tp/truststore.p12",
#     password: "truststorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeEcPublicKeyFromTrustStore(trustStore, "keyAlias");
# ```
#
# + trustStore - The trustStore configurations containing the file path and password
# + keyAlias - The alias of the public key in the TrustStore
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeEcPublicKeyFromTrustStore(TrustStore trustStore, string keyAlias)
                                                          returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-DSA-65 (Dilithium3) public key from the given PKCS#12 archive file.
# ```ballerina
# crypto:TrustStore trustStore = {
#    path: "/path/tp/truststore.p12",
#    password: "truststorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeMlDsa65PublicKeyFromTrustStore(trustStore, "keyAlias");
# ```
#
# + trustStore - The trustStore configurations containing the file path and password
# + keyAlias - The alias of the public key in the TrustStore
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeMlDsa65PublicKeyFromTrustStore(TrustStore trustStore, string keyAlias)
                                                        returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-KEM-768 (Kyber768) public key from the given PKCS#12 archive file.
# ```ballerina
# crypto:TrustStore trustStore = {
#    path: "/path/tp/truststore.p12",
#    password: "truststorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeMlKem768PublicKeyFromTrustStore(trustStore, "keyAlias");
# ```
#
# + trustStore - The trustStore configurations containing the file path and password
# + keyAlias - The alias of the public key in the TrustStore
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeMlKem768PublicKeyFromTrustStore(TrustStore trustStore, string keyAlias)
                                                        returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the RSA public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromCertFile(certFile);
# ```
#
# + certFile - The certificate file path
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeRsaPublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the RSA public key from the given public certificate content.
# ```ballerina
# byte[] certContent = [45,45,45,45,45,66,69,71,73,78,...];
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromContent(certContent);
# ```
#
# + content - The certificate content as a byte array
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeRsaPublicKeyFromContent(byte[] content) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the EC public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeEcPublicKeyFromCertFile(certFile);
# ```
#
# + certFile - The certificate file path
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeEcPublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-DSA-65 (Dilithium3) public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeMlDsa65PublicKeyFromCertFile(certFile);
# ```
#
# + certFile - The certificate file path
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeMlDsa65PublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the ML-KEM-768 (Kyber768) public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeMlKem768PublicKeyFromCertFile(certFile);
# ```
#
# + certFile - The certificate file path
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeMlKem768PublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Builds the RSA public key from the given modulus and exponent parameters.
# ```ballerina
# string modulus = "luZFdW1ynitztkWLC6xKegbRWxky...";
# string exponent = "AQAB";
# crypto:PublicKey publicKey = check crypto:buildRsaPublicKey(modulus, exponent);
# ```
#
# + modulus - Modulus value ('n' parameter) for the RSA public key
# + exponent - Exponent value ('e' paramenter) for the RSA public key
# + return - Reference to the public key or else a `crypto:Error` if the modulus or exponent is invalid
public isolated function buildRsaPublicKey(string modulus, string exponent) returns PublicKey|Error = @java:Method {
    name: "buildRsaPublicKey",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;
