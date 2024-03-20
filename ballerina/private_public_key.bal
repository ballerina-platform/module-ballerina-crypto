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

# Represents the supported key algorithms.
public type KeyAlgorithm RSA;

# The `RSA` algorithm.
public const RSA = "RSA";

# Represents the KeyStore-related configurations.
#
# + path - Path to the KeyStore file
# + password - KeyStore password
public type KeyStore record {|
    string path;
    string password;
|};

# Represents the truststore-related configurations.
#
# + path - Path to the TrustStore file
# + password - TrustStore password
public type TrustStore record {|
    string path;
    string password;
|};

# Represents the private key used in cryptographic operations.
#
# + algorithm - Key algorithm
public type PrivateKey record {|
    KeyAlgorithm algorithm;
|};

# Represents the public key used in cryptographic operations.
#
# + algorithm - Key algorithm
# + certificate - Public key certificate
public type PublicKey record {|
    KeyAlgorithm algorithm;
    Certificate certificate?;
|};

# Represents the X509 public key certificate information.
#
# + version0 - Version number
# + serial - Serial number
# + issuer - Issuer name
# + subject - Subject name
# + notBefore - Not before validity period of certificate
# + notAfter - Not after validity period of certificate
# + signature - Raw signature bits
# + signingAlgorithm - Signature algorithm
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
# + keyStore - KeyStore configurations
# + keyAlias - Key alias
# + keyPassword - Key password
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
# + keyStore - KeyStore configurations
# + keyAlias - Key alias
# + keyPassword - Key password
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeEcPrivateKeyFromKeyStore(KeyStore keyStore, string keyAlias, string keyPassword)
                                                         returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Dilithium3 private key from the given PKCS#12 archive file.
# ```ballerina
# crypto:KeyStore keyStore = {
#    path: "/path/to/keyStore.p12",
#   password
# };
# crypto:PrivateKey privateKey = check crypto:decodeDilithium3PrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# ```
#
# + keyStore - KeyStore configurations
# + keyAlias - Key alias
# + keyPassword - Key password
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeDilithium3PrivateKeyFromKeyStore(KeyStore keyStore, string keyAlias, string keyPassword)
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Kyber768 private key from the given PKCS#12 archive file.
# ```ballerina
# crypto:KeyStore keyStore = {
#    path: "/path/to/keyStore.p12",
#   password
# };
# crypto:PrivateKey privateKey = check crypto:decodeKyber768PrivateKeyFromKeyStore(keyStore, "keyAlias", "keyPassword");
# ```
#
# + keyStore - KeyStore configurations
# + keyAlias - Key alias
# + keyPassword - Key password
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeKyber768PrivateKeyFromKeyStore(KeyStore keyStore, string keyAlias, string keyPassword)
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the RSA private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeRsaPrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - Path to the key file
# + keyPassword - Password of the key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeRsaPrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the EC private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeEcPrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - Path to the key file
# + keyPassword - Password of the key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeEcPrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Dilithium3 private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeDilithium3PrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - Path to the key file
# + keyPassword - Password of the key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeDilithium3PrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
                                                        returns PrivateKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Kyber768 private key from the given private key and private key password.
# ```ballerina
# string keyFile = "/path/to/private.key";
# crypto:PrivateKey privateKey = check crypto:decodeKyber768PrivateKeyFromKeyFile(keyFile, "keyPassword");
# ```
#
# + keyFile - Path to the key file
# + keyPassword - Password of the key file if it is encrypted
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodeKyber768PrivateKeyFromKeyFile(string keyFile, string? keyPassword = ())
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
# + trustStore - TrustStore configurations
# + keyAlias - Key alias
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
# + trustStore - TrustStore configurations
# + keyAlias - Key alias
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeEcPublicKeyFromTrustStore(TrustStore trustStore, string keyAlias)
                                                          returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Dilithium3 public key from the given PKCS#12 archive file.
# ```ballerina
# crypto:TrustStore trustStore = {
#    path: "/path/tp/truststore.p12",
#    password: "truststorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeDilithium3PublicKeyFromTrustStore(trustStore, "keyAlias");
# ```
#
# + trustStore - TrustStore configurations
# + keyAlias - Key alias
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeDilithium3PublicKeyFromTrustStore(TrustStore trustStore, string keyAlias)
                                                        returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Kyber768 public key from the given PKCS#12 archive file.
# ```ballerina
# crypto:TrustStore trustStore = {
#    path: "/path/tp/truststore.p12",
#    password: "truststorePassword"
# };
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromTrustStore(trustStore, "keyAlias");
# ```
#
# + trustStore - TrustStore configurations
# + keyAlias - Key alias
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeKyber768PublicKeyFromTrustStore(TrustStore trustStore, string keyAlias)
                                                        returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the RSA public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeRsaPublicKeyFromCertFile(certFile);
# ```
#
# + certFile - Path to the certificate file
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeRsaPublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the EC public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeEcPublicKeyFromCertFile(certFile);
# ```
#
# + certFile - Path to the certificate file
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeEcPublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Dilithium3 public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeDilithium3PublicKeyFromCertFile(certFile);
# ```
#
# + certFile - Path to the certificate file
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeDilithium3PublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Decode"
} external;

# Decodes the Kyber768 public key from the given public certificate file.
# ```ballerina
# string certFile = "/path/to/public.cert";
# crypto:PublicKey publicKey = check crypto:decodeKyber768PublicKeyFromCertFile(certFile);
# ```
#
# + certFile - Path to the certificate file
# + return - Reference to the public key or else a `crypto:Error` if the public key was unreadable
public isolated function decodeKyber768PublicKeyFromCertFile(string certFile) returns PublicKey|Error = @java:Method {
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
