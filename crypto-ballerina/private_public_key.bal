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

# The key algorithms supported by the Crypto module.
public type KeyAlgorithm RSA;

# The `RSA` algorithm.
public const RSA = "RSA";

# Key store related configurations.
#
# + path - Path to the key store file
# + password - Key store password
public type KeyStore record {|
    string path;
    string password;
|};

# Trust store related configurations.
#
# + path - Path to the key store file
# + password - Key store password
public type TrustStore record {|
    string path;
    string password;
|};

# Private key used in cryptographic operations.
#
# + algorithm - Key algorithm
public type PrivateKey record {|
    KeyAlgorithm algorithm;
|};

# Public key used in cryptographic operations.
#
# + algorithm - Key algorithm
# + certificate - Public key certificate
public type PublicKey record {|
    KeyAlgorithm algorithm;
    Certificate certificate?;
|};

# X509 public key certificate information.
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
    time:Time notBefore;
    time:Time notAfter;
    byte[] signature;
    string signingAlgorithm;
|};

# Reads a private key from the provided PKCS#12 archive file.
# ```ballerina
#  crypto:KeyStore keyStore = {
#      path: "/home/ballerina/keystore.p12",
#      password: "keystorePassword"
#  };
#  crypto:PrivateKey|crypto:Error privateKey = crypto:decodePrivateKey(keyStore, "keyAlias", "keyPassword");
# ```
#
# + keyStore - Key store or Trust store configurations
# + keyAlias - Key alias
# + keyPassword - Key password
# + return - Reference to the private key or else a `crypto:Error` if the private key was unreadable
public isolated function decodePrivateKey(KeyStore|TrustStore keyStore, string keyAlias, string keyPassword)
                                          returns PrivateKey|Error = @java:Method {
    name: "decodePrivateKey",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Decode"
} external;

# Reads a public key from the provided PKCS#12 archive file.
# ```ballerina
#  crypto:KeyStore keyStore = {
#      path: "/home/ballerina/keystore.p12",
#      password: "keystorePassword"
#  };
#  crypto:PublicKey|crypto:Error publicKey = crypto:decodePublicKey(keyStore, "keyAlias");
# ```
#
# + keyStore - Key store or Trust store configurations
# + keyAlias - Key alias
# + return - Reference to the public key or else a `crypto:Error` if the private key was unreadable
public isolated function decodePublicKey(KeyStore|TrustStore keyStore, string keyAlias)
                                         returns PublicKey|Error = @java:Method {
    name: "decodePublicKey",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Decode"
} external;

# Returns the `crypto:PublicKey` created with the modulus and exponent retrieved from the JWK's endpoint.
# ```ballerina
# string modulus = "luZFdW1ynitztkWLC6xKegbRWxky...";
# string exponent = "AQAB";
# crypto:PublicKey|crypto:Error publicKey = crypto:buildRsaPublicKey(modulus, exponent);
# ```
#
# + modulus - JWK modulus value ('n' parameter) for the RSA public key
# + exponent - JWK exponent value ('e' paramenter) for the RSA public key
# + return - Reference to the public key or else a `crypto:Error` if the modulus or exponent is invalid
public isolated function buildRsaPublicKey(string modulus, string exponent) returns PublicKey|Error = @java:Method {
    name: "buildRsaPublicKey",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Decode"
} external;
