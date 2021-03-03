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

import ballerina/test;

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromP12() {
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    if (result is PrivateKey) {
        test:assertEquals(result["algorithm"], "RSA");
    } else {
        test:assertFail(msg = "Error while decoding encrypted private-key from a p12 file. " + result.message());
    }
}

@test:Config {}
isolated function testReadPrivateKeyFromNonExistingP12() {
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12.invalid",
        password: "ballerina"
    };
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    if (result is Error) {
        test:assertTrue(result.message().includes("PKCS12 key store not found at:"),
            msg = "Incorrect error for reading private key from non existing p12 file.");
    } else {
        test:assertFail(msg = "No error while attempting to read a private key from a non-existing p12 file.");
    }
}

@test:Config {}
isolated function testParsePrivateKeyFromPkcs8KeyFile() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/pkcs8Private.key");
    if (result is PrivateKey) {
        test:assertEquals(result["algorithm"], "RSA");
    } else {
        test:assertFail(msg = "Error while decoding private-key from a key file. " + result.message());
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromPkcs8KeyFile() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/pkcs8EncryptedPrivate.key", "ballerina");
    if (result is PrivateKey) {
        test:assertEquals(result["algorithm"], "RSA");
    } else {
        test:assertFail(msg = "Error while decoding private-key from a key file. " + result.message());
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromPkcs8KeyFileWithInvalidPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/pkcs8EncryptedPrivate.key", "invalid-password");
    if (result is Error) {
        test:assertEquals(result.message(), "Unable to do private key operations: unable to read encrypted data: javax.crypto.BadPaddingException: pad block corrupted");
    } else {
        test:assertFail(msg = "Error while decoding private-key from a key file with invalid password.");
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromPkcs8KeyFileWithNoPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/pkcs8EncryptedPrivate.key");
    if (result is Error) {
        test:assertEquals(result.message(), "Failed to read the encrypted private key without password.");
    } else {
        test:assertFail(msg = "Error while decoding private-key from a key file with invalid password.");
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromPkcs1KeyFile() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/pkcs1EncryptedPrivate.key", "ballerina");
    if (result is PrivateKey) {
        test:assertEquals(result["algorithm"], "RSA");
    } else {
        test:assertFail(msg = "Error while decoding private-key from a key file. " + result.message());
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromPkcs1KeyFileWithInvalidPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/pkcs1EncryptedPrivate.key", "invalid-password");
    if (result is Error) {
        test:assertEquals(result.message(), "Unable to do private key operations: exception using cipher - please check password and data.");
    } else {
        test:assertFail(msg = "Error while decoding private-key from a key file with invalid password.");
    }
}

@test:Config {}
isolated function testParseEncryptedPrivateKeyFromPkcs1KeyFileWithNoPassword() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/pkcs1EncryptedPrivate.key");
    if (result is Error) {
        test:assertEquals(result.message(), "Failed to read the encrypted private key without password.");
    } else {
        test:assertFail(msg = "Error while decoding private-key from a key file with invalid password.");
    }
}

@test:Config {}
isolated function testReadPrivateKeyFromNonExistingKeyFile() {
    PrivateKey|Error result = decodeRsaPrivateKeyFromKeyFile("tests/resources/datafiles/private.key.invalid");
    if (result is Error) {
        test:assertTrue(result.message().includes("Key file not found at:"),
            msg = "Incorrect error for reading private key from non existing key file.");
    } else {
        test:assertFail(msg = "No error while attempting to read a private key from a non-existing key file.");
    }
}

@test:Config {}
isolated function testParsePublicKeyFromP12() {
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12",
        password: "ballerina"
    };
    PublicKey publicKey = checkpanic decodeRsaPublicKeyFromTrustStore(keyStore, "ballerina");
    test:assertEquals(publicKey["algorithm"], "RSA", msg = "Error while check parsing encrypted public-key from a p12 file.");
    map<json> certificate = <map<json>>publicKey["certificate"];

    string serial = (<int>certificate["serial"]).toString();
    string issuer = <string>certificate["issuer"];
    string subject = <string>certificate["subject"];
    var notBefore = certificate["notBefore"];
    var notAfter = certificate["notAfter"];
    var signature = certificate["signature"];
    string signingAlgorithm = <string>certificate["signingAlgorithm"];

    test:assertEquals(serial, "2097012467",
        msg = "Error while checking serial from encrypted public-key from a p12 file.");
    test:assertEquals(issuer, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US",
        msg = "Error while checking issuer from encrypted public-key from a p12 file.");
    test:assertEquals(subject, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US",
        msg = "Error while checking subject from encrypted public-key from a p12 file.");
    test:assertTrue(notBefore is map<json>, msg = "Error in the format of notBefore field from a certificate.");
    test:assertTrue(notAfter is map<json>, msg = "Error in the format of notAfter field from a certificate.");
    test:assertTrue(signature is json[], msg = "Error in the format of signature field from a certificate.");
    test:assertEquals(signingAlgorithm, "SHA256withRSA",
        msg = "Error while checking signingAlgorithm from encrypted public-key from a p12 file.");
}

@test:Config {}
isolated function testReadPublicKeyFromNonExistingP12() {
    KeyStore keyStore = {
        path: "tests/resources/datafiles/keystore.p12.invalid",
        password: "ballerina"
    };
    PublicKey|Error result = decodeRsaPublicKeyFromTrustStore(keyStore, "ballerina");
    if (result is Error) {
        test:assertTrue(result.message().includes("PKCS12 key store not found at:"),
            msg = "Incorrect error for reading public key from non existing p12 file.");
    } else {
        test:assertFail(msg = "No error while attempting to read a public key from a non-existing p12 file.");
    }
}

@test:Config {}
isolated function testParsePublicKeyFromX509CertFile() {
    PublicKey publicKey = checkpanic decodeRsaPublicKeyFromCertFile("tests/resources/datafiles/x509Public.crt");
    test:assertEquals(publicKey["algorithm"], "RSA", msg = "Error while check parsing public-key from a cert file.");
    map<json> certificate = <map<json>>publicKey["certificate"];

    string serial = (<int>certificate["serial"]).toString();
    string issuer = <string>certificate["issuer"];
    string subject = <string>certificate["subject"];
    var notBefore = certificate["notBefore"];
    var notAfter = certificate["notAfter"];
    var signature = certificate["signature"];
    string signingAlgorithm = <string>certificate["signingAlgorithm"];

    test:assertEquals(serial, "2097012467",
        msg = "Error while checking serial from public-key from a cert file.");
    test:assertEquals(issuer, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US",
        msg = "Error while checking issuer from public-key from a cert file.");
    test:assertEquals(subject, "CN=localhost,OU=WSO2,O=WSO2,L=Mountain View,ST=CA,C=US",
        msg = "Error while checking subject from public-key from a cert file.");
    test:assertTrue(notBefore is map<json>, msg = "Error in the format of notBefore field from a certificate.");
    test:assertTrue(notAfter is map<json>, msg = "Error in the format of notAfter field from a certificate.");
    test:assertTrue(signature is json[], msg = "Error in the format of signature field from a certificate.");
    test:assertEquals(signingAlgorithm, "SHA256withRSA",
        msg = "Error while checking signingAlgorithm from public-key from a cert file.");
}

@test:Config {}
isolated function testReadPublicKeyFromNonExistingCertFile() {
    PublicKey|Error result = decodeRsaPublicKeyFromCertFile("tests/resources/datafiles/public.crt.invalid");
    if (result is Error) {
        test:assertTrue(result.message().includes("Certificate file not found at:"),
            msg = "Incorrect error for reading public key from non existing cert file.");
    } else {
        test:assertFail(msg = "No error while attempting to read a public key from a non-existing cert file.");
    }
}

@test:Config {}
isolated function testBuildPublicKeyFromJwk() {
    string modulus = "luZFdW1ynitztkWLC6xKegbRWxky-5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9-" +
        "PmjdGtau4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0-s6kMl2EhB-rk7gXluEep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsy" +
        "L4tztS70vmmX121qm0sTJdKWP4HxXyqK9neolXI9fYyHOYILVNZ69z_73OOVhkh_mvTmWZLM7GM6sApmyLX6OXUp8z0pkY-v" +
        "T_9-zRxxQs7GurC4_C1nK3rI_0ySUgGEafO1atNjYmlFN-M3tZX6nEcA6g94IavyQ";
    string exponent = "AQAB";
    PublicKey publicKey = checkpanic buildRsaPublicKey(modulus, exponent);
    test:assertEquals(publicKey["algorithm"], "RSA", msg = "Error while check parsing public-key from JWK.");
}
