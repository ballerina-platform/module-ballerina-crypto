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
function testParsePublicKeyFromP12() {
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    test:assertEquals(puk["algorithm"], "RSA", msg = "Error while check parsing encrypted public-key from a p12 file.");
    map<json> certificate = <map<json>>puk["certificate"];

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
function testReadPublicKeyFromNonExistingP12() {
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12.invalid",
        password: "ballerina"
    };
    test:assertTrue((trap decodePublicKey(keyStore, "ballerina")) is error,
        msg = "No error while attempting to read a public key from a non-existing p12 file.");
}
