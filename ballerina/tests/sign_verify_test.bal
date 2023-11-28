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
isolated function testSignRsaMd5() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    string expectedMd5Signature = "457050eca794baf2149f53631f373525fbc7b40de83e0af5b03473e7b726064b" +
        "3eb6a8b7ce48218e4adaf2b598429236192a458ad5cef1ab2f456164f2646ba57a1ce6b858403504ddc49915bf8bf34558" +
        "0366bd9f7d1d777572fcacd3aa935267af6cf5dc988668b8cea0f57cd0e286658f0ca7c060d7a68b6330bc590b6db59489" +
        "aa676b1c539e5bb0116c64a963f8a03789b9fd7e689bac5576eea15d93d45be3547aef7c7dc26251dfa7bdf23b47c6a346" +
        "ae3603c158cbd32ff9298df71f930cebdda8564199e948f1ac03173e9f9d425240c7f99857d5f469dd0b23c0248b4fa42e" +
        "67145ec0e6e8abfc3f7f10122cc278b5469eb970034483839f290eec";
    byte[] md5Signature = check signRsaMd5(payload, privateKey);
    test:assertEquals(md5Signature.toBase16(), expectedMd5Signature);
}

@test:Config {}
isolated function testSignRsaSha1() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    string expectedSha1Signature = "70728d6d37fd83704bcb2649d93cfd20dbadb83a9d2169965d2a241795a131f" +
        "cfdb8b1b4f35f5de3c1f6f1d71ea0c9f80e494627b4c01d6e670ae4698b774171e8a017d62847c92aa47e868c230532af" +
        "9fc3a681387eead94578d2287674940df2e2f4a28f59688257254dfaab81c17617357ae05b42898412136abed116d6b86" +
        "eab68ff4ace029b67c7e4c5784a9bad00129b69d5afb6a89cb596cad56e8c98a1642eab87cb337980cc987708800e62a4" +
        "27c6f61828437d5491549b05025e9a98bf27825dc6002068678dde1e7d365407881b2b1a4d4e522a53f69e5b43202299e" +
        "02f7840f8991b8c335b0332b3b4bd658030ec3007f6f36c190b8663d3b746";
    byte[] sha1Signature = check signRsaSha1(payload, privateKey);
    test:assertEquals(sha1Signature.toBase16(), expectedSha1Signature);
}

@test:Config {}
isolated function testSignRsaSha256() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    string expectedSha256Signature = "34477f0e0a5457ca1a95049da10d59baa33ee4fa9e1bb8be3d3c70d82b980850" +
        "fd017a1c9984a97384736aacfe33d39ff8d63e01b952972910c86135b7558a2274c6d772f0d2fcdc0ac4aabc75f3978edb" +
        "d4aabd17d6447fb88e83b055bbff24d8212125b760c8bf88e9e4908645434f53a2ab0e3d5517c8e3241d8ebabbc767e7d9" +
        "24b5481621831f3a63e06c393c9378d782406705cd8823e12d3b4042a3cb738b8a8bb5731ff2934394c928c4262d130af6" +
        "6a2b507fc538bd16bccabc2f3b95137370dcca31e80866533bf445cf7f63aec6a9fa596333abb3a59d9b327891c7e6016e" +
        "0c11ef2a0d32088d4683d915005c9dcc8137611e5bff9dc4a5db6f87";
    byte[] sha256Signature = check signRsaSha256(payload, privateKey);
    test:assertEquals(sha256Signature.toBase16(), expectedSha256Signature);
}

@test:Config {}
isolated function testSignRsaSha384() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    string expectedSha384Signature = ("4981CC5213F384E8DB7950BF76C97AE20FA2A34244A517FC585B2381B9E88" +
        "278E447B92F6F452332BCA65DD5D6CCE04B5AC51D92E7E820B6FB826870DFBA437BBDA7F0E5850C02F72A8644DA8382" +
        "237E8C1ABD50A4BAEE179C8C838EA4AC53D2223B3C57D7D463A8E1BBFFC43F3F3C44494850377A8668E156B2D23B6E0" +
        "D8132632E3D79D68A391F619EF2E1E986A455F8F27092C66029C98D001A81FFE3E4B00991E7F0C0141D0635275544FC" +
        "5BF70A40C12B7BC765F6209C9640A60B9E978AD8DEC551983F5773A72327DF1A6256BEB8DF50A03F89443123E1354A9" +
        "EF7D8F8BF0659E1D6B77916B4AEEC79989AFDAA2F5B8983DE476C1A0FFBB2B647DE449E").toLowerAscii();
    byte[] sha384Signature = check signRsaSha384(payload, privateKey);
    test:assertEquals(sha384Signature.toBase16(), expectedSha384Signature);
}

@test:Config {}
isolated function testSignRsaSha512() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    string expectedSha512Signature = "6995ba8d2382a8c4f0ed513033126b2305df419a8b105ee60483243229d2c496" +
        "b7f670783c52068cd2b4b8c2392f2932c682f30057cb4d8d616ba3a142356b0394747b2a3642da4d23447bb997eacb086f" +
        "173b4045ee8ee014e1e667e34522defb7a4ac1b5b3f175d40a409d947d562fcf7b2b2631d273751a0f8c658bd8c1d1d23a" +
        "0dbe685b15e13abf45f998114577c85a6478d915a445645a6360944e4962c56bee79d2363931c77f8040c620692debc747" +
        "4c1e62d9d4b0b39fa664b8c3a32155c7c1966ef3d55993ad8f7f3bf4d929cf047ab91344facefeba944b043e1e31496753" +
        "9cb2e6e669ec3352073a8933a2a0cac6056b4997b3628132f7a7e553";
    byte[] sha512Signature = check signRsaSha512(payload, privateKey);
    test:assertEquals(sha512Signature.toBase16(), expectedSha512Signature);
}

@test:Config {}
isolated function testSignRsaMd5WithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey privateKey = {algorithm:"RSA"};
    byte[]|Error result = signRsaMd5(payload, privateKey);
    if result is Error {
        test:assertTrue(result.message().includes("Uninitialized private key:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testSignRsaSha1WithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey privateKey = {algorithm:"RSA"};
    byte[]|Error result = signRsaSha1(payload, privateKey);
    if result is Error {
        test:assertTrue(result.message().includes("Uninitialized private key:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testSignRsaSha256WithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey privateKey = {algorithm:"RSA"};
    byte[]|Error result = signRsaSha256(payload, privateKey);
    if result is Error {
        test:assertTrue(result.message().includes("Uninitialized private key:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testSignRsaSha384WithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey privateKey = {algorithm:"RSA"};
    byte[]|Error result = signRsaSha384(payload, privateKey);
    if result is Error {
        test:assertTrue(result.message().includes("Uninitialized private key:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testSignRsaSha512WithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey privateKey = {algorithm:"RSA"};
    byte[]|Error result = signRsaSha512(payload, privateKey);
    if result is Error {
        test:assertTrue(result.message().includes("Uninitialized private key:"));
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testVerifyRsaMd5() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(keyStore, "ballerina");
    byte[] md5Signature = check signRsaMd5(payload, privateKey);
    test:assertTrue(check verifyRsaMd5Signature(payload, md5Signature, publicKey));
}

@test:Config {}
isolated function testVerifyRsaSha1() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(keyStore, "ballerina");
    byte[] sha1Signature = check signRsaSha1(payload, privateKey);
    test:assertTrue(check verifyRsaSha1Signature(payload, sha1Signature, publicKey));
}

@test:Config {}
isolated function testVerifyRsaSha256() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(keyStore, "ballerina");
    byte[] sha256Signature = check signRsaSha256(payload, privateKey);
    test:assertTrue(check verifyRsaSha256Signature(payload, sha256Signature, publicKey));
}

@test:Config {}
isolated function testVerifyRsaSha384() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(keyStore, "ballerina");
    byte[] sha384Signature = check signRsaSha384(payload, privateKey);
    test:assertTrue(check verifyRsaSha384Signature(payload, sha384Signature, publicKey));
}

@test:Config {}
isolated function testVerifyRsaSha512() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeRsaPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    PublicKey publicKey = check decodeRsaPublicKeyFromTrustStore(keyStore, "ballerina");
    byte[] sha512Signature = check signRsaSha512(payload, privateKey);
    test:assertTrue(check verifyRsaSha512Signature(payload, sha512Signature, publicKey));
}

@test:Config {}
isolated function testVerifySha384withEcdsa() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: EC_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeEcPrivateKeyFromKeyStore(keyStore, "ec-keypair", "ballerina");
    PublicKey publicKey = check decodeEcPublicKeyFromTrustStore(keyStore, "ec-keypair");
    byte[] sha384withEcdsaSignature = check signSha384withEcdsa(payload, privateKey);
    test:assertTrue(check verifySha384withEcdsaSignature(payload, sha384withEcdsaSignature, publicKey));
}

@test:Config {}
isolated function testDecodeRsaPrivateKeyError() returns Error? {
    KeyStore keyStore = {
        path: EC_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error privateKey = decodeRsaPrivateKeyFromKeyStore(keyStore, "ec-keypair", "ballerina");
    if privateKey is Error {
        test:assertEquals(privateKey.message(), "Not a valid RSA key.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testDecodeEcPrivateKeyError() returns Error? {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error privateKey = decodeEcPrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    if privateKey is Error {
        test:assertEquals(privateKey.message(), "Not a valid EC key.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {}
isolated function testDecodeEcPublicKeyError() returns Error? {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey|Error publicKey = decodeEcPublicKeyFromTrustStore(keyStore, "ballerina");
    if publicKey is Error {
        test:assertEquals(publicKey.message(), "Not a valid EC public key.");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testDecodeRsaPublicKeyError() returns Error? {
    KeyStore keyStore = {
        path: EC_KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey|Error publicKey = decodeRsaPublicKeyFromTrustStore(keyStore, "ec-keypair");
    if publicKey is Error {
        test:assertEquals(publicKey.message(), "Not a valid RSA public key.");
    } else {
        test:assertFail("Expected error not found");
    }
}
