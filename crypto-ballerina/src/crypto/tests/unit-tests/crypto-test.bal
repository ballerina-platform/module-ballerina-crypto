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

import ballerina/stringutils;
import ballerina/test;

@test:Config {}
function testHashFunctions() {
    byte[] input = "Ballerina test".toBytes();
    string expectedMd5Hash = "3B12196DB784CD9F86CC635D32764FDF".toLowerAscii();
    string expectedSha1Hash = "73FBC15DB28D52C03359EDE7A7DC40B4A83DF207".toLowerAscii();
    string expectedSha256Hash =
        "68F6CA0B55B55099331BF4EAA659B8BDC94FBDCE2F54D94FD90DA8240797A5D7".toLowerAscii();
    string expectedSha384Hash = ("F00B4A8C67B38E7E32FF8B1AB570345743878F7ADED9B5FA02518DDD84E16CBC" +
        "A344AF42CB60A1FD5C48C5FEDCFF7F24").toLowerAscii();
    string expectedSha512Hash = ("1C9BED7C87E7D17BA07ADD67F59B4A29AFD2B046409B65429E77D0CEE53A33C5" +
        "E26731DC1CB091FAADA8C5D6433CB1544690804CC046A55D6AFED8BE0B901062").toLowerAscii();
    test:assertEquals(crc32b(input), "d37b9692", msg = "Error while Hash with CRC32b.");
    test:assertEquals(hashMd5(input).toBase16(), expectedMd5Hash, msg = "Error while Hash with MD5.");
    test:assertEquals(hashSha1(input).toBase16(), expectedSha1Hash, msg = "Error while Hash with SHA1.");
    test:assertEquals(hashSha256(input).toBase16(), expectedSha256Hash, msg = "Error while Hash with SHA256.");
    test:assertEquals(hashSha384(input).toBase16(), expectedSha384Hash, msg = "Error while Hash with SHA384.");
    test:assertEquals(hashSha512(input).toBase16(), expectedSha512Hash, msg = "Error while Hash with SHA512.");
}

@test:Config {}
function testHmacFunctions() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[] key = "abcdefghijk".toBytes();

    string expectedMd5Hash = "3D5AC29160F2905A5C8153597798A4C1".toLowerAscii();
    string expectedSha1Hash = "13DD8D54D0EB702EDC6E8EDCAF616837D3A51499".toLowerAscii();
    string expectedSha256Hash =
        "2651203E18BF0088D3EF1215022D147E2534FD4BAD5689C9E5F12436E9758B15".toLowerAscii();
    string expectedSha384Hash = ("c27a281dffed3d4d176646d7261e9f6268a3d40a237cd274fc2f5970f637f1c" +
        "bc20a3835d7b7aa7401308737f23a9bf7").toLowerAscii();
    string expectedSha512Hash = ("78d99bf3e5277fc893af6cd6b0487c33ed3abc4f956fdd1fada302f135b012a" +
        "3c71cadaaeb462e51ff281202bdfa8807719b91f69742c3f71f036c469ac5b918").toLowerAscii();

    test:assertEquals(hmacMd5(message, key).toBase16(), expectedMd5Hash, msg = "Error while HMAC with MD5.");
    test:assertEquals(hmacSha1(message, key).toBase16(), expectedSha1Hash, msg = "Error while HMAC with SHA1.");
    test:assertEquals(hmacSha256(message, key).toBase16(), expectedSha256Hash, msg = "Error while HMAC with SHA256.");
    test:assertEquals(hmacSha384(message, key).toBase16(), expectedSha384Hash, msg = "Error while HMAC with SHA384.");
    test:assertEquals(hmacSha512(message, key).toBase16(), expectedSha512Hash, msg = "Error while HMAC with SHA512.");

    // Test error for empty key
    test:assertTrue((trap hmacMd5(message, [])) is error, msg = "No error for empty key while HMAC with MD5.");
    test:assertTrue((trap hmacSha1(message, [])) is error, msg = "No error for empty key while HMAC with SHA1.");
    test:assertTrue((trap hmacSha256(message, [])) is error, msg = "No error for empty key while HMAC with SHA256.");
    test:assertTrue((trap hmacSha384(message, [])) is error, msg = "No error for empty key while HMAC with SHA384.");
    test:assertTrue((trap hmacSha512(message, [])) is error, msg = "No error for empty key while HMAC with SHA512.");

}

@test:Config {}
function testSignAndVerifyRsaFunctions() {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PrivateKey pk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");

    string expectedMd5Signature = "457050eca794baf2149f53631f373525fbc7b40de83e0af5b03473e7b726064b" +
        "3eb6a8b7ce48218e4adaf2b598429236192a458ad5cef1ab2f456164f2646ba57a1ce6b858403504ddc49915bf8bf34558" +
        "0366bd9f7d1d777572fcacd3aa935267af6cf5dc988668b8cea0f57cd0e286658f0ca7c060d7a68b6330bc590b6db59489" +
        "aa676b1c539e5bb0116c64a963f8a03789b9fd7e689bac5576eea15d93d45be3547aef7c7dc26251dfa7bdf23b47c6a346" +
        "ae3603c158cbd32ff9298df71f930cebdda8564199e948f1ac03173e9f9d425240c7f99857d5f469dd0b23c0248b4fa42e" +
        "67145ec0e6e8abfc3f7f10122cc278b5469eb970034483839f290eec";
    string expectedSha1Signature = "70728d6d37fd83704bcb2649d93cfd20dbadb83a9d2169965d2a241795a131f" +
        "cfdb8b1b4f35f5de3c1f6f1d71ea0c9f80e494627b4c01d6e670ae4698b774171e8a017d62847c92aa47e868c230532af" +
        "9fc3a681387eead94578d2287674940df2e2f4a28f59688257254dfaab81c17617357ae05b42898412136abed116d6b86" +
        "eab68ff4ace029b67c7e4c5784a9bad00129b69d5afb6a89cb596cad56e8c98a1642eab87cb337980cc987708800e62a4" +
        "27c6f61828437d5491549b05025e9a98bf27825dc6002068678dde1e7d365407881b2b1a4d4e522a53f69e5b43202299e" +
        "02f7840f8991b8c335b0332b3b4bd658030ec3007f6f36c190b8663d3b746";
    string expectedSha256Signature = "34477f0e0a5457ca1a95049da10d59baa33ee4fa9e1bb8be3d3c70d82b980850" +
        "fd017a1c9984a97384736aacfe33d39ff8d63e01b952972910c86135b7558a2274c6d772f0d2fcdc0ac4aabc75f3978edb" +
        "d4aabd17d6447fb88e83b055bbff24d8212125b760c8bf88e9e4908645434f53a2ab0e3d5517c8e3241d8ebabbc767e7d9" +
        "24b5481621831f3a63e06c393c9378d782406705cd8823e12d3b4042a3cb738b8a8bb5731ff2934394c928c4262d130af6" +
        "6a2b507fc538bd16bccabc2f3b95137370dcca31e80866533bf445cf7f63aec6a9fa596333abb3a59d9b327891c7e6016e" +
        "0c11ef2a0d32088d4683d915005c9dcc8137611e5bff9dc4a5db6f87";
    string expectedSha384Signature = ("4981CC5213F384E8DB7950BF76C97AE20FA2A34244A517FC585B2381B9E88" +
        "278E447B92F6F452332BCA65DD5D6CCE04B5AC51D92E7E820B6FB826870DFBA437BBDA7F0E5850C02F72A8644DA8382" +
        "237E8C1ABD50A4BAEE179C8C838EA4AC53D2223B3C57D7D463A8E1BBFFC43F3F3C44494850377A8668E156B2D23B6E0" +
        "D8132632E3D79D68A391F619EF2E1E986A455F8F27092C66029C98D001A81FFE3E4B00991E7F0C0141D0635275544FC" +
        "5BF70A40C12B7BC765F6209C9640A60B9E978AD8DEC551983F5773A72327DF1A6256BEB8DF50A03F89443123E1354A9" +
        "EF7D8F8BF0659E1D6B77916B4AEEC79989AFDAA2F5B8983DE476C1A0FFBB2B647DE449E").toLowerAscii();
    string expectedSha512Signature = "6995ba8d2382a8c4f0ed513033126b2305df419a8b105ee60483243229d2c496" +
        "b7f670783c52068cd2b4b8c2392f2932c682f30057cb4d8d616ba3a142356b0394747b2a3642da4d23447bb997eacb086f" +
        "173b4045ee8ee014e1e667e34522defb7a4ac1b5b3f175d40a409d947d562fcf7b2b2631d273751a0f8c658bd8c1d1d23a" +
        "0dbe685b15e13abf45f998114577c85a6478d915a445645a6360944e4962c56bee79d2363931c77f8040c620692debc747" +
        "4c1e62d9d4b0b39fa664b8c3a32155c7c1966ef3d55993ad8f7f3bf4d929cf047ab91344facefeba944b043e1e31496753" +
        "9cb2e6e669ec3352073a8933a2a0cac6056b4997b3628132f7a7e553";

    byte[] md5Signature = checkpanic signRsaMd5(payload, pk);
    byte[] sha1Signature = checkpanic signRsaSha1(payload, pk);
    byte[] sha256Signature = checkpanic signRsaSha256(payload, pk);
    byte[] sha384Signature = checkpanic signRsaSha384(payload, pk);
    byte[] sha512Signature = checkpanic signRsaSha512(payload, pk);

    test:assertEquals(md5Signature.toBase16(), expectedMd5Signature, msg = "Error while RSA Sign with MD5.");
    test:assertEquals(sha1Signature.toBase16(), expectedSha1Signature, msg = "Error while RSA Sign with SHA1.");
    test:assertEquals(sha256Signature.toBase16(), expectedSha256Signature, msg = "Error while RSA Sign with SHA256.");
    test:assertEquals(sha384Signature.toBase16(), expectedSha384Signature, msg = "Error while RSA Sign with SHA384.");
    test:assertEquals(sha512Signature.toBase16(), expectedSha512Signature, msg = "Error while RSA Sign with SHA512.");

    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");

    test:assertTrue(checkpanic verifyRsaMd5Signature(payload, md5Signature, puk));
    test:assertTrue(checkpanic verifyRsaSha1Signature(payload, sha1Signature, puk));
    test:assertTrue(checkpanic verifyRsaSha256Signature(payload, sha256Signature, puk));
    test:assertTrue(checkpanic verifyRsaSha384Signature(payload, sha384Signature, puk));
    test:assertTrue(checkpanic verifyRsaSha512Signature(payload, sha512Signature, puk));
}

@test:Config {}
function testSignRsaFunctionWithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey pk = {algorithm:"RSA"};
    string errorMessage = "Uninitialized private key: Key must not be null";
    test:assertEquals(extractErrorMessage(signRsaMd5(payload, pk)), errorMessage,
        msg = "Incorrect output/error when with Signing RSA MD5 with invalid key.");
    test:assertEquals(extractErrorMessage(signRsaSha1(payload, pk)), errorMessage,
        msg = "Incorrect output/error when with Signing RSA SHA1 with invalid key.");
    test:assertEquals(extractErrorMessage(signRsaSha256(payload, pk)), errorMessage,
        msg = "Incorrect output/error when with Signing RSA SHA256 with invalid key.");
    test:assertEquals(extractErrorMessage(signRsaSha384(payload, pk)), errorMessage,
        msg = "Incorrect output/error when with Signing RSA SAH384 with invalid key.");
    test:assertEquals(extractErrorMessage(signRsaSha512(payload, pk)), errorMessage,
        msg = "Incorrect output/error when with Signing RSA SHA512 with invalid key.");
}

function extractErrorMessage(byte[]|error result) returns string {
    if (result is error) {
        return <string>result.message();
    } else {
        return "";
    }
}

@test:Config {}
function testEncryptAndDecryptWithAesEcb() {

    // Test encrypt and decrypt with AES ECB NoPadding
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    int i = 0;
    while(i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = checkpanic encryptAesEcb(message, key, NONE);
    byte[] plainText = checkpanic decryptAesEcb(cipherText, key, NONE);
    test:assertEquals(plainText.toBase16(), message.toBase16(), msg = "Error while Encrypt/Decrypt with AES ECB.");

    // Test encrypt and decrypt with AES ECB NoPadding using invalid key size
    i = 0;
    byte[] invalidKey = [];
    while(i < 31) {
        invalidKey[i] = <byte> i;
        i = i + 1;
    }
    byte[]|error result = encryptAesEcb(message, invalidKey, NONE);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result), "Invalid key size. valid key sizes in bytes: [16, 24, 32]",
            msg = "Incorrect error for invalid key while No Padding Encryption with AES ECB.");
    } else {
        test:assertFail(msg = "No error for invalid key while No Padding Encryption with AES ECB.");
    }

    // Test encrypt and decrypt with AES ECB NoPadding using invalid input length
    byte[] invalidMessage = "Ballerina crypto test".toBytes();
    result = encryptAesEcb(invalidMessage, key, NONE);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result),
            "Error occurred while AES encrypt/decrypt: Input length not multiple of 16 bytes",
            msg = "Incorrect error for for invalid input length while No Padding Encryption with AES ECB.");
    } else {
        test:assertFail(msg = "No error for invalid input length while No Padding Encryption with AES ECB.");
    }

    // Test encrypt and decrypt with AES ECB PKCS5
    message = "Ballerina crypto test".toBytes();
    cipherText = checkpanic encryptAesEcb(message, key, "PKCS5");
    plainText = checkpanic decryptAesEcb(cipherText, key, "PKCS5");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with AES ECB PKCS5.");

}

@test:Config {}
function testEncryptAndDecryptWithAesCbc() {

    // Test encrypt and decrypt with AES CBC NoPadding
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while(i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while(i < 16) {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = checkpanic encryptAesCbc(message, key, iv, NONE);
    byte[] plainText = checkpanic decryptAesCbc(cipherText, key, iv, NONE);
    test:assertEquals(plainText.toBase16(), message.toBase16(), msg = "Error while Encrypt/Decrypt with AES CBC.");

    // Test encrypt and decrypt with AES CBC NoPadding using invalid key size
    i = 0;
    byte[] invalidKey = [];
    while(i < 31) {
        invalidKey[i] = <byte> i;
        i = i + 1;
    }
    byte[]|error result = encryptAesCbc(message, invalidKey, iv, NONE);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result), "Invalid key size. valid key sizes in bytes: [16, 24, 32]",
            msg = "Incorrect error for invalid key while No Padding Encryption with AES CBC.");
    } else {
        test:assertFail(msg = "No error for invalid key while No Padding Encryption with AES CBC.");
    }

    // Test encrypt and decrypt with AES CBC NoPadding using invalid IV length
    i = 0;
    byte[] invalidIv = [];
    while(i < 15) {
        invalidIv[i] = <byte> i;
        i = i + 1;
    }
    result = encryptAesCbc(message, key, invalidIv, NONE);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result),
            "Error occurred while AES encrypt/decrypt: Wrong IV length: must be 16 bytes long",
            msg = "Incorrect error for invalid key while No Padding Encryption with AES CBC.");
    } else {
        test:assertFail(msg = "No error for invalid IV length while No Padding Encryption with AES CBC.");
    }

    // Test encrypt and decrypt with AES CBC NoPadding using invalid input length
    byte[] invalidMessage = "Ballerina crypto test".toBytes();
    result = encryptAesCbc(invalidMessage, key, iv, NONE);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result),
            "Error occurred while AES encrypt/decrypt: Input length not multiple of 16 bytes",
            msg = "Incorrect error for for invalid input length while No Padding Encryption with AES CBC.");
    } else {
        test:assertFail(msg = "No error for invalid input length while No Padding Encryption with AES CBC.");
    }

    // Test encrypt and decrypt with AES CBC PKCS5
    message = "Ballerina crypto test".toBytes();
    cipherText = checkpanic encryptAesCbc(message, key, iv, "PKCS5");
    plainText = checkpanic decryptAesCbc(cipherText, key, iv, "PKCS5");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with AES CBC PKCS5.");

}

@test:Config {}
function testEncryptAndDecryptWithAesGcm() {

    // Test encrypt and decrypt with AES GCM NoPadding
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] key = [];
    byte[] iv = [];
    int i = 0;
    while(i < 16) {
        key[i] = <byte> i;
        i = i + 1;
    }
    i = 0;
    while(i < 16) {
        iv[i] = <byte> i;
        i = i + 1;
    }
    byte[] cipherText = checkpanic encryptAesGcm(message, key, iv, NONE, 128);
    byte[] plainText = checkpanic decryptAesGcm(cipherText, key, iv, NONE, 128);
    test:assertEquals(plainText.toBase16(), message.toBase16(), msg = "Error while Encrypt/Decrypt with AES GCM.");

    // Test encrypt and decrypt with AES GCM NoPadding using invalid key size
    i = 0;
    byte[] invalidKey = [];
    while(i < 31) {
        invalidKey[i] = <byte> i;
        i = i + 1;
    }
    byte[]|error result = encryptAesGcm(message, invalidKey, iv, NONE, 128);
    if (result is error) {
        test:assertEquals(extractErrorMessage(result), "Invalid key size. valid key sizes in bytes: [16, 24, 32]",
            msg = "Incorrect error for invalid key while No Padding Encryption with AES GCM.");
    } else {
        test:assertFail(msg = "No error for invalid key while No Padding Encryption with AES GCM.");
    }

    // Test encrypt and decrypt with AES GCM PKCS5
    message = "Ballerina crypto test".toBytes();
    cipherText = checkpanic encryptAesGcm(message, key, iv, "PKCS5");
    plainText = checkpanic decryptAesGcm(cipherText, key, iv, "PKCS5");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with AES GCM PKCS5.");

    // Test encrypt and decrypt with AES GCM PKCS5 with invalid tag value
    result = encryptAesGcm(message, key, iv, "PKCS5", 500);
    if (result is error) {
        test:assertTrue(stringutils:contains(extractErrorMessage(result),
            "Invalid tag size. valid tag sizes in bytes:"),
            msg = "Incorrect error for invalid key while Encryption with AES GCM PKCS5.");
    } else {
        test:assertFail(msg = "No error for invalid tag size while Encryption with AES GCM PKCS5.");
    }

}

@test:Config {}
function testEncryptAndDecryptWithRsaEcb() {

    // Test encrypt and decrypt with RSA ECB PKCS1
    byte[] message = "Ballerina crypto test           ".toBytes();
    KeyStore keyStore = {
        path: "src/crypto/tests/resources/datafiles/testKeystore.p12",
        password: "ballerina"
    };
    PublicKey puk = checkpanic decodePublicKey(keyStore, "ballerina");
    PrivateKey prk = checkpanic decodePrivateKey(keyStore, "ballerina", "ballerina");
    byte[] cipherText = checkpanic encryptRsaEcb(message, puk, "PKCS1");
    byte[] plainText = checkpanic decryptRsaEcb(cipherText, prk, "PKCS1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB PKCS1.");

    // Test encrypt and decrypt with RSA ECB OAEPwithMD5andMGF1
    cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPwithMD5andMGF1");
    plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPwithMD5andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithMD5andMGF1.");

    // Test encrypt and decrypt with RSA ECB OAEPWithSHA1AndMGF1
    cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPWithSHA1AndMGF1");
    plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPWithSHA1AndMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPWithSHA1AndMGF1.");

    // Test encrypt and decrypt with RSA ECB OAEPWithSHA256AndMGF1
    cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPWithSHA256AndMGF1");
    plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPWithSHA256AndMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPWithSHA256AndMGF1.");

    // Test encrypt and decrypt with RSA ECB OAEPwithSHA384andMGF1
    cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPwithSHA384andMGF1");
    plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPwithSHA384andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithSHA384andMGF1.");

    // Test encrypt and decrypt with RSA ECB OAEPwithSHA512andMGF1
    cipherText = checkpanic encryptRsaEcb(message, puk, "OAEPwithSHA512andMGF1");
    plainText = checkpanic decryptRsaEcb(cipherText, prk, "OAEPwithSHA512andMGF1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB OAEPwithSHA512andMGF1.");

    // Test encrypt with private key and decrypt with public key using RSA ECB PKCS1
    cipherText = checkpanic encryptRsaEcb(message, prk, "PKCS1");
    plainText = checkpanic decryptRsaEcb(cipherText, puk, "PKCS1");
    test:assertEquals(plainText.toBase16(), message.toBase16(),
        msg = "Error while Encrypt/Decrypt with RSA ECB PKCS1.");

    // Test encrypt and decrypt with RSA ECB PKCS1 with an invalid key
    PrivateKey invalidPrk = {algorithm:"RSA"};
    byte[]|error result = encryptRsaEcb(message, invalidPrk, "PKCS1");
    if (result is error) {
        test:assertEquals(extractErrorMessage(result), "Uninitialized private/public key",
            msg = "Incorrect error for for invalid key while Encryption with RSA ECB.");
    } else {
        test:assertFail(msg = "No error for invalid key Encryption with RSA ECB PKCS1.");
    }

}
