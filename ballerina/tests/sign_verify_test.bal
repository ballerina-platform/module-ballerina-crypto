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
isolated function testSignMlDsa65() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: MLDSA_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeMlDsa65PrivateKeyFromKeyStore(keyStore, "mldsa-keypair", "ballerina");
    string expectedMlDsa65Signature = "6ed60e3deb502db7c8e6631b68fcebd60ecdd7505ba504bb23bfa88f70721f762f82683263c5b651" +
        "2c1832961e90f03430a5d2ba1afc872842f81b7c843b50b52f624b93c3ff7d3e2c0178c6f8c13de5" +
        "54f905e993fbe11f42437251b7eaaf376273b1ef019943127dc9c2fe241f3f2bfff34848f3bd65e4" +
        "deefb7ececba6d0b89dc8b8bfdd2636dbfb042fe3c7ebddabd6ae14655febec302606562ca666687" +
        "a3095cd56cf30dced6e28b83d17b0f9a68b4fae502a686c5577719668db4f36c8117b503bf99d1ad" +
        "aa875916c7cc409f4aefc5955f7635e894434ca0b61e4e1729c17528029267be67e49bb8084097ec" +
        "631a0cd8507b3cd2e233e07f52f226d611c554093d99b8d50020c04d21e0a4e08980a798c411ad88" +
        "6916bf26416b72c0931b0d555185c11a0997c82ebbdddea31316cb696a388282dbb447e09b8319fe" +
        "f37946e80094c8da1e121e66441077c02ecab250f8e7d4e1d916b8e97ec025cffa7f4cb9773de9df" +
        "b2373b6ea6d99f7bfc6327164ccc16219a0ce180a84619eaa1dec2474bc5b25111b9761869ef987a" +
        "93b7ad955bd67ced1ba9514168b5888a1776c968cc17a98afa96d08f1f88e0b82f7bde901ded8e8d" +
        "c73b518330ce88f3ff2de98d2b4bd9c2542e2612eaf72cce8be231364d8a8c846627d5ef75f74e34" +
        "fedad64d03e77e5ba2ae348d9253dcb3a4e71655d59243564f25c0ee3c724cd3c213f668db9733a7" +
        "c11863255e00d64ce3ae057a4d7875bb4c795205405b09957a2f12be5003745123bf563dc289ecbe" +
        "369a214a4ccbd418167e5beffa053a050132165aaeaa99263ca56e9dc1d870eb7fa6b317d85ef3e6" +
        "a2361ba1b640c1a68b6a40f23861b4575fe39758c5789fb3f62dc15855410dce1295624f5e5377c7" +
        "69c6a9c20096e48ea4cfa334c98bb009318749a66e52176474d21b6b278058ec18aa96df17c9e355" +
        "af39980f655eb33ed21d4657f3b9b0563a605d7975dcd866a61421e03ad83977f87ce7f29dac4e5b" +
        "e94794d5a1a14a6f3dbcbda32332bb6dc85ab2280c27eaebbc483fd4b0c1276600e9d41548069096" +
        "d91c55a04282d435b0f17f7506551b5a15d0e87cd3b0e098c78692c798a6102367b4f7efb352d317" +
        "e770b5ddbcb85c27fbc1a27fe7de3ecb4ab3e377103500ac2c17b9b74e68b1de73676b0f495909c0" +
        "08c9eb303ff882b348ca767f88274d192a324a5a500abe57b0c8093867b197947bc2ec319becae84" +
        "669edf908aa848c57181946107e8dc01babb1626d59967d280da7045cd9a6c1cd87991852fc9d664" +
        "03b216b616732ff11735969a1ec22af8f5c449d93ffdd2b3db11fbd02b82f993adab371da735eef0" +
        "d0ae62b2359e71a709222cbb07b08f9a27e71d80fba23fc2b6d96888e6aabac3907259474213b8ea" +
        "3384be2c461498ad7df615263c23c34c01e1c13fcf5345c384017f528374a7665842dc185b9f4261" +
        "0947b468b085823ce21da781b931230910af6874857079aa85cb7f92002eef13bc4c76d9212c30b2" +
        "e40df4f717a3cb9ca83538103ef3cf130378f040deab07b87e3ce145af7be1a8becf9cdae13951f1" +
        "3aecf76fedba0f29b5f0dd04654a1cae30bafb647b9f5fa41a23abe5efc46419c2960013592c23bc" +
        "d6be12acfc6dca8a1bf86fe488f8dea4f075744aa6b412c843f94f033dfd2f4db70dbd8356164e6b" +
        "2e8a1e115e57294702cbbd0f8a6f4cb9d89e7bac6fc66343a9288dfabc51c1c360e85b25ac2cdd05" +
        "8e88f6ce483e0e7ad7afe360af2c98939fdc520b699735925b3d0e92bdf2662d4b61284af8ea2e92" +
        "c2a37f8f943b5542cf95a2dd82cd569c5976dd97a758f894b56d85f068392ecee1bfa62599d5384f" +
        "a251e45a7184adef28d2e1db43b21436bc034c1eec619a9e97b0c8ca5225dae09c13357a31f034a6" +
        "49961306aca53b9d77fdbef0cff122b5063a1ee63300123d6673544ebb6d23371eb276524eebf317" +
        "51e865084cff38a005a597fb60814f00e668f6cc6d339ecbea7198aeee2b8a4e27c281c174eb3d23" +
        "4f0fdfbb96a2135544db2f8a43d4ff4ec25b859f3a68bf5b4fa8cab825c6e50f27844be7a00e7d77" +
        "43bfb92af909f6a067ad5576602c4de4a4b2a6115c9d965f63b5327a9cb4a53a46de8308f22377d6" +
        "9f1102746928aa521ed575b57539841e85eb225af0e6c3451d421311b3e6628ae3aca182fe605ec3" +
        "09bc32ca7143cb905907310587271aaacd7ba41645b633ce3a98ed49890396d50b66ab0e8ba8e6c7" +
        "6936033b36d85f072b311823d79217979167a35818b505355760fb88d113c2c9df56766dc9d9ffb8" +
        "d49c0ecafaa4f32a26390f38123c50122398cb99cf174e3df1146c2f5fd09061a53f891bfe73f0a7" +
        "fae2ba551f848e8ab64671ba2aab3ea91b93fa59d8790c8d3e92f917e9409a0d29c54b8741fc0e56" +
        "f652a3e486380fa534d5e76eed3afbf297868204d981ec92fbd77bb4809ddbe532a435f0a7be4564" +
        "cadb9c3058103c348e86d37a2f84e4211b5ddda45c11ad016db8f4b2b1e2809f57eae638c20229e3" +
        "7f69f40c797a7b41b6fbc36ba58f03d6b0ef8eadd75c40180ef45c9a53f59c88f1691f2b87fddaca" +
        "30c3f5b1072462de6685f382fec416de7a671d4cb70ab804c703227e67d52ed5602012a1135ce795" +
        "b91311d8bb55feb56dd54aff790374f21e33fa5647a6928da012bfe6cf9982ccc334ada987f52fe1" +
        "18a5b06c22d1438b47fbed55716f256729ad8cb4c54e570702e119b681cacf57d77627c0526c2f8d" +
        "0e5cb34066f2a554e28b1b3d830099dcfab22890419e772339d58e2921c72b99a1c69b479acd7314" +
        "0994f00180731a33fa572539c05a27b8019d1bee1933487905fb0341150c237c8d75a132c3b10d2a" +
        "5f5d532d7ef2673a8153eb1fe169c36b58c9fd74086c6e4a595e26f875370dbe0da4714813d81c02" +
        "baab7b6b42b8516ae0d741038dea4ba756ecf7a6ab62d13c72fdf36b9f76f24735f46b6ad341878f" +
        "be3dcfa7e6499ed3b2e17cbd8fa14befa79f65891ee05de8637e12bef43b5c73f1859c81c01a9f4c" +
        "f6b55d9b916999a8f0a272e11b3da31fe191c15457e2c6ca49d3ad506f10f77eeee2c3c743dc7625" +
        "358ad07384c117f0a80667388fc820e0b0d93511aec327fee7f1ee28982b2b51f20a1311d67c99df" +
        "dbcc46b033c55aa0779a426e684586320bb09bafcabc0da039094f10a42ce253133fd6cb782c5413" +
        "d3c19d30512cb168fc28872938cec287eb14aedf57d428d901d98f4ef6db81db0071ef665b83058e" +
        "d4c0c46c37c98fbf2342f41da93cecc22fbf06666d16fa309d5370b99617956fdc5e8e32c61bef7b" +
        "7c636cc884e66cc907981b85a699761b9add402d52fa314bb9157e7e07186d37c5402af4a170ea79" +
        "3d38c391329189fa40bc726fe0c8a9a1361d0160d1455e00982de6c55d4b7c95b5b4100a5252950e" +
        "994e6a5db5520520a66e1fe8dc977d720e545685c244caf722679c0f2e60087bf1d3df17d74ed821" +
        "4b3f824cc0a4947ff97415c24b29d1d935140cfc7e983745460448bbed263050bc6e09209f6187db" +
        "24858ba8d1a7330b4249cfa9ba649449de7e270fafbd4426d5bf9ffacb22e4df153fa98dda7ed6b0" +
        "b059e7074c0678f66cdd254c1733cd3c786d3fab48914ad3003dfe1b6d4c96b313c167297cf86c57" +
        "20488ba941ce023d0a8449dbe89cd5e9caf7ecb62de2870809892e1d0478e6cc3ecb268e48b7c387" +
        "c843ac7dafd7c301375c45cc2f9a765b2951bcaa66fc9b430cbf2e8f1c297a0c3aea35e6c2827d3f" +
        "cc1d1d4f486135a4f5a221baed3387598dd61e10e924803e7ab7d8da52f891e848fc28487f41490f" +
        "0a49c9acae56e925dc7abd3fbdbb91401c25d28b0de96b5fa32637204dedda34f89e88e3d135a8d5" +
        "bee03427b5166d5554693615ed9a1f3a3f42c98416bbd3cb21827cbe7bad4c6e59cc6b234126a0de" +
        "f837881d0860759357f07090d6a0db594e5bfba2f728f797831392974faaa6133a25e59b2e243f21" +
        "0633877459f735aae577f88dcafb16467597e435a1c511034f7d53a2bd05da5701155d10dc0f8d8c" +
        "a021b4e0c26415f15cfc1ba8ab4914c6145a96bbe33438e59af012fd6697fc90ec9fad3b3344f612" +
        "d57d8c34536510b78a4af5ed0b375816d6f3ac1890dd4076ce71dfe48310e641bec96f114443aeef" +
        "0f0d258b16a3d381a0809f3de016db9fbb8c3a8151fcc93cab9827778b70d7d471709583d4e9fbe2" +
        "6f5aefb76c87948843377fe35b75b0d0fd19a3e78de3809fe3e6de8feaa5bc54f81f0ae1ccccf44f" +
        "b2479a7475dd91a5953924bda9b968ced3666c63a1b109dcf20a88a308400ef0ec7d32e7b4a0d7e0" +
        "31cd49cc6790a8e0ed7d885646da0bb8d6b5357c1a921b29c2b1a58491a6acec29f2b492863b2a1b" +
        "c34eb8d64b6d5b6c53efe5c28ce7b027694909dada39acadc752cbe8d2ef0d7583165cc71d1db0d9" +
        "f24d67eddf13bf6194ac6f8f1f17a78dddee49bc028d5479ba6a8e22b036f2243a407417111e3c6f" +
        "ac7a8dd51548689bf38b043b637dc4476d9a1056ba5caa3dada8a4b400c2082bf4eb05cd49f174fd" +
        "29225955aee685aa5a646f8ff0f9617db7c7d7325778d3ea21325b65cbeaf9146d88c5f1758295a9" +
        "0000000000000000000000000000000000000000000000060b10171c20";
    byte[] mlDsa65Signature = check signMlDsa65(payload, privateKey);
    test:assertEquals(mlDsa65Signature.toBase16(), expectedMlDsa65Signature);
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
isolated function testSignMlDsa65WithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey privateKey = {algorithm:"DILITHIUM3"};
    byte[]|Error result = signMlDsa65(payload, privateKey);
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
isolated function testVerifySha256withEcdsa() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: EC_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeEcPrivateKeyFromKeyStore(keyStore, "ec-keypair", "ballerina");
    PublicKey publicKey = check decodeEcPublicKeyFromTrustStore(keyStore, "ec-keypair");
    byte[] sha256withEcdsaSignature = check signSha256withEcdsa(payload, privateKey);
    test:assertTrue(check verifySha256withEcdsaSignature(payload, sha256withEcdsaSignature, publicKey));
}

@test:Config {}
isolated function testVerifyMlDsa65() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: MLDSA_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeMlDsa65PrivateKeyFromKeyStore(keyStore, "mldsa-keypair", "ballerina");
    PublicKey publicKey = check decodeMlDsa65PublicKeyFromTrustStore(keyStore, "mldsa-keypair");
    byte[] mlDsa65Signature = check signMlDsa65(payload, privateKey);
    test:assertTrue(check verifyMlDsa65Signature(payload, mlDsa65Signature, publicKey));
}

@test:Config {}
isolated function testDecodeRsaPrivateKeyError() returns Error? {
    KeyStore keyStore = {
        path: EC_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error privateKey = decodeRsaPrivateKeyFromKeyStore(keyStore, "ec-keypair", "ballerina");
    if privateKey is Error {
        test:assertEquals(privateKey.message(), "Not a valid RSA key");
    } else {
        test:assertFail("Expected error not found");
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
        test:assertEquals(privateKey.message(), "Not a valid EC key");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testDecodeMlDsa65PrivateKeyError() returns Error? {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error privateKey = decodeMlDsa65PrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    if privateKey is Error {
        test:assertEquals(privateKey.message(), "Not a valid ML-DSA-65 key");
    } else {
        test:assertFail("Expected error not found");
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
        test:assertEquals(publicKey.message(), "Not a valid EC public key");
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
        test:assertEquals(publicKey.message(), "Not a valid RSA public key");
    } else {
        test:assertFail("Expected error not found");
    }
}

@test:Config {}
isolated function testDecodeMlDsa65PublicKeyError() returns Error? {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey|Error publicKey = decodeMlDsa65PublicKeyFromTrustStore(keyStore, "ballerina");
    if publicKey is Error {
        test:assertEquals(publicKey.message(), "Not a valid ML-DSA-65 public key");
    } else {
        test:assertFail("Expected error not found");
    }
}
