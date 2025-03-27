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

@test:Config {
    groups: ["non-fips"]
}
isolated function testSignMlDsa65() returns Error? {
    byte[] payload = "Ballerina test".toBytes();
    KeyStore keyStore = {
        path: MLDSA_KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey privateKey = check decodeMlDsa65PrivateKeyFromKeyStore(keyStore, "mldsa-keypair", "ballerina");
    string expectedMlDsa65Signature = "58b26469dfce2036f912ead5427a7e2f6a89ca2587a666e2d5df06e084f4964106c07d38a5dd42ba" +
        "7a4a5491b8f4699231bcf96ce02a06830c9cd0397136b95980db76d394b05dd907050b07f53fe0d2" +
        "bb6f99335bafbfe3ff71654feed835dd2eb9b427c2452feca25d4bce120aaf036de462ce87575b45" +
        "97b359793493dd9b7afb6fd6a7dbdf094eb4b143891e676d9ddb9c8d7edfa246da7afdacfcc62897" +
        "770b64e4c69d8d7365e80b2dc9a72708e842a94ccec5cf03cdd274a315f4ffb437e3a1e26e1ceb9f" +
        "ca3079bd99f57a5c09a651ccff8068ef14a6f8acfe42fa336a0b0f02c9a34c57861a7593fe54f416" +
        "c9b8c3b65c85883819486051ee571d03b58a282e7d080e69ecbfe434a261f5c0e262b532f0f9f2c5" +
        "05802d78ceaedfaa9f58a6f86e898fcdf9a8c6dd0a90a40337c22a5fa0cb72f99adc209373e7b9b1" +
        "0924928c515d3ef63a77250561c05901a51270be14134ae80c08ceb4c6a7c542f0094cc119b34469" +
        "9fc829c77cc455577d72d55fbd00e5a71095c99c269a5784cace8d8c8609177fe89a27d4f60f3ab4" +
        "845aa44bebdc09a443be6297bf75e70c2c6f77932f636cd3330990fff58b502dc22241c357b0b64a" +
        "415fabcd1c3dba90d8fbca783cebbdfdea4636b30515ea5a96265745322225e8551c83f56793005f" +
        "917f4cf970712b37825dfcb7eca564b108937774327340e8fb969678012bad4bba1b6c5856eb9396" +
        "f682556b6e5b2a0561d8bca38c3397b8cbdc11353ab861396daa20a19fd900c311e31c43d743ed5f" +
        "db4ece61fe4dd0efc3bbeb791358a0dd557dcbbe39630a332e30375728884a63090ac93eee37257d" +
        "ffdb35a85ca27ad6310543554659a51db86148bb00bd9768e741b7c958d82d2e2e851de27098913c" +
        "19009af53f1dfff8d6cdbc76c5ce79d0743ff3e8651cdd625a804356588cc2d1a0aef5e2cb487291" +
        "731096875339f1bf56b1dbea69bf59c6ea3788ba5fcf5bfa2c59117771de6b2515d91acd49c50bfe" +
        "9cc55a92910d83e1fc6c0d52805e29f1eef204e3fcb167ecf4ce4e844bad40237575cf1cc6eaceb8" +
        "472f7f146f25f8f0c6c63d5f0e3f598ec5e496bb6c99b72dcfdc4ef43b19e50f096825efdbcca63e" +
        "9a5e399a7b9ed8ea6082341e4f4ee9cc969da55681c07ce755b6acef871b98e175d7a26d1aff6542" +
        "e86c743c519ae33693f4345c8c3c6091681bb1a097ce188e2bd45b470310d86f63b7907254d7a59c" +
        "0b3677e32f6d8b7b28562208fa64db7e94deac9518d7add88b69d209ad8d53691a6fa326fbbb1c05" +
        "544e6b6f3dd3877ff0bac23c64c8f37029ebaea1ea5dbc634d3a0aa8be55329c1e92bca3d23b6b30" +
        "3a3707a4c34b964545474060a1ae6591962cdaa5d6a8aac7f4ccb8ff9eede46d43fa253296e1fb0c" +
        "ff0b7410c8b357d689cb7fcce644bda4fac794abc1661504e6e58671a4e9cc81d9c081cb1e63358c" +
        "726bc832e8554c5beb816f51378c9729cc7862055f6a18f86ab691138f3e9e81b0689e02bc73c685" +
        "3e6641e3408b8546ef608105af9c7a721494ab9ce44631c1057fb1a17d1566b3d14701e99c74c4e1" +
        "532464bc679456bc1e1f5ab488f23a083aa8b41035d735b579351e71a97c0cd4ed40166c0aaffe0c" +
        "8e52bf4b472818255f3791ce1ed9d9397924960f88e026ca400f9a7697c0bb82c58c41c02aec9798" +
        "ebbbd902ee3aa3caf46b9a5dd9427ebdeb590662b63e3147b81044eaf5998b61e6782ddbb8427448" +
        "107eef3e0ef9c19d96abcd528288d593b1a54e738a83c95c7a02b1ce12f4f643b259f3074931b0e2" +
        "209be01d93347cb1eb6dd5317ae4ff7c33dc58853288f47a54e277b67e44178ca91015a7568ac6e6" +
        "4e72cfbcc4158cd45f8db9034ec8173d61877fd17decbcc85c568af770d1423a72e47e168465ba43" +
        "3d7fc8248a7321b128e2163aae20966ab92fdbc9bd4a72036594982969f827b30aca3666d94ab973" +
        "89bf44a179a0677a1f800790f8f069c1683d0fa0e6dbb7e6a2f27aa032500e8247429fea546d4e22" +
        "15d9f45ca7370c675d8a38750f8f069e4a673ad99ae2281642645b69d33de2027d99a31f7e80f2c9" +
        "a46f91f70fc17dd75262fb388447aee84b375347fb536222f19f3a1d4b1443f183c59d8bfe7057d9" +
        "70c915c14de6b9f34b22d9ee792185e5e37e73b2e23cb250411cb9c98c6aebb6a62251e39b9bf8bf" +
        "f3b608b3bc4a182b780198e7aa2075fbd8a0cbf5f0357848c59f776ef4da5784996c0f31e19e85b7" +
        "8db493b7877a5fe4808956ea52b06e2aab925532e8e1b3a8570e4b85db6d327b57b37ddc810161a0" +
        "f2e51b75f92be67efb8e789880a824ca3aec0a8431f3c0fef4b35c1bc86350396f822c32030c15b1" +
        "b70096feef73ce304a8ec06f7e533dd32d5b1ce916d941c364ef12c05d7553e3e519f3228c676aee" +
        "705244be403eafc169e181da990079ab19828fd193656802df54c5a2aac2e4959eae25db97e65c31" +
        "ea7e166800cd1b34bd72ab914e3fb28c29c6bb5925b019807d92acf35240df355470023ef9864482" +
        "05f46511acdc6fadfb9f0af05b1061bb27f85f2db6b6b3c78e346078ade7bb3ed5063f7c3504d73c" +
        "3d2b668b853f148dd88d8f6f590627d1981921fb58b617d1e5f1204adaa5701495931df0721aa0fb" +
        "c51c529dbcdf6f066c1d2e5855a6f0af0ed148cda1d231aa2f55f1c508721bd1881c5602d6648348" +
        "47b9def1b914441b7a05c0e3ded83e17cdcfe436a0e7fb98c2d00e25f5174111c5aa7c5f509e0be3" +
        "28aab62fb93eed0068b37a7d5d9e245a606d837daf1008ab7168d1ac3ff74a607389f13c288db1d6" +
        "0aab84ffd395809e4df53cf82cc92bf1029eb945831ca09e2c7757c019194759760e9a136e68a6bd" +
        "00e65e49375099c1340a034f0318766a541786313acef6aab4c2715f4efb67ee4dc823226a0dbca0" +
        "ae4d3377dd7e5f09a8656f9f7af7f84356b1480e7619fe164e2ab759cee35d62456437a22a8aba3d" +
        "584bb6fcf2898dcafe015430775c9eba3662ff2f0a5faf477cf66f3bba92c5407ba7014a223739d2" +
        "780a275f62b17529fec5c0cca5f9b8a256e3fd62bf83ca247cef46f8ae08add8f8c443398e047991" +
        "d07ca267983ccacbce84a4a6dc444388ad8b45b412816c5a974f3072b3a8a597af07a0c333b694a4" +
        "2d56a6a8cf22918ba56b5ca4ec610c9955ba1a0b1253dedca917945d7d13f42e2d3363a4bf2d5a1d" +
        "450858327444534bad19dc1ff7a37acf41efe0db53a94971c74b7bd97ee04ab440ed0ec9c95a5e55" +
        "66a4443542d4357de5affdbd0f6a79db99d037fd55a17913ebdf5bda51d143693b678ec7c9ea48e6" +
        "257dc326d2126012dda898dc13cd42b8edfed4a9616e316dc83f04f01eb85d217ca0ac0f61a151b2" +
        "ea93bdd75c0ff2b93383ec4264a5c4b6b98689ff6a3993274eaaf8c93cacc8c724a05b9d1d84869f" +
        "810a57b8c768e89fc5ab16d5de023bff249b5d0a2ad0b0f89116244bb4dc508fee4ba76aac779156" +
        "cba003ee8a02cfcc6dafa99461d4a06385eda4a4df5f0bab5203affb27726f64cdeaa68019a94262" +
        "770a2c5a53507bdc643556e7b2f3f4f62c9497f9cf3bc76c443d653f74ddb60832e363ea94ff1a68" +
        "2aa4f26f02404958cb2cf417d0db3709948d10512613cc3f29b7b27c420613253b3a6e31bda11437" +
        "671928c2e0d8fa0013dc5dc86803e9d71adef4786e86e69cb6df892a9a7cc44efe2007b6bde4bfe8" +
        "bbe73d7af013f6387a3de8bc5e0214ae4754cd71b5302bf71a8d7bbce6ad6b404d3c81e306f1294d" +
        "c9bb74040e4cf4c9931dc7e082c63c959caadec37713f573fa2b56277b943616e121b60c6322aa02" +
        "a6bfff0275e77691a4b170a58b244087349c107034ee665e8d44b8664edc4d00929ecf08fc9275b5" +
        "adfae5d344ec6981e1dab46d1dfe629da67cb953a808763e9d9043c3ff5a6c1e18c4358435edf800" +
        "51f6140a4dcf746e77a196ff1245bfbb2c4fc5251551e10cc402db29c795991150a12ce439397c38" +
        "854cb38c6133e08dd05383f0f1c9dcf86126b5953789587ccdbc5cb3044a7faf851822816c7a3b20" +
        "9246f77b9603a75e86435de10f09ce1f1579eefac4b3dd5354c6e5127b9a69ae40b4829bab4b4a46" +
        "f23e6fcf56e6d807c6acfc8fd0a7bdfd2801036fef985f0dbb38f74e072108f0014d12357bdb56ae" +
        "d64e75d4f4b2e11d823bddce77321c740f8e210638c78c1dc64be9db3910eb8f4fe5835d277d84e4" +
        "897d4be4727786cb078a340a2e0829a04e175f5270e586bdcad18db0bc0d755aaefdaa765d2a01cf" +
        "62a451ac6d19ca336363d99463438cddf41c14aaf16d80354580688d3965f86f24cde13e02e2c9aa" +
        "424c054a2fcf4d7c5f0f1972aa6db5146a3fcef060d380f60de6a42c2b90201d3adfb0d2ca151b9a" +
        "c6487a0ce3aa83eadb1c6076c44c45efcc4e77f6ba4b7ca03652dbb045307efc846ec8886656a227" +
        "4b9e800a022d0a1e92ab425cf090313fce4a1559e7f88e1266cd95f9742994c89d147508e4ef7e36" +
        "c3e170c84cb2d7cd2a22bad98e967d2a80afe88861a2297eb485f817805d18da3edf5a9a7113be15" +
        "004d2f6551146b741d4f7492d8ea3684cdf42b3c7d9caeb7ce6c8ba9d7e2009d9fb5cd1c42455772" +
        "a2a4b1bdc6000000000000000000000000000000000000060a11161b25";
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

@test:Config {
    groups: ["non-fips"]
}
isolated function testSignMlDsa65WithInvalidKey() {
    byte[] payload = "Ballerina test".toBytes();
    PrivateKey privateKey = {algorithm: "ML-DSA-65"};
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

@test:Config {
    groups: ["non-fips"]
}
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
isolated function testDecodeMlKem768PrivateKeyError() returns Error? {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PrivateKey|Error privateKey = decodeMlKem768PrivateKeyFromKeyStore(keyStore, "ballerina", "ballerina");
    if privateKey is Error {
        test:assertEquals(privateKey.message(), "Not a valid ML-KEM-768 key");
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

@test:Config {}
isolated function testDecodeMlKem768PublicKeyError() returns Error? {
    KeyStore keyStore = {
        path: KEYSTORE_PATH,
        password: "ballerina"
    };
    PublicKey|Error publicKey = decodeMlKem768PublicKeyFromTrustStore(keyStore, "ballerina");
    if publicKey is Error {
        test:assertEquals(publicKey.message(), "Not a valid ML-KEM-768 public key");
    } else {
        test:assertFail("Expected error not found");
    }
}
