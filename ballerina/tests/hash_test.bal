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
isolated function testHashCrc32() {
    byte[] input = "Ballerina test".toBytes();
    string expectedCrc32Hash = "d37b9692";
    test:assertEquals(crc32b(input), expectedCrc32Hash);
}

@test:Config {}
isolated function testHashMd5() {
    byte[] input = "Ballerina test".toBytes();
    string expectedMd5Hash = "3B12196DB784CD9F86CC635D32764FDF".toLowerAscii();
    test:assertEquals(hashMd5(input).toBase16(), expectedMd5Hash);
}

@test:Config {}
isolated function testHashSha1() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha1Hash = "73FBC15DB28D52C03359EDE7A7DC40B4A83DF207".toLowerAscii();
    test:assertEquals(hashSha1(input).toBase16(), expectedSha1Hash);
}

@test:Config {}
isolated function testHashSha256() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha256Hash =
        "68F6CA0B55B55099331BF4EAA659B8BDC94FBDCE2F54D94FD90DA8240797A5D7".toLowerAscii();
    test:assertEquals(hashSha256(input).toBase16(), expectedSha256Hash);
}

@test:Config {}
isolated function testHashSha384() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha384Hash = ("F00B4A8C67B38E7E32FF8B1AB570345743878F7ADED9B5FA02518DDD84E16CBC" +
        "A344AF42CB60A1FD5C48C5FEDCFF7F24").toLowerAscii();
    test:assertEquals(hashSha384(input).toBase16(), expectedSha384Hash);
}

@test:Config {}
isolated function testHashSha512() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha512Hash = ("1C9BED7C87E7D17BA07ADD67F59B4A29AFD2B046409B65429E77D0CEE53A33C5" +
        "E26731DC1CB091FAADA8C5D6433CB1544690804CC046A55D6AFED8BE0B901062").toLowerAscii();
    test:assertEquals(hashSha512(input).toBase16(), expectedSha512Hash);
}

@test:Config {}
isolated function testHashMd5WithSalt() {
    byte[] input = "Ballerina test".toBytes();
    byte[] salt = "s3cr3t".toBytes();
    string expectedMd5Hash = "6B8DC4929448297E9C9FBE5638CBF85E".toLowerAscii();
    test:assertEquals(hashMd5(input, salt).toBase16(), expectedMd5Hash);
}

@test:Config {}
isolated function testHashSha1WithSalt() {
    byte[] input = "Ballerina test".toBytes();
    byte[] salt = "s3cr3t".toBytes();
    string expectedSha1Hash = "3A5119055B9593CEC2463E03EDA41FCF7A770D1A".toLowerAscii();
    test:assertEquals(hashSha1(input, salt).toBase16(), expectedSha1Hash);
}

@test:Config {}
isolated function testHashSha256WithSalt() {
    byte[] input = "Ballerina test".toBytes();
    byte[] salt = "s3cr3t".toBytes();
    string expectedSha256Hash = "3E28D04139D80A125175A353729982B698B3B0044CD758E896B672A2D224373F".toLowerAscii();
    test:assertEquals(hashSha256(input, salt).toBase16(), expectedSha256Hash);
}

@test:Config {}
isolated function testHashSha384WithSalt() {
    byte[] input = "Ballerina test".toBytes();
    byte[] salt = "s3cr3t".toBytes();
    string expectedSha384Hash = ("D3DA4A915288D3E1A8748746E8B24DE38E40289DB6C8205AF14856BDDE2658E8" +
        "64440DDB5396E76C9D319E983A71FF0E").toLowerAscii();
    test:assertEquals(hashSha384(input, salt).toBase16(), expectedSha384Hash);
}

@test:Config {}
isolated function testHashSha512WithSalt() {
    byte[] input = "Ballerina test".toBytes();
    byte[] salt = "s3cr3t".toBytes();
    string expectedSha512Hash = ("7C67E0D9D453D0599B270D9DEE45910E971AD537D5B8BA06B347F1F82D2BE48F" +
        "5E78702995D181042420860B111781AFEE88ACD455CAA0367271C78DAE0F69DA").toLowerAscii();
    test:assertEquals(hashSha512(input, salt).toBase16(), expectedSha512Hash);
}

@test:Config {}
isolated function testHashKeccak256() {
    byte[] input = "Ballerina test".toBytes();
    string expectedKeccak256Hash =
        "73b6cc25ab0656625ee654a6cdc8f1d1803a6330fba4f4bf5bd6b9018f7d3131".toLowerAscii();
    test:assertEquals(hashKeccak256(input).toBase16(), expectedKeccak256Hash);
}
