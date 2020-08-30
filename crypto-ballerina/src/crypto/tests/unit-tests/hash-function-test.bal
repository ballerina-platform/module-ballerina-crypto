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
function testHashMd5() {
    byte[] input = "Ballerina test".toBytes();
    string expectedMd5Hash = "3B12196DB784CD9F86CC635D32764FDF".toLowerAscii();
    test:assertEquals(crc32b(input), "d37b9692", msg = "Error while Hash with CRC32b.");
}

@test:Config {}
function testHashSha1() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha1Hash = "73FBC15DB28D52C03359EDE7A7DC40B4A83DF207".toLowerAscii();
    test:assertEquals(hashSha1(input).toBase16(), expectedSha1Hash, msg = "Error while Hash with SHA1.");
}

@test:Config {}
function testHashSha256() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha256Hash =
        "68F6CA0B55B55099331BF4EAA659B8BDC94FBDCE2F54D94FD90DA8240797A5D7".toLowerAscii();
    test:assertEquals(hashSha256(input).toBase16(), expectedSha256Hash, msg = "Error while Hash with SHA256.");
}

@test:Config {}
function testHashSha384() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha384Hash = ("F00B4A8C67B38E7E32FF8B1AB570345743878F7ADED9B5FA02518DDD84E16CBC" +
        "A344AF42CB60A1FD5C48C5FEDCFF7F24").toLowerAscii();
    test:assertEquals(hashSha384(input).toBase16(), expectedSha384Hash, msg = "Error while Hash with SHA384.");
}

@test:Config {}
function testHashSha512() {
    byte[] input = "Ballerina test".toBytes();
    string expectedSha512Hash = ("1C9BED7C87E7D17BA07ADD67F59B4A29AFD2B046409B65429E77D0CEE53A33C5" +
        "E26731DC1CB091FAADA8C5D6433CB1544690804CC046A55D6AFED8BE0B901062").toLowerAscii();
    test:assertEquals(hashSha512(input).toBase16(), expectedSha512Hash, msg = "Error while Hash with SHA512.");
}
