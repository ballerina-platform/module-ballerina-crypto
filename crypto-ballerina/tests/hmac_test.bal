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
isolated function testHmacMd5() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[] key = "abcdefghijk".toBytes();
    string expectedMd5Hash = "3D5AC29160F2905A5C8153597798A4C1".toLowerAscii();
    byte[]|Error hmac = hmacMd5(message, key);
    test:assertTrue(hmac is byte[]);
    test:assertEquals((checkpanic hmac).toBase16(), expectedMd5Hash, msg = "Error while HMAC with MD5.");
}

@test:Config {}
isolated function testHmacSha1() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[] key = "abcdefghijk".toBytes();
    string expectedSha1Hash = "13DD8D54D0EB702EDC6E8EDCAF616837D3A51499".toLowerAscii();
    byte[]|Error hmac = hmacSha1(message, key);
    test:assertTrue(hmac is byte[]);
    test:assertEquals((checkpanic hmac).toBase16(), expectedSha1Hash, msg = "Error while HMAC with SHA1.");
}

@test:Config {}
isolated function testHmacSha256() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[] key = "abcdefghijk".toBytes();
    string expectedSha256Hash = "2651203E18BF0088D3EF1215022D147E2534FD4BAD5689C9E5F12436E9758B15".toLowerAscii();
    byte[]|Error hmac = hmacSha256(message, key);
    test:assertTrue(hmac is byte[]);
    test:assertEquals((checkpanic hmac).toBase16(), expectedSha256Hash, msg = "Error while HMAC with SHA256.");
}

@test:Config {}
isolated function testHmacSha384() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[] key = "abcdefghijk".toBytes();
    string expectedSha384Hash = ("c27a281dffed3d4d176646d7261e9f6268a3d40a237cd274fc2f5970f637f1c" +
        "bc20a3835d7b7aa7401308737f23a9bf7").toLowerAscii();
    byte[]|Error hmac = hmacSha384(message, key);
    test:assertTrue(hmac is byte[]);
    test:assertEquals((checkpanic hmac).toBase16(), expectedSha384Hash, msg = "Error while HMAC with SHA384.");
}

@test:Config {}
isolated function testHmacSha512() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[] key = "abcdefghijk".toBytes();
    string expectedSha512Hash = ("78d99bf3e5277fc893af6cd6b0487c33ed3abc4f956fdd1fada302f135b012a" +
        "3c71cadaaeb462e51ff281202bdfa8807719b91f69742c3f71f036c469ac5b918").toLowerAscii();
    byte[]|Error hmac = hmacSha512(message, key);
    test:assertTrue(hmac is byte[]);
    test:assertEquals((checkpanic hmac).toBase16(), expectedSha512Hash, msg = "Error while HMAC with SHA512.");
}

@test:Config {}
isolated function testHmacMd5WithEmptyKey() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[]|Error hmac = hmacMd5(message, []);
    test:assertTrue(hmac is Error);
    test:assertEquals((<Error>hmac).message(), "Error occurred while calculating HMAC: Empty key");
}

@test:Config {}
isolated function testHmacSha1WithEmptyKey() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[]|Error hmac = hmacSha1(message, []);
    test:assertTrue(hmac is Error);
    test:assertEquals((<Error>hmac).message(), "Error occurred while calculating HMAC: Empty key");
}

@test:Config {}
isolated function testHmacSha256WithEmptyKey() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[]|Error hmac = hmacSha256(message, []);
    test:assertTrue(hmac is Error);
    test:assertEquals((<Error>hmac).message(), "Error occurred while calculating HMAC: Empty key");
}

@test:Config {}
isolated function testHmacSha384WithEmptyKey() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[]|Error hmac = hmacSha384(message, []);
    test:assertTrue(hmac is Error);
    test:assertEquals((<Error>hmac).message(), "Error occurred while calculating HMAC: Empty key");
}

@test:Config {}
isolated function testHmacSha512WithEmptyKey() {
    byte[] message = "Ballerina HMAC test".toBytes();
    byte[]|Error hmac = hmacSha512(message, []);
    test:assertTrue(hmac is Error);
    test:assertEquals((<Error>hmac).message(), "Error occurred while calculating HMAC: Empty key");
}
