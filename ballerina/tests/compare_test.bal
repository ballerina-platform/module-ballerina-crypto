// Copyright (c) 2026 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
isolated function testEqualConstantTimeMatchingByteArrays() {
    byte[] value = [1, 2, 3, 4, 5];
    byte[] expectedValue = [1, 2, 3, 4, 5];
    test:assertTrue(equalConstantTime(value, expectedValue));
}

@test:Config {}
isolated function testEqualConstantTimeDifferentByteArrays() {
    byte[] value = [1, 2, 3, 4, 5];
    byte[] expectedValue = [1, 2, 3, 4, 9];
    test:assertFalse(equalConstantTime(value, expectedValue));
}

@test:Config {}
isolated function testEqualConstantTimeDifferentLengths() {
    byte[] value = [1, 2, 3];
    byte[] expectedValue = [1, 2, 3, 4, 5];
    test:assertFalse(equalConstantTime(value, expectedValue));
}

@test:Config {}
isolated function testEqualConstantTimeEmptyByteArrays() {
    byte[] value = [];
    byte[] expectedValue = [];
    test:assertTrue(equalConstantTime(value, expectedValue));
}

@test:Config {}
isolated function testEqualConstantTimeMatchingStrings() {
    test:assertTrue(equalConstantTime(
        "sha256=abc123def456",
        "sha256=abc123def456"
    ));
}

@test:Config {}
isolated function testEqualConstantTimeDifferentStrings() {
    test:assertFalse(equalConstantTime(
        "sha256=abc123def456",
        "sha256=abc123def999"
    ));
}

@test:Config {}
isolated function testEqualConstantTimeEmptyStrings() {
    test:assertTrue(equalConstantTime("", ""));
}

@test:Config {}
isolated function testEqualConstantTimeMixedTypes() {
    byte[] value = "hello".toBytes();
    test:assertTrue(equalConstantTime(value, "hello"));
    test:assertTrue(equalConstantTime("hello", value));
    test:assertFalse(equalConstantTime(value, "world"));
    test:assertFalse(equalConstantTime("world", value));
}

@test:Config {}
isolated function testEqualConstantTimeWithHmacBytes() {
    byte[] input = "Hello Ballerina".toBytes();
    byte[] key = "secret".toBytes();
    byte[]|error value = hmacSha256(input, key);
    byte[]|error expectedValue = hmacSha256(input, key);
    if value is byte[] && expectedValue is byte[] {
        test:assertTrue(equalConstantTime(value, expectedValue));
    }
}

@test:Config {}
isolated function testEqualConstantTimeWithHmacHexStrings() {
    byte[] input = "Hello Ballerina".toBytes();
    byte[] key = "secret".toBytes();
    byte[]|error hmac = hmacSha256(input, key);
    if hmac is byte[] {
        string value = string `sha256=${hmac.toBase16()}`;
        string expectedValue = string `sha256=${hmac.toBase16()}`;
        test:assertTrue(equalConstantTime(value, expectedValue));
    }
}
