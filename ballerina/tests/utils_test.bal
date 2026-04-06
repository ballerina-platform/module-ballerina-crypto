// Copyright (c) 2026 WSO2 LLC. (http://www.wso2.com)
//
// WSO2 LLC. licenses this file to you under the Apache License,
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
import ballerina/time;

const int TIMING_ITERATIONS = 5000;
const int TIMING_WARMUP = 500;
const decimal TIMING_RATIO_THRESHOLD = 0.15d;
const decimal TIMING_ABS_THRESHOLD_MS = 3d;

function makeLargeArray(int size) returns byte[] {
    byte[] arr = [];
    foreach int i in 0 ..< size {
        arr.push(<byte>(i % 256));
    }
    return arr;
}

function makeLargeString(int size) returns string {
    string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    string result = "";
    foreach int i in 0 ..< size {
        result += chars[i % chars.length()];
    }
    return result;
}

@test:BeforeGroups {value: ["timing"]}
function timingWarmup() {
    byte[] a = "warmup-alpha".toBytes();
    byte[] b = "warmup-alpha".toBytes();
    byte[] c = "warmup-XXXXX".toBytes();
    foreach int i in 0 ..< TIMING_WARMUP {
        _ = equalConstantTime(a, b);
        _ = equalConstantTime(a, c);
    }
    // Warm up the large-array code path so the JIT compiles it before measurements begin.
    byte[] large = makeLargeArray(100000);
    byte[] largeDiff = large.clone();
    largeDiff[0] = largeDiff[0] == 0 ? 1 : 0;
    foreach int i in 0 ..< TIMING_WARMUP {
        _ = equalConstantTime(large, large.clone());
        _ = equalConstantTime(large, largeDiff);
    }
}

function timeBothByteInterleaved(byte[] base, byte[] altA, byte[] altB) returns [decimal, decimal] {
    decimal totalA = 0d;
    decimal totalB = 0d;
    foreach int i in 0 ..< TIMING_ITERATIONS {
        decimal t1 = time:monotonicNow();
        _ = equalConstantTime(base, altA);
        totalA += time:monotonicNow() - t1;
        decimal t2 = time:monotonicNow();
        _ = equalConstantTime(base, altB);
        totalB += time:monotonicNow() - t2;
    }
    return [totalA, totalB];
}

function timeBothStringInterleaved(string base, string altA, string altB) returns [decimal, decimal] {
    decimal totalA = 0d;
    decimal totalB = 0d;
    foreach int i in 0 ..< TIMING_ITERATIONS {
        decimal t1 = time:monotonicNow();
        _ = equalConstantTime(base, altA);
        totalA += time:monotonicNow() - t1;
        decimal t2 = time:monotonicNow();
        _ = equalConstantTime(base, altB);
        totalB += time:monotonicNow() - t2;
    }
    return [totalA, totalB];
}

function isSuspiciousTiming(decimal t1, decimal t2) returns boolean {
    decimal diff = t1 > t2 ? t1 - t2 : t2 - t1;
    decimal larger = t1 > t2 ? t1 : t2;
    test:assertTrue(t1 != 0d, "Timing value t1 must not be zero");
    test:assertTrue(t2 != 0d, "Timing value t2 must not be zero");
    decimal ratio = diff / larger;
    decimal diffMs = diff * 1000d;
    return ratio > TIMING_RATIO_THRESHOLD && diffMs > TIMING_ABS_THRESHOLD_MS;
}

@test:Config {groups: ["timing"]}
function testEqualConstantTimeTimingDifferAtStartVsEnd() {
    byte[] base = makeLargeArray(100000);
    byte[] differAtStart = base.clone();
    byte[] differAtEnd = base.clone();
    differAtStart[0] = differAtStart[0] == 0 ? 1 : 0;
    differAtEnd[differAtEnd.length() - 1] = differAtEnd[differAtEnd.length() - 1] == 0 ? 1 : 0;

    // Pre-warm with the actual test arrays.
    foreach int i in 0 ..< TIMING_WARMUP {
        _ = equalConstantTime(base, differAtStart);
        _ = equalConstantTime(base, differAtEnd);
    }

    [decimal, decimal] [tStart, tEnd] = timeBothByteInterleaved(base, differAtStart, differAtEnd);

    test:assertFalse(
        isSuspiciousTiming(tStart, tEnd),
        "Timing gap detected: differ-at-start took " + (tStart * 1000d).toString()
            + "ms vs differ-at-end " + (tEnd * 1000d).toString() + "ms over "
            + TIMING_ITERATIONS.toString() + " iterations"
    );
}

@test:Config {groups: ["timing"], "description": "Verifies match and mismatch at the midpoint take the same time (no early exit on equality)."}
function testEqualConstantTimeTimingMatchVsMismatch() {
    byte[] base = makeLargeArray(100000);
    byte[] matching = base.clone();
    byte[] mismatch = base.clone();
    int mid = base.length() / 2;
    mismatch[mid] = mismatch[mid] == 0 ? 1 : 0;

    // Pre-warm with the actual test arrays.
    foreach int i in 0 ..< TIMING_WARMUP {
        _ = equalConstantTime(base, matching);
        _ = equalConstantTime(base, mismatch);
    }

    [decimal, decimal] [tMatch, tMismatch] = timeBothByteInterleaved(base, matching, mismatch);

    test:assertFalse(
        isSuspiciousTiming(tMatch, tMismatch),
        "Timing gap detected: match took " + (tMatch * 1000d).toString()
            + "ms vs mismatch " + (tMismatch * 1000d).toString() + "ms over "
            + TIMING_ITERATIONS.toString() + " iterations"
    );
}

@test:Config {groups: ["timing"], "description": "Verifies the same constant-time property holds when inputs are strings."}
function testEqualConstantTimeTimingStrings() {
    string base = makeLargeString(100000);
    string differAtStart = "X" + base.substring(1);
    string differAtEnd = base.substring(0, base.length() - 1) + "X";

    // Pre-warm with the actual test strings.
    foreach int i in 0 ..< TIMING_WARMUP {
        _ = equalConstantTime(base, differAtStart);
        _ = equalConstantTime(base, differAtEnd);
    }

    [decimal, decimal] [tStart, tEnd] = timeBothStringInterleaved(base, differAtStart, differAtEnd);

    test:assertFalse(
        isSuspiciousTiming(tStart, tEnd),
        "Timing gap detected: string differ-at-start took " + (tStart * 1000d).toString()
            + "ms vs differ-at-end " + (tEnd * 1000d).toString() + "ms over "
            + TIMING_ITERATIONS.toString() + " iterations"
    );
}

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
    if value is error {
        test:assertFail("hmacSha256 failed for 'value': " + value.message());
    } else if expectedValue is error {
        test:assertFail("hmacSha256 failed for 'expectedValue': " + expectedValue.message());
    } else {
        test:assertTrue(equalConstantTime(value, expectedValue));
    }
}

@test:Config {}
isolated function testEqualConstantTimeWithHmacHexStrings() {
    byte[] input = "Hello Ballerina".toBytes();
    byte[] key = "secret".toBytes();
    byte[]|error hmac = hmacSha256(input, key);
    if hmac is error {
        test:assertFail("hmacSha256 failed: " + hmac.message());
    } else {
        string value = string `sha256=${hmac.toBase16()}`;
        string expectedValue = string `sha256=${hmac.toBase16()}`;
        test:assertTrue(equalConstantTime(value, expectedValue));
    }
}
