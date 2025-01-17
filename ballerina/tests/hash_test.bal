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

type ComplexPassword record {|
    string password;
|};

type InvalidArgon2Params record {|
    int iterations;
    int memory;
    int parallelism;
    string expectedError;
|};

type InvalidWorkFactor record {|
    int factor;
    string expectedError;
|};

type ValidPassword record {|
    string password;
|};

type PasswordPair record {|
    string correctPassword;
    string wrongPassword;
|};

type InvalidHash record {|
    string hash;
    string expectedError;
|};


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

// tests for Argon2
@test:Config {}
isolated function testHashPasswordArgon2Default() returns error? {
    string password = "Ballerina@123";
    string hash = check hashArgon2(password);
    test:assertTrue(hash.startsWith("$argon2id$v=19$"));
    test:assertTrue(hash.length() > 50);
}

@test:Config {}
isolated function testHashPasswordArgon2Custom() returns error? {
    string password = "Ballerina@123";
    string hash = check hashArgon2(password, 4, 131072, 8);
    test:assertTrue(hash.includes("m=131072,t=4,p=8"));
    test:assertTrue(hash.length() > 50);
}

@test:Config {
    dataProvider: complexPasswordsDataProvider
}
isolated function testHashPasswordArgon2ComplexPasswords(ComplexPassword data) returns error? {
    string hash = check hashArgon2(data.password);
    test:assertTrue(hash.startsWith("$argon2id$v=19$"));
    boolean result = check verifyArgon2(data.password, hash);
    test:assertTrue(result, "Password verification failed for: " + data.password);
}

@test:Config {
    dataProvider: invalidArgon2ParamsDataProvider
}
isolated function testHashPasswordArgon2InvalidParams(InvalidArgon2Params data) {
    string password = "Ballerina@123";
    string|Error hash = hashArgon2(password, data.iterations, data.memory, data.parallelism);
    if hash !is Error {
        test:assertFail(string `Should fail with invalid parameters: iterations=${data.iterations}, memory=${data.memory}, parallelism=${data.parallelism}`);
    }
    test:assertEquals(hash.message(), data.expectedError);
}

@test:Config {
    dataProvider: validPasswordsDataProvider
}
isolated function testVerifyPasswordArgon2Success(ValidPassword data) returns error? {
    string hash = check hashArgon2(data.password);
    boolean result = check verifyArgon2(data.password, hash);
    test:assertTrue(result, "Password verification failed for: " + data.password);
}

@test:Config {
    dataProvider: wrongPasswordsDataProvider
}
isolated function testVerifyPasswordArgon2Failure(PasswordPair data) returns error? {
    string hash = check hashArgon2(data.correctPassword);
    boolean result = check verifyArgon2(data.wrongPassword, hash);
    test:assertFalse(result, "Should fail for wrong password: " + data.wrongPassword);
}

@test:Config {
    dataProvider: invalidArgon2HashesDataProvider
}
isolated function testVerifyPasswordArgon2InvalidHashFormat(InvalidHash data) {
    string password = "Ballerina@123";
    boolean|Error result = verifyArgon2(password, data.hash);
    if result !is Error {
        test:assertFail("Should fail with invalid hash: " + data.hash);
    }
    test:assertTrue(result.message().startsWith("Invalid Argon2 hash format"));
}

@test:Config {
    dataProvider: uniquenessPasswordsDataProvider
}
isolated function testArgon2PasswordHashUniqueness(ValidPassword data) returns error? {
    string hash1 = check hashArgon2(data.password);
    string hash2 = check hashArgon2(data.password);
    string hash3 = check hashArgon2(data.password);

    test:assertNotEquals(hash1, hash2, "Hashes should be unique for: " + data.password);
    test:assertNotEquals(hash2, hash3, "Hashes should be unique for: " + data.password);
    test:assertNotEquals(hash1, hash3, "Hashes should be unique for: " + data.password);

    boolean verify1 = check verifyArgon2(data.password, hash1);
    boolean verify2 = check verifyArgon2(data.password, hash2);
    boolean verify3 = check verifyArgon2(data.password, hash3);

    test:assertTrue(verify1 && verify2 && verify3,
            "All hashes should verify successfully for: " + data.password);
}

// tests for Bcrypt
@test:Config {}
isolated function testHashPasswordBcryptDefault() returns error? {
    string password = "Ballerina@123";
    string hash = check hashBcrypt(password);
    test:assertTrue(hash.startsWith("$2a$12$"));
    test:assertTrue(hash.length() > 50);
}

@test:Config {}
isolated function testHashPasswordBcryptCustomWorkFactor() returns error? {
    string password = "Ballerina@123";
    string hash = check hashBcrypt(password, 10);
    test:assertTrue(hash.startsWith("$2a$10$"));
    test:assertTrue(hash.length() > 50);
}

@test:Config {
    dataProvider: complexPasswordsDataProvider
}
isolated function testHashPasswordBcryptComplexPasswords(ComplexPassword data) returns error? {
    string hash = check hashBcrypt(data.password);
    test:assertTrue(hash.startsWith("$2a$12$"));
    test:assertTrue(hash.length() > 50);

    boolean result = check verifyBcrypt(data.password, hash);
    test:assertTrue(result, "Password verification failed for: " + data.password);
}

@test:Config {
    dataProvider: invalidBcryptWorkFactorsDataProvider
}
isolated function testHashPasswordBcryptInvalidWorkFactor(InvalidWorkFactor data) {
    string password = "Ballerina@123";
    string|Error hash = hashBcrypt(password, data.factor);
    if hash !is Error {
        test:assertFail(string `Should fail with invalid work factor: ${data.factor}`);
    }
    test:assertEquals(hash.message(), data.expectedError);
}

@test:Config {
    dataProvider: validPasswordsDataProvider
}
isolated function testVerifyPasswordBcryptSuccess(ValidPassword data) returns error? {
    string hash = check hashBcrypt(data.password);
    boolean result = check verifyBcrypt(data.password, hash);
    test:assertTrue(result, "Password verification failed for: " + data.password);
}

@test:Config {
    dataProvider: wrongPasswordsDataProvider
}
isolated function testVerifyPasswordBcryptFailure(PasswordPair data) returns error? {
    string hash = check hashBcrypt(data.correctPassword);
    boolean result = check verifyBcrypt(data.wrongPassword, hash);
    test:assertFalse(result, "Should fail for wrong password: " + data.wrongPassword);
}

@test:Config {
    dataProvider: invalidBcryptHashesDataProvider
}
isolated function testVerifyPasswordBcryptInvalidHashFormat(InvalidHash data) {
    string password = "Ballerina@123";
    boolean|Error result = verifyBcrypt(password, data.hash);
    if result !is Error {
        test:assertFail("Should fail with invalid hash: " + data.hash);
    }
    test:assertEquals(result.message(), data.expectedError);
}

@test:Config {
    dataProvider: uniquenessPasswordsDataProvider
}
isolated function testBcryptPasswordHashUniqueness(ValidPassword data) returns error? {
    string hash1 = check hashBcrypt(data.password);
    string hash2 = check hashBcrypt(data.password);
    string hash3 = check hashBcrypt(data.password);

    test:assertNotEquals(hash1, hash2, "Hashes should be unique for: " + data.password);
    test:assertNotEquals(hash2, hash3, "Hashes should be unique for: " + data.password);
    test:assertNotEquals(hash1, hash3, "Hashes should be unique for: " + data.password);

    boolean verify1 = check verifyBcrypt(data.password, hash1);
    boolean verify2 = check verifyBcrypt(data.password, hash2);
    boolean verify3 = check verifyBcrypt(data.password, hash3);

    test:assertTrue(verify1 && verify2 && verify3,
            "All hashes should verify successfully for: " + data.password);
}

// common tests for both algorithms
@test:Config {
    dataProvider: hashingAlgorithmsDataProvider
}
isolated function testEmptyPasswordError(string algorithm) returns error? {
    string password = "";
    string|Error hash = algorithm == "argon2" ? hashArgon2(password) : hashBcrypt(password);
    if hash !is Error {
        test:assertFail("Should fail with empty password");
    }
    test:assertEquals(hash.message(), "Password cannot be empty");
}

// data Providers for password tests
isolated function complexPasswordsDataProvider() returns ComplexPassword[][] {
    return [
        [{password: "Short1!"}],
        [{password: "ThisIsAVeryLongPasswordWith123!@#"}],
        [{password: "❤️🌟🎉Pass123!"}],
        [{password: "Pass\u{0000}word123"}],
        [{password: " LeadingSpace123!"}],
        [{password: "TrailingSpace123! "}],
        [{password: "Pass word123!"}],
        [{password: "!@#$%^&*()_+-=[]{}|;:,.<>?"}],
        [{password: "12345678901234567890"}],
        [{password: "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}],
        [{password: "abcdefghijklmnopqrstuvwxyz"}]
    ];
}

isolated function invalidArgon2ParamsDataProvider() returns InvalidArgon2Params[][] {
    return [
        [{iterations: 0, memory: 65536, parallelism: 4, expectedError: "Iterations must be positive"}],
        [{iterations: 3, memory: 1024, parallelism: 4, expectedError: "Memory must be at least 8192 KB (8MB)"}],
        [{iterations: 3, memory: 65536, parallelism: 0, expectedError: "Parallelism must be positive"}],
        [{iterations: -1, memory: 65536, parallelism: 4, expectedError: "Iterations must be positive"}],
        [{iterations: 3, memory: -1024, parallelism: 4, expectedError: "Memory must be at least 8192 KB (8MB)"}],
        [{iterations: 3, memory: 65536, parallelism: -2, expectedError: "Parallelism must be positive"}]
    ];
}

isolated function invalidBcryptWorkFactorsDataProvider() returns InvalidWorkFactor[][] {
    return [
        [{factor: 2, expectedError: "Work factor must be between 4 and 31"}],
        [{factor: 3, expectedError: "Work factor must be between 4 and 31"}],
        [{factor: 32, expectedError: "Work factor must be between 4 and 31"}],
        [{factor: 0, expectedError: "Work factor must be between 4 and 31"}],
        [{factor: -1, expectedError: "Work factor must be between 4 and 31"}]
    ];
}

isolated function validPasswordsDataProvider() returns ValidPassword[][] {
    return [
        [{password: "Ballerina@123"}],
        [{password: "AnotherPass@456"}],
        [{password: "YetAnotherPass@789"}],
        [{password: "❤️🌟🎉Pass123!"}],
        [{password: "Helloasdjk@123#999xDhabasdas333"}]
    ];
}

isolated function wrongPasswordsDataProvider() returns PasswordPair[][] {
    return [
        [{correctPassword: "Ballerina@123", wrongPassword: "ballerina@123"}],
        [{correctPassword: "Ballerina@123", wrongPassword: "Ballerina@124"}],
        [{correctPassword: "Ballerina@123", wrongPassword: "Ballerina@1234"}],
        [{correctPassword: "Ballerina@123", wrongPassword: "Ballerin@123"}],
        [{correctPassword: "Ballerina@123", wrongPassword: " Ballerina@123"}],
        [{correctPassword: "Ballerina@123", wrongPassword: "Ballerina@123 "}],
        [{correctPassword: "Ballerina@123", wrongPassword: ""}]
    ];
}

isolated function invalidArgon2HashesDataProvider() returns InvalidHash[][] {
    return [
        [{hash: "invalid_hash_format", expectedError: "Invalid Argon2 hash format"}],
        [{hash: "$argon2id$v=19$invalid", expectedError: "Invalid Argon2 hash format"}],
        [{hash: "$argon2id$v=19$m=65536$missing_parts", expectedError: "Invalid Argon2 hash format"}],
        [{hash: "$argon2i$v=19$m=65536,t=3,p=4$salt$hash", expectedError: "Invalid Argon2 hash format"}]
    ];
}

isolated function invalidBcryptHashesDataProvider() returns InvalidHash[][] {
    return [
        [{hash: "invalid_hash_format", expectedError: "Invalid hash format"}],
        [{hash: "asdjbashndjakbnsdajkbdnaksjbd", expectedError: "Invalid hash format"}],
        [{hash: "this is invalid formattttttttttttttttttttttt", expectedError: "Invalid hash format"}]
    ];
}

isolated function uniquenessPasswordsDataProvider() returns ValidPassword[][] {
    return [
        [{password: "Ballerina@123"}],
        [{password: "Complex!Pass#2024"}],
        [{password: "Test123!@#"}],
        [{password: "❤️SecurePass789"}],
        [{password: "LongPassword123!@#$"}]
    ];
}

isolated function hashingAlgorithmsDataProvider() returns string[][] {
    return [
        ["argon2"],
        ["bcrypt"]
    ];
}
