// Copyright (c) 2025 WSO2 LLC. (http://www.wso2.com).
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

@test:Config {}
isolated function testHashPasswordArgon2ComplexPasswords() returns error? {
    string[] passwords = [
        "Short1!",
        "ThisIsAVeryLongPasswordWith123!@#",
        "❤️🌟🎉Pass123!",
        "Pass\u{0000}word123",
        " LeadingSpace123!",
        "TrailingSpace123! ",
        "Pass word123!",
        "!@#$%^&*()_+-=[]{}|;:,.<>?",
        "12345678901234567890",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz"
    ];

    foreach string password in passwords {
        string hash = check hashArgon2(password);
        test:assertTrue(hash.startsWith("$argon2id$v=19$"));

        boolean result = check verifyArgon2(password, hash);
        test:assertTrue(result, "Password verification failed for: " + password);
    }
}

@test:Config {}
isolated function testHashPasswordArgon2InvalidParams() {
    string password = "Ballerina@123";
    record {|int[] params; string expectedError;|}[] testCases = [
        {params: [0, 65536, 4], expectedError: "Iterations must be positive"},
        {params: [3, 1024, 4], expectedError: "Memory must be at least 8192 KB (8MB)"},
        {params: [3, 65536, 0], expectedError: "Parallelism must be positive"},
        {params: [-1, 65536, 4], expectedError: "Iterations must be positive"},
        {params: [3, -1024, 4], expectedError: "Memory must be at least 8192 KB (8MB)"},
        {params: [3, 65536, -2], expectedError: "Parallelism must be positive"}
    ];

    foreach var {params, expectedError} in testCases {
        string|Error hash = hashArgon2(password, params[0], params[1], params[2]);
        if hash !is Error {
            test:assertFail(string `Should fail with invalid parameters: ${params.toString()}`);
        }
        test:assertEquals(hash.message(), expectedError);
    }
}

@test:Config {}
isolated function testVerifyPasswordArgon2Success() returns error? {
    string[] passwords = [
        "Ballerina@123",
        "AnotherPass@456",
        "YetAnotherPass@789",
        "❤️🌟🎉Pass123!",
        "Helloasdjk@123#999xDhabasdas333"
    ];

    foreach string password in passwords {
        string hash = check hashArgon2(password);
        boolean result = check verifyArgon2(password, hash);
        test:assertTrue(result, "Password verification failed for: " + password);
    }
}

@test:Config {}
isolated function testVerifyPasswordArgon2Failure() returns error? {
    string password = "Ballerina@123";
    string[] wrongPasswords = [
        "ballerina@123",
        "Ballerina@124",
        "Ballerina@1234",
        "Ballerin@123",
        " Ballerina@123",
        "Ballerina@123 ",
        ""
    ];

    string hash = check hashArgon2(password);
    foreach string wrongPassword in wrongPasswords {
        boolean result = check verifyArgon2(wrongPassword, hash);
        test:assertFalse(result, "Should fail for wrong password: " + wrongPassword);
    }
}

@test:Config {}
isolated function testVerifyPasswordArgon2InvalidHashFormat() {
    string password = "Ballerina@123";
    string[] invalidHashes = [
        "invalid_hash_format",
        "$argon2id$v=19$invalid",
        "$argon2id$v=19$m=65536$missing_parts",
        "$argon2i$v=19$m=65536,t=3,p=4$salt$hash" // Wrong variant
    ];

    foreach string invalidHash in invalidHashes {
        boolean|Error result = verifyArgon2(password, invalidHash);
        test:assertTrue(result is Error, string `Should fail with invalid hash: ${invalidHash}`);
        Error err = check result.ensureType();
        test:assertTrue(err.message().startsWith("Invalid Argon2 hash format"));
    }
}

@test:Config {}
isolated function testArgon2PasswordHashUniqueness() returns error? {
    string[] passwords = [
        "Ballerina@123",
        "Complex!Pass#2024",
        "Test123!@#",
        "❤️SecurePass789",
        "LongPassword123!@#$"
    ];

    foreach string password in passwords {
        string hash1 = check hashArgon2(password);
        string hash2 = check hashArgon2(password);
        string hash3 = check hashArgon2(password);

        test:assertNotEquals(hash1, hash2, "Hashes should be unique for: " + password);
        test:assertNotEquals(hash2, hash3, "Hashes should be unique for: " + password);
        test:assertNotEquals(hash1, hash3, "Hashes should be unique for: " + password);

        boolean verify1 = check verifyArgon2(password, hash1);
        boolean verify2 = check verifyArgon2(password, hash2);
        boolean verify3 = check verifyArgon2(password, hash3);

        test:assertTrue(verify1 && verify2 && verify3,
                "All hashes should verify successfully for: " + password);
    }
}

@test:Config {}
isolated function testEmptyPasswordErrorArgon2() returns error? {
    string password = "";
    string|Error hash = hashArgon2(password);
    if hash !is Error {
        test:assertFail("Should fail with empty password");
    }
    test:assertEquals(hash.message(), "Password cannot be empty");
}
