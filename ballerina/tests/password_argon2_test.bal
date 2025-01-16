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
isolated function testHashPasswordArgon2Default() {
    string password = "Ballerina@123";
    string|Error hash = hashPasswordArgon2(password);
    if hash is string {
        test:assertTrue(hash.startsWith("$argon2id$v=19$"));
        test:assertTrue(hash.length() > 50);
    } else {
        test:assertFail("Password hashing failed");
    }
}

@test:Config {}
isolated function testHashPasswordArgon2Custom() {
    string password = "Ballerina@123";
    string|Error hash = hashPasswordArgon2(password, 4, 131072, 8);
    if hash is string {
        test:assertTrue(hash.includes("m=131072,t=4,p=8"));
        test:assertTrue(hash.length() > 50);
    } else {
        test:assertFail("Password hashing failed");
    }
}

@test:Config {}
isolated function testHashPasswordArgon2ComplexPasswords() {
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
        string|Error hash = hashPasswordArgon2(password);
        if hash is string {
            test:assertTrue(hash.startsWith("$argon2id$v=19$"));

            boolean|Error result = verifyPasswordArgon2(password, hash);
            if result is boolean {
                test:assertTrue(result, "Password verification failed for: " + password);
            } else {
                test:assertFail("Verification error for password: " + password);
            }
        } else {
            test:assertFail("Hashing failed for password: " + password);
        }
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
        string|Error hash = hashPasswordArgon2(password, params[0], params[1], params[2]);
        if hash is Error {
            test:assertEquals(hash.message(), expectedError);
        } else {
            test:assertFail(string `Should fail with invalid parameters: ${params.toString()}`);
        }
    }
}

@test:Config {}
isolated function testVerifyPasswordArgon2Success() {
    string[] passwords = [
        "Ballerina@123",
        "AnotherPass@456",
        "YetAnotherPass@789",
        "❤️🌟🎉Pass123!",
        "Helloasdjk@123#999xDhabasdas333"
    ];

    foreach string password in passwords {
        string|Error hash = hashPasswordArgon2(password);
        if hash is string {
            boolean|Error result = verifyPasswordArgon2(password, hash);
            if result is boolean {
                test:assertTrue(result, "Password verification failed for: " + password);
            } else {
                test:assertFail("Password verification error for: " + password);
            }
        } else {
            test:assertFail("Password hashing failed for: " + password);
        }
    }
}

@test:Config {}
isolated function testVerifyPasswordArgon2Failure() {
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

    string|Error hash = hashPasswordArgon2(password);
    if hash is string {
        foreach string wrongPassword in wrongPasswords {
            boolean|Error result = verifyPasswordArgon2(wrongPassword, hash);
            if result is boolean {
                test:assertFalse(result, "Should fail for wrong password: " + wrongPassword);
            } else {
                test:assertFail("Verification error for wrong password: " + wrongPassword);
            }
        }
    } else {
        test:assertFail("Password hashing failed");
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
        boolean|Error result = verifyPasswordArgon2(password, invalidHash);
        if result is Error {
            test:assertTrue(result.message().startsWith("Invalid Argon2 hash format"));
        } else {
            test:assertFail("Should fail with invalid hash: " + invalidHash);
        }
    }
}

// Note: The below test case verifies that hashing the same password multiple times 
// produces different results due to the use of random salts. However, there is 
// an extremely rare chance of this test failing if the random salts generated 
// happen to match. The probability of such a collision is approximately 1 in 2^128 
// (based on the randomness of a 128-bit salt).
// 
// In practice, this is highly unlikely and should not occur under normal circumstances.
@test:Config {}
isolated function testArgon2PasswordHashUniqueness() {
    string[] passwords = [
        "Ballerina@123",
        "Complex!Pass#2024",
        "Test123!@#",
        "❤️SecurePass789",
        "LongPassword123!@#$"
    ];

    foreach string password in passwords {
        // Generate three hashes for the same password
        string|Error hash1 = hashPasswordArgon2(password);
        string|Error hash2 = hashPasswordArgon2(password);
        string|Error hash3 = hashPasswordArgon2(password);

        if (hash1 is string && hash2 is string && hash3 is string) {
            // Verify all hashes are different
            test:assertNotEquals(hash1, hash2, "Hashes should be unique for: " + password);
            test:assertNotEquals(hash2, hash3, "Hashes should be unique for: " + password);
            test:assertNotEquals(hash1, hash3, "Hashes should be unique for: " + password);

            // Verify all hashes are valid for the password
            boolean|Error verify1 = verifyPasswordArgon2(password, hash1);
            boolean|Error verify2 = verifyPasswordArgon2(password, hash2);
            boolean|Error verify3 = verifyPasswordArgon2(password, hash3);

            if (verify1 is boolean && verify2 is boolean && verify3 is boolean) {
                test:assertTrue(verify1 && verify2 && verify3,
                        "All hashes should verify successfully for: " + password);
            } else {
                test:assertFail("Verification failed for: " + password);
            }
        } else {
            test:assertFail("Hash generation failed for: " + password);
        }
    }
}
