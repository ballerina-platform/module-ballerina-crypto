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
isolated function testHashPasswordDefaultWorkFactor() {
    string password = "Ballerina@123";
    string|Error hash = hashBcrypt(password);
    if hash is string {
        test:assertTrue(hash.startsWith("$2a$12$"));
        test:assertTrue(hash.length() > 50);
    } else {
        test:assertFail("Password hashing failed");
    }
}

@test:Config {}
isolated function testHashPasswordCustomWorkFactor() {
    string password = "Ballerina@123";
    string|Error hash = hashBcrypt(password, 10);
    if hash is string {
        test:assertTrue(hash.startsWith("$2a$10$"));
        test:assertTrue(hash.length() > 50);
    } else {
        test:assertFail("Password hashing failed");
    }
}

@test:Config {}
isolated function testHashPasswordComplexPasswords() {
    string[] passwords = [
        "Short1!", // Short password
        "ThisIsAVeryLongPasswordWith123!@#", // Long password
        "❤️🌟🎉Pass123!", // With emojis
        "Pass\u{0000}word123", // With null character
        " LeadingSpace123!", // Leading space
        "TrailingSpace123! ", // Trailing space
        "Pass word123!", // With spaces
        "!@#$%^&*()_+-=[]{}|;:,.<>?", // Only special chars
        "12345678901234567890", // Only numbers
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ", // Only uppercase
        "abcdefghijklmnopqrstuvwxyz" // Only lowercase
    ];

    foreach string password in passwords {
        string|Error hash = hashBcrypt(password);
        if hash is string {
            test:assertTrue(hash.startsWith("$2a$12$"));
            test:assertTrue(hash.length() > 50);

            // Verify the password immediately
            boolean|Error result = verifyBcrypt(password, hash);
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
isolated function testHashPasswordInvalidWorkFactor() {
    string password = "Ballerina@123";
    int[] invalidFactors = [2, 3, 32, 0, -1];

    foreach int factor in invalidFactors {
        string|Error hash = hashBcrypt(password, factor);
        if hash is Error {
            test:assertEquals(hash.message(), "Work factor must be between 4 and 31");
        } else {
            test:assertFail(string `Should fail with invalid work factor: ${factor}`);
        }
    }
}

@test:Config {}
isolated function testVerifyPasswordSuccess() {
    string[] passwords = [
        "Ballerina@123",
        "AnotherPass@456",
        "YetAnotherPass@789",
        "❤️🌟🎉Pass123!",
        "Helloasdjk@123#999xDhabasdas333"
    ];

    foreach string password in passwords {
        string|Error hash = hashBcrypt(password);
        if hash is string {
            boolean|Error result = verifyBcrypt(password, hash);
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
isolated function testVerifyPasswordFailure() {
    string password = "Ballerina@123";
    string[] wrongPasswords = [
        "ballerina@123", // Different case
        "Ballerina@124", // One character different
        "Ballerina@1234", // Extra character
        "Ballerin@123", // Missing character
        " Ballerina@123", // Leading space
        "Ballerina@123 ", // Trailing space
        "" // Empty string
    ];

    string|Error hash = hashBcrypt(password);
    if hash is string {
        foreach string wrongPassword in wrongPasswords {
            boolean|Error result = verifyBcrypt(wrongPassword, hash);
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
isolated function testVerifyPasswordInvalidHashFormat() {
    string password = "Ballerina@123";
    string[] invalidHashes = [
        "invalid_hash_format",
        "asdjbashndjakbnsdajkbdnaksjbd",
        "this is invalid formattttttttttttttttttttttt"
    ];

    foreach string invalidHash in invalidHashes {
        boolean|Error result = verifyBcrypt(password, invalidHash);
        if result is Error {
            test:assertEquals(result.message(), "Invalid hash format");
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
isolated function testPasswordHashUniqueness() {
    string[] passwords = [
        "Ballerina@123",
        "Complex!Pass#2024",
        "Test123!@#",
        "❤️SecurePass789",
        "LongPassword123!@#$"
    ];

    foreach string password in passwords {
        // Generate three hashes for the same password
        string|Error hash1 = hashBcrypt(password);
        string|Error hash2 = hashBcrypt(password);
        string|Error hash3 = hashBcrypt(password);

        if hash1 is string && hash2 is string && hash3 is string {
            // Verify all hashes are different
            test:assertNotEquals(hash1, hash2, "Hashes should be unique for: " + password);
            test:assertNotEquals(hash2, hash3, "Hashes should be unique for: " + password);
            test:assertNotEquals(hash1, hash3, "Hashes should be unique for: " + password);

            // Verify all hashes are valid for the password
            boolean|Error verify1 = verifyBcrypt(password, hash1);
            boolean|Error verify2 = verifyBcrypt(password, hash2);
            boolean|Error verify3 = verifyBcrypt(password, hash3);

            if verify1 is boolean && verify2 is boolean && verify3 is boolean {
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
