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
isolated function testHashPasswordDefaultWorkFactor() returns error? {
    string password = "Ballerina@123";
    string hash = check hashBcrypt(password);
    test:assertTrue(hash.startsWith("$2a$12$"));
    test:assertTrue(hash.length() > 50);
}

@test:Config {}
isolated function testHashPasswordCustomWorkFactor() returns error? {
    string password = "Ballerina@123";
    string hash = check hashBcrypt(password, 10);
    test:assertTrue(hash.startsWith("$2a$10$"));
    test:assertTrue(hash.length() > 50);
}

@test:Config {}
isolated function testHashPasswordComplexPasswords() returns error? {
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
        string hash = check hashBcrypt(password);
        test:assertTrue(hash.startsWith("$2a$12$"));
        test:assertTrue(hash.length() > 50);

        boolean result = check verifyBcrypt(password, hash);
        test:assertTrue(result, "Password verification failed for: " + password);
    }
}

@test:Config {}
isolated function testHashPasswordInvalidWorkFactor() {
    string password = "Ballerina@123";
    int[] invalidFactors = [2, 3, 32, 0, -1];

    foreach int factor in invalidFactors {
        string|Error hash = hashBcrypt(password, factor);
        if hash !is Error {
            test:assertFail(string `Should fail with invalid work factor: ${factor}`);
        }
        test:assertEquals(hash.message(), "Work factor must be between 4 and 31");
    }
}

@test:Config {}
isolated function testVerifyPasswordSuccess() returns error? {
    string[] passwords = [
        "Ballerina@123",
        "AnotherPass@456",
        "YetAnotherPass@789",
        "❤️🌟🎉Pass123!",
        "Helloasdjk@123#999xDhabasdas333"
    ];

    foreach string password in passwords {
        string hash = check hashBcrypt(password);
        boolean result = check verifyBcrypt(password, hash);
        test:assertTrue(result, "Password verification failed for: " + password);
    }
}

@test:Config {}
isolated function testVerifyPasswordFailure() returns error? {
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

    string hash = check hashBcrypt(password);
    foreach string wrongPassword in wrongPasswords {
        boolean result = check verifyBcrypt(wrongPassword, hash);
        test:assertFalse(result, "Should fail for wrong password: " + wrongPassword);
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
        if result !is Error {
            test:assertFail("Should fail with invalid hash: " + invalidHash);
        }
        test:assertEquals(result.message(), "Invalid hash format");
    }
}

@test:Config {}
isolated function testPasswordHashUniqueness() returns error? {
    string[] passwords = [
        "Ballerina@123",
        "Complex!Pass#2024",
        "Test123!@#",
        "❤️SecurePass789",
        "LongPassword123!@#$"
    ];

    foreach string password in passwords {
        string hash1 = check hashBcrypt(password);
        string hash2 = check hashBcrypt(password);
        string hash3 = check hashBcrypt(password);

        test:assertNotEquals(hash1, hash2, "Hashes should be unique for: " + password);
        test:assertNotEquals(hash2, hash3, "Hashes should be unique for: " + password);
        test:assertNotEquals(hash1, hash3, "Hashes should be unique for: " + password);

        boolean verify1 = check verifyBcrypt(password, hash1);
        boolean verify2 = check verifyBcrypt(password, hash2);
        boolean verify3 = check verifyBcrypt(password, hash3);

        test:assertTrue(verify1 && verify2 && verify3,
                "All hashes should verify successfully for: " + password);
    }
}

@test:Config {}
isolated function testEmptyPasswordError() returns error? {
    string password = "";
    string|Error hash = hashBcrypt(password);
    if hash !is Error {
        test:assertFail("Should fail with empty password");
    }
    test:assertEquals(hash.message(), "Password cannot be empty");
}
