import ballerina/io;
import ballerina/test;

@test:Config {}
isolated function testHashPasswordDefaultWorkFactor() {
    string password = "Ballerina@123";
    string|Error hash = hashPassword(password);
    if hash is string {
        io:println(hash);
        test:assertTrue(hash.startsWith("$2a$12$"));
        test:assertTrue(hash.length() > 50);
    } else {
        test:assertFail("Password hashing failed");
    }
}

@test:Config {}
isolated function testHashPasswordCustomWorkFactor() {
    string password = "Ballerina@123";
    string|Error hash = hashPassword(password, 10);
    if hash is string {
        io:println(hash);
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
        string|Error hash = hashPassword(password);
        if hash is string {
            io:println(hash);
            test:assertTrue(hash.startsWith("$2a$12$"));
            test:assertTrue(hash.length() > 50);

            // Verify the password immediately
            boolean|Error result = verifyPassword(password, hash);
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
        string|Error hash = hashPassword(password, factor);
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
        string|Error hash = hashPassword(password);
        if hash is string {
            boolean|Error result = verifyPassword(password, hash);
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

    string|Error hash = hashPassword(password);
    if hash is string {
        foreach string wrongPassword in wrongPasswords {
            boolean|Error result = verifyPassword(wrongPassword, hash);
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
        boolean|Error result = verifyPassword(password, invalidHash);
        if result is Error {
            test:assertEquals(result.message(), "Invalid hash format");
        } else {
            test:assertFail("Should fail with invalid hash: " + invalidHash);
        }
    }
}

@test:Config {}
isolated function testGenerateSaltDefaultWorkFactor() {
    string|Error salt = generateSalt();
    if salt is string {
        test:assertTrue(salt.startsWith("$2a$12$"));
        test:assertTrue(salt.length() > 20);
    } else {
        test:assertFail("Salt generation failed");
    }
}

@test:Config {}
isolated function testGenerateSaltCustomWorkFactor() {
    int[] validFactors = [4, 10, 14, 20, 31];
    foreach int factor in validFactors {
        string|Error salt = generateSalt(factor);
        if salt is string {
            // Format the factor as a two-digit number
            string expectedPrefix = "$2a$" + factor.toBalString().padStart(2, "0") + "$";
            test:assertTrue(salt.startsWith(expectedPrefix), "Salt does not start with expected prefix for factor: " + factor.toString() + ". Generated salt: " + salt);
            test:assertTrue(salt.length() > 20, "Salt length is not greater than 20 for factor: " + factor.toString());
        } else {
            test:assertFail("Salt generation failed for factor: " + factor.toString());
        }
    }
}

@test:Config {}
isolated function testGenerateSaltInvalidWorkFactor() {
    int[] invalidFactors = [-1, 0, 3, 32, 100];
    foreach int factor in invalidFactors {
        string|Error salt = generateSalt(factor);
        if salt is Error {
            test:assertEquals(salt.message(), "Work factor must be between 4 and 31");
        } else {
            test:assertFail("Should fail with invalid factor: " + factor.toString());
        }
    }
}
