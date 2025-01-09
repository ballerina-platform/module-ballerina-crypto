import ballerina/io;
import ballerina/test;

@test:Config {}
isolated function testHashPasswordArgon2Default() {
    string password = "Ballerina@123";
    string|Error hash = hashPasswordArgon2(password);
    if hash is string {
        io:println(hash);
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
        io:println(hash);
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
            io:println(hash);
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
    int[][] invalidParams = [
        [0, 65536, 4], // Invalid iterations
        [3, 1024, 4], // Too little memory
        [3, 65536, 0], // Invalid parallelism
        [-1, 65536, 4], // Negative iterations
        [3, -1024, 4], // Negative memory
        [3, 65536, -2] // Negative parallelism
    ];

    foreach int[] params in invalidParams {
        string|Error hash = hashPasswordArgon2(password, params[0], params[1], params[2]);
        if hash is Error {
            test:assertTrue(hash.message().startsWith("Error occurred while hashing password"));
        } else {
            test:assertFail(string `Should fail with invalid parameters: ${params.toString()} but it succeeded: ${hash}`);
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

@test:Config {}
isolated function testGenerateSaltArgon2Default() {
    string|Error salt = generateSaltArgon2();
    if salt is string {
        test:assertTrue(salt.startsWith("$argon2id$v=19$"));
        test:assertTrue(salt.includes("m=65536,t=3,p=4"));
    } else {
        test:assertFail("Salt generation failed");
    }
}

@test:Config {}
isolated function testGenerateSaltArgon2Custom() {
    int[][] validParams = [
        [4, 131072, 8],
        [2, 65536, 4],
        [6, 262144, 16]
    ];

    foreach int[] params in validParams {
        string|Error salt = generateSaltArgon2(params[0], params[1], params[2]);
        if salt is string {
            string expectedParams = string `m=${params[1]},t=${params[0]},p=${params[2]}`;
            test:assertTrue(salt.includes(expectedParams));
        } else {
            test:assertFail("Salt generation failed for params: " + params.toString());
        }
    }
}
