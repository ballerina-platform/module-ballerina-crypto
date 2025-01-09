import ballerina/jballerina.java;

# Returns an Argon2id hash of the given password with optional parameters.
# ```ballerina
# string password = "mySecurePassword123";
# string|crypto:Error hash = crypto:hashPasswordArgon2(password);
# ```
#
# + password - Password string to be hashed
# + iterations - Optional number of iterations. Default is 3
# + memory - Optional memory usage in KB. Default is 65536 (64MB)
# + parallelism - Optional degree of parallelism. Default is 4
# + return - Argon2id hashed password string or Error if hashing fails
public isolated function hashPasswordArgon2(string password, int iterations = 3, int memory = 65536, int parallelism = 4) returns string|Error = @java:Method {
    name: "hashPasswordArgon2",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.PasswordArgon2"
} external;

# Verifies if a password matches an Argon2id hashed password.
# ```ballerina
# string password = "mySecurePassword123";
# string hashedPassword = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash";
# boolean|crypto:Error matches = crypto:verifyPasswordArgon2(password, hashedPassword);
# ```
#
# + password - Password string to verify
# + hashedPassword - Argon2id hashed password to verify against
# + return - Boolean indicating if password matches or Error if verification fails
public isolated function verifyPasswordArgon2(string password, string hashedPassword) returns boolean|Error = @java:Method {
    name: "verifyPasswordArgon2",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.PasswordArgon2"
} external;

# Generates an Argon2id salt with optional parameters.
# ```ballerina
# string|crypto:Error salt = crypto:generateSaltArgon2(4, 131072, 8);
# ```
#
# + iterations - Optional number of iterations. Default is 3
# + memory - Optional memory usage in KB. Default is 65536 (64MB)
# + parallelism - Optional degree of parallelism. Default is 4
# + return - Generated Argon2id salt string or Error if generation fails
public isolated function generateSaltArgon2(int iterations = 3, int memory = 65536, int parallelism = 4) returns string|Error = @java:Method {
    name: "generateSaltArgon2",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.PasswordArgon2"
} external;
