import ballerina/crypto;

public function ArgonNamedArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashArgon2(password, iterations = 1, memory = 1024, parallelism = 0);
}
