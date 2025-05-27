import ballerina/crypto;

public function ArgonPosArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashArgon2(password, 1, 1024, 0);
}
