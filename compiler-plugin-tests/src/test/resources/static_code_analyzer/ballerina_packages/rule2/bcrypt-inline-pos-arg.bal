import ballerina/crypto;

public function bcryptPosArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashBcrypt(password, 9);
}
