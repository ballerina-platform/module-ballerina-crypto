import ballerina/crypto;

public function bcryptNamedArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashBcrypt(password, workFactor = 9);
}
