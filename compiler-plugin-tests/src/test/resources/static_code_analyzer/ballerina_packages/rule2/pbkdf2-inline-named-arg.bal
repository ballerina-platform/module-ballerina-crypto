import ballerina/crypto;

public function pbkdf2NamedArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashPbkdf2(password, iterations = 90000);
}
