import ballerina/crypto;

public function pbkdf2PosArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashPbkdf2(password, 90000);
}
