import ballerina/crypto;

public function pbkdf2FuncVarPosArg() returns error? {
    string password = "your-password";
    int iterations = 90000;
    string _ = check crypto:hashPbkdf2(password, iterations);
}
