import ballerina/crypto;

public function pbkdf2FuncVarNamedArg() returns error? {
    string password = "your-password";
    int iterations = 90000;
    string _ = check crypto:hashPbkdf2(password, iterations = iterations);
}
