import ballerina/crypto;

int iterationspbkdf2ModVarNamed = 90000;

public function pbkdf2ModVarNamedArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashPbkdf2(password, iterations = iterationspbkdf2ModVarNamed);
}
