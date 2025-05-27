import ballerina/crypto;

int iterationspbkdf2ModVarPos = 90000;

public function pbkdf2ModVarPosArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashPbkdf2(password, iterationspbkdf2ModVarPos);
}
