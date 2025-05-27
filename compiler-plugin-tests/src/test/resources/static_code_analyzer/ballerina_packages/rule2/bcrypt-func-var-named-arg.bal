import ballerina/crypto;

public function bcryptFuncVarNamedArg() returns error? {
    string password = "your-password";
    int workFactor = 9;
    string _ = check crypto:hashBcrypt(password, workFactor = workFactor);
}
