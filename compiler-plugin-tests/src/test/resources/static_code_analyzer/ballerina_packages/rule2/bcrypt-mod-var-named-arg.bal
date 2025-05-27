import ballerina/crypto;

int workFactorModVarNamed = 9;

public function bcryptModVarNamedArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashBcrypt(password, workFactor = workFactorModVarNamed);
}
