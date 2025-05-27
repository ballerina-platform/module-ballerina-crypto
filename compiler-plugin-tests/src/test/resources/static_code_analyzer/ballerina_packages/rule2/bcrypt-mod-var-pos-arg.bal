import ballerina/crypto;

int workFactorModVarPos = 9;

public function bcryptModVarPosArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashBcrypt(password, workFactorModVarPos);
}
