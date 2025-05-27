import ballerina/crypto;

int iterationsModVarPos = 1;
int memoryModVarPos = 1024;
int parallelismModVarPos = 0;

public function ArgonModVarPosArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashArgon2(password, iterations = iterationsModVarPos, memory = memoryModVarPos, parallelism = parallelismModVarPos);
}
