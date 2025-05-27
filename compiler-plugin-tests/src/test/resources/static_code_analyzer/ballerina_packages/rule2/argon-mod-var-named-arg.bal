import ballerina/crypto;

int iterationsModVarNamed = 1;
int memoryModVarNamed = 1024;
int parallelismModVarNamed = 0;

public function ArgonModVarNamedArg() returns error? {
    string password = "your-password";
    string _ = check crypto:hashArgon2(password, iterations = iterationsModVarNamed, memory = memoryModVarNamed, parallelism = parallelismModVarNamed);
}
