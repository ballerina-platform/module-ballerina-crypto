import ballerina/crypto;

public function ArgonFuncVarNamedArg() returns error? {
    string password = "your-password";
    int iterations = 1;
    int memory = 1024;
    int parallelism = 0;
    string _ = check crypto:hashArgon2(password, iterations = iterations, memory = memory, parallelism = parallelism);
}
