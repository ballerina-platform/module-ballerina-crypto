// Copyright (c) 2025 WSO2 LLC. (http://www.wso2.com)
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/crypto;
import wso2/rule2.'module as mod;

const MEMORY = 16384;

public function ArgonFunc() returns error? {
    // Default parameters - iterations: 3, memory: 65536, parallelism: 4
    _ = check crypto:hashArgon2("password");
    // Custom least secure parameters: iterations: 2, memory: 19456, parallelism: 1
    _ = check crypto:hashArgon2("password", 2, 19456, 1);
    // Secure parameters - memory constant from different module
    _ = check crypto:hashArgon2("password", memory = mod:MINIMUM_ALLOWED_MEMORY);

    // Unsecure parameters
    // iterations
    _ = check crypto:hashArgon2("password", 1);
    // memory
    _ = check crypto:hashArgon2("password", memory = 8192);
    // memory with constant
    _ = check crypto:hashArgon2("password", memory = MEMORY);
    // memory with module constant
    _ = check crypto:hashArgon2("password", memory = mod:MEMORY);
    // memory with module variable - This is a negative test case
    // Cannot be determined at compile time
    _ = check crypto:hashArgon2("password", memory = mod:memory);
}
