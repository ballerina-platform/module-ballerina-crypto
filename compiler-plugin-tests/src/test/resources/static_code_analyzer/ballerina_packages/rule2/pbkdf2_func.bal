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

public function pbkdf2Func() returns error? {
    // Default parameters - iterations: 10000 which is lower than recommended for all algorithms
    // Hence vulnerable
    _ = check crypto:hashPbkdf2("password"); // Default algorithm is SHA-256.
    _ = check crypto:hashPbkdf2("password", algorithm = crypto:SHA1);
    _ = check crypto:hashPbkdf2("password", algorithm = crypto:SHA256);
    _ = check crypto:hashPbkdf2("password", algorithm = crypto:SHA512);


    // Default algorithm is SHA-256. Iterations set to minimum recommended value for SHA-256 (600000)
    _ = check crypto:hashPbkdf2("password", 600000);
    _ = check crypto:hashPbkdf2("password", 600000, "SHA256");

    // Iterations set to minimum recommended value for SHA-1 (1000000)
    _ = check crypto:hashPbkdf2("password", 1300000, crypto:SHA1);

    // Iterations set to minimum recommended value for SHA-512 (500000)
    _ = check crypto:hashPbkdf2("password", 210000, "SHA512");

    // Vulnerable examples
    _ = check crypto:hashPbkdf2("password", 200000, crypto:SHA256);
    _ = check crypto:hashPbkdf2("password", 900000, "SHA1");
    _ = check crypto:hashPbkdf2("password", 200000, crypto:SHA512);
}
