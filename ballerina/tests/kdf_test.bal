// Copyright (c) 2024 WSO2 LLC. (https://www.wso2.com).
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

import ballerina/test;
import ballerina/lang.array;

@test:Config {
    groups: ["non-fips"]
}
isolated function testHkdfSha256() returns error? {
    string sharedSecret = "Hu7q5+8SI61d7kKsD3qMxkdPYOnp+6tMp5YkR6NuN28=";
    string expectedDerivedKey = "Oze/CwrXylVzqWXirsT15/qGWe/iXwe+xeCRB9PrRZE=";

    byte[] decodedSharedSecret = check array:fromBase64(sharedSecret);
    byte[] derivedKey = check hkdfSha256(decodedSharedSecret, 32);
    string encodedDerivedKey = array:toBase64(derivedKey);
    test:assertEquals(derivedKey.length(), 32);
    test:assertEquals(encodedDerivedKey, expectedDerivedKey);
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testHkdfSha256WithSalt() returns error? {
    string sharedSecret = "Hu7q5+8SI61d7kKsD3qMxkdPYOnp+6tMp5YkR6NuN28=";
    string salt = "NaCl";
    string expectedDerivedKey = "JsmMnsD8uGUePvUAAuweZoAZteedTbK2Xs2ezbf/LWc=";

    byte[] decodedSharedSecret = check array:fromBase64(sharedSecret);
    byte[] derivedKey = check hkdfSha256(decodedSharedSecret, 32, salt.toBytes());
    string encodedDerivedKey = array:toBase64(derivedKey);
    test:assertEquals(encodedDerivedKey, expectedDerivedKey);
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testHkdfSha256WithInfo() returns error? {
    string sharedSecret = "Hu7q5+8SI61d7kKsD3qMxkdPYOnp+6tMp5YkR6NuN28=";
    string info = "info";
    string expectedDerivedKey = "oTPUhp3AWCESr1dIZyYJySgixUPMb+8hn3gm/t2sQ6M=";

    byte[] decodedSharedSecret = check array:fromBase64(sharedSecret);
    byte[] derivedKey = check hkdfSha256(decodedSharedSecret, 32, info = info.toBytes());
    string encodedDerivedKey = array:toBase64(derivedKey);
    test:assertEquals(encodedDerivedKey, expectedDerivedKey);
}

@test:Config {
    groups: ["non-fips"]
}
isolated function testHkdfSha256WithSaltAndInfo() returns error? {
    string sharedSecret = "Hu7q5+8SI61d7kKsD3qMxkdPYOnp+6tMp5YkR6NuN28=";   
    string salt = "NaCl";
    string info = "info";
    string expectedDerivedKey = "7ciQw6QKifikWk4NccsJ2q5CYPyJVfVrlblSBqGaB3o=";

    byte[] decodedSharedSecret = check array:fromBase64(sharedSecret);
    byte[] derivedKey = check hkdfSha256(decodedSharedSecret, 32, salt.toBytes(), info.toBytes());
    string encodedDerivedKey = array:toBase64(derivedKey);
    test:assertEquals(encodedDerivedKey, expectedDerivedKey);
}
