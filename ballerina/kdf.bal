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

import ballerina/jballerina.java;

# Returns HKDF (HMAC-based Key Derivation Function) using SHA-256 as the hash function.
# ```ballerina
# string secret = "some-secret";
# byte[] key = secret.toBytes();
# byte[] hash = crypto:hkdfSha256(key, 32);
# ```
# + input - The input key material to derive the key from
# + length - The length of the output keying material (OKM) in bytes
# + salt - Optional salt value, a non-secret random value
# + info - Optional context and application-specific information
# + return - The derived keying material (OKM) of the specified length
public isolated function hkdfSha256(byte[] input, int length, byte[] salt = [], byte[] info = []) returns byte[]|Error = @java:Method {
    name: "hkdfSha256",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Kdf"
} external;
