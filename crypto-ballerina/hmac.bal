// Copyright (c) 2020 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
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

# Returns the HMAC using the MD-5 hash function of the given data.
# ```ballerina
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  string keyString = "some-secret";
#  byte[] key = keyString.toBytes();
#  byte[] hmac = crypto:hmacMd5(data, key);
# ```
#
# + input - Value to be hashed
# + key - Key used for HMAC generation
# + return - HMAC output or `crypto:Error`
public isolated function hmacMd5(byte[] input, byte[] key) returns byte[]|Error = @java:Method {
    name: "hmacMd5",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hmac"
} external;

# Returns the HMAC using the SHA-1 hash function of the given data.
# ```ballerina
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  string keyString = "some-secret";
#  byte[] key = keyString.toBytes();
#  byte[] hmac = crypto:hmacSha1(data, key);
# ```
#
# + input - Value to be hashed
# + key - Key used for HMAC generation
# + return - HMAC output or `crypto:Error`
public isolated function hmacSha1(byte[] input, byte[] key) returns byte[]|Error = @java:Method {
    name: "hmacSha1",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hmac"
} external;

# Returns the HMAC using the SHA-256 hash function of the given data.
# ```ballerina
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  string keyString = "some-secret";
#  byte[] key = keyString.toBytes();
#  byte[] hmac = crypto:hmacSha256(data, key);
# ```
#
# + input - Value to be hashed
# + key - Key used for HMAC generation
# + return - HMAC output or `crypto:Error`
public isolated function hmacSha256(byte[] input, byte[] key) returns byte[]|Error = @java:Method {
    name: "hmacSha256",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hmac"
} external;

# Returns the HMAC using the SHA-384 hash function of the given data.
# ```ballerina
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  string keyString = "some-secret";
#  byte[] key = keyString.toBytes();
#  byte[] hmac = crypto:hmacSha384(data, key);
# ```
#
# + input - Value to be hashed
# + key - Key used for HMAC generation
# + return - HMAC output or `crypto:Error`
public isolated function hmacSha384(byte[] input, byte[] key) returns byte[]|Error = @java:Method {
    name: "hmacSha384",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hmac"
} external;

# Returns the HMAC using the SHA-512 hash function of the given data.
# ```ballerina
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  string keyString = "some-secret";
#  byte[] key = keyString.toBytes();
#  byte[] hmac = crypto:hmacSha512(data, key);
# ```
#
# + input - Value to be hashed
# + key - Key used for HMAC generation
# + return - HMAC output or `crypto:Error`
public isolated function hmacSha512(byte[] input, byte[] key) returns byte[]|Error = @java:Method {
    name: "hmacSha512",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hmac"
} external;
