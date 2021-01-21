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

# Returns the MD5 hash of the given data.
# ```ballerina
#  string dataString = "Hello Ballerina";
#  byte[] data = dataString.toBytes();
#  byte[] hash = crypto:hashMd5(data);
# ```
#
# + input - Value to be hashed
# + return - Hashed output
public isolated function hashMd5(byte[] input) returns byte[] = @java:Method {
    name: "hashMd5",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hash"
} external;

# Returns the SHA-1 hash of the given data.
# ```ballerina
#  string dataString = "Hello Ballerina";
#  byte[] data = dataString.toBytes();
#  byte[] hash = crypto:hashSha1(data);
# ```
#
# + input - Value to be hashed
# + return - Hashed output
public isolated function hashSha1(byte[] input) returns byte[] = @java:Method {
    name: "hashSha1",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hash"
} external;

# Returns the SHA-256 hash of the given data.
# ```ballerina
#  string dataString = "Hello Ballerina";
#  byte[] data = dataString.toBytes();
#  byte[] hash = crypto:hashSha256(data);
# ```
#
# + input - Value to be hashed
# + return - Hashed output
public isolated function hashSha256(byte[] input) returns byte[] = @java:Method {
    name: "hashSha256",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hash"
} external;

# Returns the SHA-384 hash of the given data.
# ```ballerina
#  string dataString = "Hello Ballerina";
#  byte[] data = dataString.toBytes();
#  byte[] hash = crypto:hashSha384(data);
# ```
#
# + input - Value to be hashed
# + return - Hashed output
public isolated function hashSha384(byte[] input) returns byte[] = @java:Method {
    name: "hashSha384",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hash"
} external;

# Returns the SHA-512 hash of the given data.
# ```ballerina
#  string dataString = "Hello Ballerina";
#  byte[] data = dataString.toBytes();
#  byte[] hash = crypto:hashSha512(data);
# ```
#
# + input - Value to be hashed
# + return - Hashed output
public isolated function hashSha512(byte[] input) returns byte[] = @java:Method {
    name: "hashSha512",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hash"
} external;

# Returns the Hex-encoded CRC32B value for the provided element.
# ```ballerina
#  string stringData = "Hello Ballerina";
#  byte[] data = stringData.toBytes();
#  string checksum = crypto:crc32b(data);
# ```
#
# + input - Value for checksum generation
# + return - The generated checksum
public isolated function crc32b(byte[] input) returns string = @java:Method {
    name: "crc32b",
    'class: "org.ballerinalang.stdlib.crypto.nativeimpl.Hash"
} external;
