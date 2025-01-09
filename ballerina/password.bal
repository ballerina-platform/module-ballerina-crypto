// Copyright (c) 2024 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

# Returns a BCrypt hash of the given password with optional work factor.
# ```ballerina
# string password = "mySecurePassword123";
# string|crypto:Error hash = crypto:hashPassword(password);
# ```
#
# + password - Password string to be hashed
# + workFactor - Optional work factor (cost parameter) between 4 and 31. Default is 12
# + return - BCrypt hashed password string or Error if hashing fails
public isolated function hashPassword(string password, int workFactor = 12) returns string|Error = @java:Method {
    name: "hashPassword",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Password"
} external;

# Verifies if a password matches a BCrypt hashed password.
# ```ballerina
# string password = "mySecurePassword123";
# string hashedPassword = "$2a$12$LQV3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYpwBAM7RHF.H9m";
# boolean|crypto:Error matches = crypto:verifyPassword(password, hashedPassword);
# ```
#
# + password - Password string to verify
# + hashedPassword - BCrypt hashed password to verify against
# + return - Boolean indicating if password matches or Error if verification fails
public isolated function verifyPassword(string password, string hashedPassword) returns boolean|Error = @java:Method {
    name: "verifyPassword",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Password"
} external;

# Generates a BCrypt salt with optional work factor.
# ```ballerina
# string|crypto:Error salt = crypto:generateSalt(14);
# ```
#
# + workFactor - Optional work factor (cost parameter) between 4 and 31. Default is 12
# + return - Generated BCrypt salt string or Error if generation fails
public isolated function generateSalt(int workFactor = 12) returns string|Error = @java:Method {
    name: "generateSalt",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Password"
} external;