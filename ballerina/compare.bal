// Copyright (c) 2026 WSO2 LLC. (http://www.wso2.com)
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

# Represents a hash value as either a byte array or a string.
public type HashValue byte[]|string;

# Compares two hash values in constant time.
#
# + value - The hash value to compare, provided as a byte array or string
# + expectedValue - The expected hash value to compare against, provided as a byte array or string
# + return - `true` if the two values are equal, `false` otherwise
public isolated function equalConstantTime(HashValue value, HashValue expectedValue)
                                           returns boolean {
    byte[] a = value is string ? value.toBytes() : value;
    byte[] b = expectedValue is string ? expectedValue.toBytes() : expectedValue;
    return equalByteConstantTime(a, b);
}

isolated function equalByteConstantTime(byte[] value, byte[] expectedValue) returns boolean = @java:Method {
    name: "equalByteConstantTime",
    'class: "io.ballerina.stdlib.crypto.nativeimpl.Compare"
} external;
