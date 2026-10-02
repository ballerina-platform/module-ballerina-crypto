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

import ballerina/crypto;

function discardedInDeclaration(byte[] data, byte[] signature, crypto:PublicKey publicKey) returns error? {
    boolean _ = check crypto:verifyRsaSha256Signature(data, signature, publicKey);
}

function discardedInAssignment(byte[] data, byte[] signature, crypto:PublicKey publicKey) returns error? {
    _ = check crypto:verifyRsaSha512Signature(data, signature, publicKey);
}

// Negative case - the result is bound and acted on
function verificationChecked(byte[] data, byte[] signature, crypto:PublicKey publicKey) returns error? {
    boolean valid = check crypto:verifyRsaSha256Signature(data, signature, publicKey);
    if !valid {
        return error("signature verification failed");
    }
}

// Negative case - the result is handed to another call that acts on it, even though that call's own result is
// discarded
function verificationPassedOn(byte[] data, byte[] signature, crypto:PublicKey publicKey) returns error? {
    boolean _ = check requireValid(check crypto:verifyRsaSha256Signature(data, signature, publicKey));
}

function requireValid(boolean valid) returns boolean|error {
    if !valid {
        return error("signature verification failed");
    }
    return valid;
}
