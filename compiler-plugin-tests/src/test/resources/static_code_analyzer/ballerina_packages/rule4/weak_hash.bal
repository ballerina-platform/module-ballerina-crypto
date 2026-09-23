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

function weakHashes(string data) {
    byte[] _ = crypto:hashMd5(data.toBytes());
    byte[] _ = crypto:hashSha1(data.toBytes());
}

function weakHmacs(string data, byte[] key) {
    byte[] _ = crypto:hmacMd5(data.toBytes(), key);
    byte[] _ = crypto:hmacSha1(data.toBytes(), key);
}

// Negative cases - these algorithms are not flagged
function strongHashes(string data, byte[] key) {
    byte[] _ = crypto:hashSha256(data.toBytes());
    byte[] _ = crypto:hashSha512(data.toBytes());
    byte[] _ = crypto:hmacSha256(data.toBytes(), key);
}
