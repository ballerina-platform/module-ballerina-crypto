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
import wso2/rule3.'module as mod;

const HARDCODED_IV = "constHardcodedIV!";

public function funcHardcodedIV(string data) returns error? {
    byte[16] key = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    byte[] dataBytes = data.toBytes();
    _ = check crypto:encryptAesGcm(dataBytes, key, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    _ = check crypto:encryptAesGcm(dataBytes, key, "hardcodedIV1234".toBytes());
    byte[] iv;
    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    _ = check crypto:encryptAesGcm(dataBytes, key, iv);

    iv = "anotherHardcodedIV".toBytes();
    _ = check crypto:encryptAesGcm(dataBytes, key, iv);

    string ivStr = "dynamicIVValue";
    iv = ivStr.toBytes();
    _ = check crypto:encryptAesGcm(dataBytes, key, iv);

    iv = HARDCODED_IV.toBytes();
    _ = check crypto:encryptAesGcm(dataBytes, key, iv);
    do {
        iv = mod:IV_STRING_VALUE.toBytes();
        _ = check crypto:encryptAesGcm(dataBytes, key, iv);
    }
}

public function funcHardcodedIVNegative(string data) returns error? {
    byte[16] key = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    byte[] dataBytes = data.toBytes();
    // Negative test where we cannot determine at compile time
    byte[] iv = mod:ivStringValue.toBytes();
    _ = check crypto:encryptAesGcm(dataBytes, key, iv);

    // Negative test with conditional assignment which is not supported yet
    if data.length() > 5 {
        iv = "shortIV".toBytes();
    } else {
        iv = "longerHardcodedIV".toBytes();
    }
    _ = check crypto:encryptAesGcm(dataBytes, key, iv);
}
