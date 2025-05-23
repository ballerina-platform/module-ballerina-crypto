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

import ballerina/crypto as c;
import ballerina/random;

public function aesCbcAsImport() returns error? {
    string dataString = "Hello Ballerina!";
    byte[] data = dataString.toBytes();
    byte[16] key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    foreach int i in 0 ... 15 {
        key[i] = <byte>(check random:createIntInRange(0, 255));
    }
    byte[16] initialVector = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    foreach int i in 0 ... 15 {
        initialVector[i] = <byte>(check random:createIntInRange(0, 255));
    }
    byte[] _ = check c:encryptAesCbc(data, key, initialVector);
}
