/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.values.BArray;
import io.ballerina.stdlib.crypto.CryptoUtils;

public class Kdf {

    private Kdf() {}

    public static Object hkdfSha256(BArray inputValue, long length, BArray saltValue, BArray infoValue) {

        byte[] input = inputValue.getBytes();
        byte[] salt = saltValue.getBytes();
        byte[] info = infoValue.getBytes();

        return CryptoUtils.hkdf("SHA-256", input, salt, info, (int) length);
    }

}
