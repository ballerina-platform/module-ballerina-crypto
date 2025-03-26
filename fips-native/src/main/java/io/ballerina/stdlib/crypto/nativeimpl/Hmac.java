/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

/**
 * Extern functions ballerina hmac algorithms.
 *
 * @since 0.990.3
 */
public class Hmac {

    private Hmac() {}

    public static Object hmacMd5(BArray inputValue, BArray keyValue) {
        return CryptoUtils.hmac("HmacMD5", keyValue.getBytes(), inputValue.getBytes());
    }

    public static Object hmacSha1(BArray inputValue, BArray keyValue) {
        return CryptoUtils.hmac("HmacSHA1", keyValue.getBytes(), inputValue.getBytes());
    }

    public static Object hmacSha256(BArray inputValue, BArray keyValue) {
        return CryptoUtils.hmac("HmacSHA256", keyValue.getBytes(), inputValue.getBytes());
    }

    public static Object hmacSha384(BArray inputValue, BArray keyValue) {
        return CryptoUtils.hmac("HmacSHA384", keyValue.getBytes(), inputValue.getBytes());
    }

    public static Object hmacSha512(BArray inputValue, BArray keyValue) {
        return CryptoUtils.hmac("HmacSHA512", keyValue.getBytes(), inputValue.getBytes());
    }
}
