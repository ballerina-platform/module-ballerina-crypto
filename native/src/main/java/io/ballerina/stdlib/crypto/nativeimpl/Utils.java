/*
 * Copyright (c) 2026 WSO2 LLC. (https://www.wso2.com).
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

import java.security.MessageDigest;

/**
 * Functions for constant-time comparison operations.
 *
 * @since 2.11.0
 */
public final class Utils {

    private Utils() {}

    /**
     * Compares two byte arrays in constant time.
     *
     * @param value         the Ballerina byte array to compare
     * @param expectedValue the Ballerina byte array to compare against
     * @return {@code true} if both arrays have the same length and content,
     *         {@code false} otherwise
     */
    public static boolean equalByteConstantTime(BArray value, BArray expectedValue) {
        byte[] valueBytes = value.getBytes();
        byte[] expectedBytes = expectedValue.getBytes();
        return MessageDigest.isEqual(valueBytes, expectedBytes);
    }
}
