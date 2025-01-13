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

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.CryptoUtils;

import java.util.zip.CRC32;
import java.util.zip.Checksum;

/**
 * Extern functions ballerina hashing algorithms.
 *
 * @since 0.990.3
 */
public class Hash {

    private Hash() {}

    public static BString crc32b(BArray input) {
        Checksum checksum = new CRC32();
        byte[] bytes = input.getBytes();
        checksum.update(bytes, 0, bytes.length);
        long checksumVal = checksum.getValue();
        return StringUtils.fromString(Long.toHexString(checksumVal));
    }

    public static BArray hashMd5(BArray inputValue, Object saltValue) {
        return ValueCreator.createArrayValue(CryptoUtils.hash("MD5", inputValue.getBytes(), saltValue));
    }

    public static BArray hashSha1(BArray inputValue, Object saltValue) {
        return ValueCreator.createArrayValue(CryptoUtils.hash("SHA-1", inputValue.getBytes(), saltValue));
    }

    public static BArray hashSha256(BArray inputValue, Object saltValue) {
        return ValueCreator.createArrayValue(CryptoUtils.hash("SHA-256", inputValue.getBytes(), saltValue));
    }

    public static BArray hashSha384(BArray inputValue, Object saltValue) {
        return ValueCreator.createArrayValue(CryptoUtils.hash("SHA-384", inputValue.getBytes(), saltValue));
    }

    public static BArray hashSha512(BArray inputValue, Object saltValue) {
        return ValueCreator.createArrayValue(CryptoUtils.hash("SHA-512", inputValue.getBytes(), saltValue));
    }

    public static BArray hashKeccak256(BArray inputValue, Object saltValue) {
        return ValueCreator.createArrayValue(CryptoUtils.hash("Keccak-256", inputValue.getBytes(), saltValue));
    }

}
