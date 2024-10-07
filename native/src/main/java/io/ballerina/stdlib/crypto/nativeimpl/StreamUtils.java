/*
 * Copyright (c) 2024 WSO2 LLC. (https://www.wso2.com).
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

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.stdlib.crypto.CryptoUtils;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import static io.ballerina.stdlib.crypto.Constants.COMPRESSED_PGP_STREAM;
import static io.ballerina.stdlib.crypto.Constants.COMPRESSED_STREAM;
import static io.ballerina.stdlib.crypto.Constants.DECRYPTED_STREAM;

/**
 * Provides functionality for stream operations.
 *
 * @since 2.8.0
 */
public final class StreamUtils {

    private StreamUtils() {
    }

    public static Object read(BObject iterator) {
        Object stream = iterator.getNativeData(DECRYPTED_STREAM);
        if (Objects.isNull(stream) || !(stream instanceof InputStream inputStream)) {
            return CryptoUtils.createError("Stream is not available");
        }
        try {
            byte[] buffer = new byte[4096];
            int in = inputStream.read(buffer);
            if (in == -1) {
                return null;
            }
            if (in < buffer.length) {
                byte[] temp = new byte[in];
                System.arraycopy(buffer, 0, temp, 0, in);
                return ValueCreator.createArrayValue(temp);
            }
            return ValueCreator.createArrayValue(buffer);
        } catch (IOException e) {
            return CryptoUtils.createError("Error occurred while reading from the stream: " + e.getMessage());
        }
    }

    public static Object closeStream(BObject iterator) {
        Object result = closeNativeStream(iterator, DECRYPTED_STREAM);
        // Ignore the errors occurred while closing the compressed streams.
        closeNativeStream(iterator, COMPRESSED_PGP_STREAM);
        closeNativeStream(iterator, COMPRESSED_STREAM);
        return result;
    }

    public static Object closeNativeStream(BObject iterator, String streamName) {
        Object stream = iterator.getNativeData(streamName);
        if (Objects.isNull(stream) || !(stream instanceof InputStream inputStream)) {
            return CryptoUtils.createError("Stream is not available");
        }
        try {
            inputStream.close();
        } catch (IOException e) {
            return CryptoUtils.createError("Error occurred while closing the stream: " + e.getMessage());
        }
        return null;
    }
}
