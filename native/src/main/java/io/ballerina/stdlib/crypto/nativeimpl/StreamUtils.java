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
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.stdlib.crypto.CryptoUtils;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

import static io.ballerina.stdlib.crypto.Constants.COMPRESSED_DATA_GENERATOR;
import static io.ballerina.stdlib.crypto.Constants.ENCRYPTED_OUTPUT_STREAM;
import static io.ballerina.stdlib.crypto.Constants.END_OF_INPUT_STREAM;
import static io.ballerina.stdlib.crypto.Constants.INPUT_STREAM_TO_ENCRYPT;
import static io.ballerina.stdlib.crypto.Constants.KEY_ENCRYPTED_DATA;
import static io.ballerina.stdlib.crypto.Constants.PIPED_INPUT_STREAM;
import static io.ballerina.stdlib.crypto.Constants.COMPRESSED_DATA_STREAM;
import static io.ballerina.stdlib.crypto.Constants.DATA_STREAM;
import static io.ballerina.stdlib.crypto.Constants.PIPED_OUTPUT_STREAM;
import static io.ballerina.stdlib.crypto.Constants.TARGET_STREAM;
import static io.ballerina.stdlib.crypto.PgpEncryptionGenerator.BUFFER_SIZE;

/**
 * Provides functionality for stream operations.
 *
 * @since 2.8.0
 */
public final class StreamUtils {

    public static final String STREAM_NOT_AVAILABLE = "Stream is not available";
    public static final String ERROR_OCCURRED_WHILE_CLOSING_THE_STREAM = "Error occurred while closing the stream: %s";
    public static final String ERROR_OCCURRED_WHILE_CLOSING_THE_GENERATOR = "Error occurred while closing the " +
            "generator: %s";
    public static final String ERROR_OCCURRED_WHILE_READING_THE_STREAM = "Error occurred while reading from the " +
            "stream: %s";
    public static final String NATIVE_DATA_NOT_AVAILABLE_ERROR = "%s is not available";
    public static final String MESSAGE_FAILED_INTEGRITY_CHECK = "Message failed integrity check";
    public static final String ERROR_OCCURRED_WHILE_VERIFYING_THE_INTEGRITY = "Error occurred while verifying the" +
            " integrity: %s";
    public static final String ERROR_OCCURRED_WHILE_READING_FROM_THE_STREAM = "Error occurred while reading from " +
            "the stream: %s";

    private StreamUtils() {
    }

    public static Object readDecryptedStream(BObject iterator) {
        Object stream = iterator.getNativeData(TARGET_STREAM);
        if (Objects.isNull(stream) || !(stream instanceof InputStream inputStream)) {
            return CryptoUtils.createError(String.format(NATIVE_DATA_NOT_AVAILABLE_ERROR, TARGET_STREAM));
        }
        try {
            byte[] buffer = new byte[BUFFER_SIZE];
            int in = inputStream.read(buffer);
            if (in == -1) {
                closeNativeStream(iterator, TARGET_STREAM);
                performIntegrityCheck(iterator);
                return null;
            }
            if (in < buffer.length) {
                byte[] temp = new byte[in];
                System.arraycopy(buffer, 0, temp, 0, in);
                return ValueCreator.createArrayValue(temp);
            }
            return ValueCreator.createArrayValue(buffer);
        } catch (IOException e) {
            return CryptoUtils.createError(String.format(ERROR_OCCURRED_WHILE_READING_FROM_THE_STREAM,
                    e.getMessage()));
        }
    }

    private static void performIntegrityCheck(BObject iterator) throws IOException {
        Object publicKeyEncryptedDataObj = iterator.getNativeData(KEY_ENCRYPTED_DATA);
        if (Objects.isNull(publicKeyEncryptedDataObj) || !(publicKeyEncryptedDataObj instanceof
                PGPPublicKeyEncryptedData publicKeyEncryptedData)) {
            throw CryptoUtils.createError(STREAM_NOT_AVAILABLE);
        }
        try {
            if (publicKeyEncryptedData.isIntegrityProtected() && !publicKeyEncryptedData.verify()) {
                throw CryptoUtils.createError(MESSAGE_FAILED_INTEGRITY_CHECK);
            }
        } catch (PGPException e) {
            throw CryptoUtils.createError(String.format(ERROR_OCCURRED_WHILE_VERIFYING_THE_INTEGRITY, e.getMessage()));
        }
    }

    public static Object readEncryptedStream(BObject iterator) {
        NativeData nativeData = getNativeData(iterator);

        try {
            if (Boolean.FALSE.equals(nativeData.endOfStream())) {
                writeToOutStream(iterator, nativeData.inputStream(), nativeData.outputStream());
            }
            return readFromPipedStream(iterator, nativeData.pipedInStream());
        } catch (IOException e) {
            return CryptoUtils.createError(String.format(ERROR_OCCURRED_WHILE_READING_THE_STREAM, e.getMessage()));
        } catch (BError e) {
            return e;
        }
    }

    private static NativeData getNativeData(BObject iterator) {
        Object inputStreamToEncrypt = iterator.getNativeData(INPUT_STREAM_TO_ENCRYPT);
        if (Objects.isNull(inputStreamToEncrypt) || !(inputStreamToEncrypt instanceof InputStream inputStream)) {
            throw CryptoUtils.createError(String.format(NATIVE_DATA_NOT_AVAILABLE_ERROR, INPUT_STREAM_TO_ENCRYPT));
        }

        Object targetStream = iterator.getNativeData(TARGET_STREAM);
        if (Objects.isNull(targetStream) || !(targetStream instanceof OutputStream outputStream)) {
            throw CryptoUtils.createError(String.format(NATIVE_DATA_NOT_AVAILABLE_ERROR, TARGET_STREAM));
        }

        Object pipelinedInputStream = iterator.getNativeData(PIPED_INPUT_STREAM);
        if (Objects.isNull(pipelinedInputStream) || !(pipelinedInputStream instanceof InputStream pipedInStream)) {
            throw CryptoUtils.createError(String.format(NATIVE_DATA_NOT_AVAILABLE_ERROR, PIPED_INPUT_STREAM));
        }

        Object endOfInputStream = iterator.getNativeData(END_OF_INPUT_STREAM);
        if (Objects.isNull(endOfInputStream) || !(endOfInputStream instanceof Boolean endOfStream)) {
            throw CryptoUtils.createError(String.format(NATIVE_DATA_NOT_AVAILABLE_ERROR, END_OF_INPUT_STREAM));
        }
        return new NativeData(inputStream, outputStream, pipedInStream, endOfStream);
    }

    private record NativeData(InputStream inputStream, OutputStream outputStream, InputStream pipedInStream,
                              Boolean endOfStream) {
    }

    private static BArray readFromPipedStream(BObject iterator, InputStream pipedInStream) throws IOException {
        byte[] pipelinedBuffer = new byte[BUFFER_SIZE];
        int pipelinedIn = pipedInStream.read(pipelinedBuffer);
        if (pipelinedIn == -1) {
            closeNativeStream(iterator, PIPED_INPUT_STREAM);
            return null;
        }
        if (pipelinedIn < pipelinedBuffer.length) {
            byte[] temp = new byte[pipelinedIn];
            System.arraycopy(pipelinedBuffer, 0, temp, 0, pipelinedIn);
            return ValueCreator.createArrayValue(temp);
        }
        return ValueCreator.createArrayValue(pipelinedBuffer);
    }

    private static void writeToOutStream(BObject iterator, InputStream inputStream, OutputStream outputStream)
            throws IOException {
        byte[] inputBuffer = new byte[BUFFER_SIZE];
        int result = inputStream.read(inputBuffer);
        if (result == -1) {
            iterator.addNativeData(END_OF_INPUT_STREAM, true);
            closeEncryptedSourceStreams(iterator);
        }
        if (result > 0) {
            outputStream.write(inputBuffer, 0, result);
        }
    }

    public static void closeDecryptedStream(BObject iterator) throws BError {
        closeNativeStream(iterator, TARGET_STREAM);
        closeNativeStream(iterator, COMPRESSED_DATA_STREAM);
        closeNativeStream(iterator, DATA_STREAM);
    }

    public static void closeEncryptedStream(BObject iterator) throws BError {
        closeNativeStream(iterator, TARGET_STREAM);
        closeNativeStream(iterator, COMPRESSED_DATA_STREAM);
        closeDataGenerator(iterator);
        closeNativeStream(iterator, DATA_STREAM);
        closeNativeStream(iterator, ENCRYPTED_OUTPUT_STREAM);
        closeNativeStream(iterator, PIPED_OUTPUT_STREAM);
        closeNativeStream(iterator, PIPED_INPUT_STREAM);
    }

    public static void closeEncryptedSourceStreams(BObject iterator) throws BError {
        closeNativeStream(iterator, INPUT_STREAM_TO_ENCRYPT);
        closeNativeStream(iterator, TARGET_STREAM);
        closeNativeStream(iterator, COMPRESSED_DATA_STREAM);
        closeDataGenerator(iterator);
        closeNativeStream(iterator, DATA_STREAM);
        closeNativeStream(iterator, ENCRYPTED_OUTPUT_STREAM);
        closeNativeStream(iterator, PIPED_OUTPUT_STREAM);
    }

    public static void closeNativeStream(BObject iterator, String streamName) throws BError {
        Object streamObj = iterator.getNativeData(streamName);
        if (Objects.isNull(streamObj) || !(streamObj instanceof Closeable stream)) {
            throw CryptoUtils.createError(STREAM_NOT_AVAILABLE);
        }
        try {
            stream.close();
        } catch (IOException e) {
            throw CryptoUtils.createError(String.format(ERROR_OCCURRED_WHILE_CLOSING_THE_STREAM, e.getMessage()));
        }
    }

    public static void closeDataGenerator(BObject iterator) throws BError {
        Object generatorObj = iterator.getNativeData(COMPRESSED_DATA_GENERATOR);
        if (Objects.isNull(generatorObj) || !(generatorObj instanceof PGPCompressedDataGenerator generator)) {
            throw CryptoUtils.createError(STREAM_NOT_AVAILABLE);
        }
        try {
            generator.close();
        } catch (IOException e) {
            throw  CryptoUtils.createError(String.format(ERROR_OCCURRED_WHILE_CLOSING_THE_GENERATOR, e.getMessage()));
        }
    }
}
