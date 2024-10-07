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
package io.ballerina.stdlib.crypto;

import io.ballerina.runtime.api.Environment;
import io.ballerina.runtime.api.async.Callback;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BStream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;

/**
 * Represents a Ballerina stream as an {@link InputStream}.
 *
 * @since 2.8.0
 */
public class BallerinaInputStream extends InputStream {
    private final Environment environment;
    private final BStream ballerinaStream;
    private ByteBuffer buffer = null;

    public BallerinaInputStream(Environment environment, BStream ballerinaStream) {
        this.ballerinaStream = ballerinaStream;
        this.environment = environment;
    }

    @Override
    public int read() throws IOException {
        if (Objects.isNull(buffer) || !buffer.hasRemaining()) {
            Object nextElement = getNext();
            if (nextElement instanceof BError) {
                throw new IOException(((BError) nextElement).getMessage());
            }
            if (Objects.isNull(nextElement)) {
                return -1;
            }
            if (nextElement instanceof BMap nextValue) {
                Object nextBytes = nextValue.get(StringUtils.fromString("value"));
                if (nextBytes instanceof BArray) {
                    buffer = ByteBuffer.wrap(((BArray) nextBytes).getBytes());
                } else {
                    throw new IOException("Error occurred while reading the next element from the stream: " +
                            "unexpected value type");
                }
            } else {
                throw new IOException("Error occurred while reading the next element from the stream: " +
                        "unexpected value type");
            }
        }
        return buffer.get() & 0xFF;
    }

    @Override
    public void close() {
        Object result = callBallerinaFunction("close", "Error occurred while closing the stream");
        if (result instanceof BError) {
            throw new RuntimeException(((BError) result).getMessage());
        }
    }

    public Object getNext() {
        return callBallerinaFunction("next", "Error occurred while reading the next element from the stream");
    }

    private Object callBallerinaFunction(String functionName, String message) {
        final Object[] nextResult = new Object[1];
        CountDownLatch countDownLatch = new CountDownLatch(1);
        Callback returnCallback = new StreamCallback(message, nextResult, countDownLatch);

        environment.getRuntime().invokeMethodAsyncSequentially(ballerinaStream.getIteratorObj(), functionName, null,
                null, returnCallback, null, null);
        try {
            countDownLatch.await();
        } catch (InterruptedException exception) {
            return CryptoUtils.createError("Error occurred while reading the next element from the stream: " +
                    "interrupted exception");
        }
        return nextResult[0];
    }

    private record StreamCallback(String message, Object[] nextResult,
                                  CountDownLatch countDownLatch) implements Callback {

        @Override
        public void notifySuccess(Object result) {
            nextResult[0] = result;
            countDownLatch.countDown();
        }

        @Override
        public void notifyFailure(BError bError) {
            BError error = CryptoUtils.createError(String.format("%s: %s", message, bError.getMessage()));
            nextResult[0] = error;
            countDownLatch.countDown();
        }
    }
}

