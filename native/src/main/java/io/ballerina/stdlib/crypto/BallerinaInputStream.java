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
import io.ballerina.runtime.api.types.MethodType;
import io.ballerina.runtime.api.types.ObjectType;
import io.ballerina.runtime.api.types.Type;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BStream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a Ballerina stream as an {@link InputStream}.
 *
 * @since 2.8.0
 */
public class BallerinaInputStream extends InputStream {
    public static final String BAL_STREAM_CLOSE = "close";
    public static final String STREAM_VALUE = "value";
    public static final String BAL_STREAM_NEXT = "next";

    public static final String ERROR_OCCURRED_WHILE_READING_THE_STREAM = "Error occurred while reading the next " +
            "element from the stream";
    public static final String UNEXPECTED_TYPE_ERROR = ERROR_OCCURRED_WHILE_READING_THE_STREAM +
            ": unexpected value type";

    private final Environment environment;
    private final BStream ballerinaStream;
    private ByteBuffer buffer = null;
    private boolean endOfStream = false;
    private final boolean hasCloseMethod;

    public BallerinaInputStream(Environment environment, BStream ballerinaStream) {
        this.ballerinaStream = ballerinaStream;
        this.environment = environment;

        // Implementing a close method for a Ballerina stream is optional
        // There is no Ballerina runtime API to check if the stream has a close method
        // So accessing the iterator object type methods to check if it has a close method
        Type iteratorType = ballerinaStream.getIteratorObj().getOriginalType();
        if (iteratorType instanceof ObjectType iteratorObjectType) {
            MethodType[] methods = iteratorObjectType.getMethods();
            hasCloseMethod = Arrays.stream(methods).anyMatch(method -> method.getName().equals(BAL_STREAM_CLOSE));
        } else {
            hasCloseMethod = false;
        }
    }

    @Override
    public int read() throws IOException {
        if (endOfStream) {
            return -1;
        }
        if (Objects.isNull(buffer) || !buffer.hasRemaining()) {
            boolean result = pollNext();
            if (!result) {
                endOfStream = true;
                return -1;
            }
        }
        return buffer.get() & 0xFF;
    }

    @Override
    public void close() throws IOException {
        if (!hasCloseMethod) {
            return;
        }
        Object result = callBalStreamMethod(BAL_STREAM_CLOSE);
        if (result instanceof BError bError) {
            throw new IOException((bError).getMessage());
        }
    }

    public Object getNext() {
        return callBalStreamMethod(BAL_STREAM_NEXT);
    }

    private Object callBalStreamMethod(String functionName) {
        return environment.getRuntime().callMethod(ballerinaStream.getIteratorObj(), functionName, null);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (endOfStream) {
            return -1;
        }
        if (Objects.isNull(buffer) || !buffer.hasRemaining()) {
            boolean result = pollNext();
            if (!result) {
                endOfStream = true;
                return -1;
            }
        }
        int remaining = buffer.remaining();
        int readLength = Math.min(remaining, len);
        buffer.get(b, off, readLength);
        return readLength;
    }

    private boolean pollNext() throws IOException {
        Object nextElement = getNext();
        if (nextElement instanceof BError bError) {
            throw new IllegalStateException((bError).getMessage());
        }
        if (Objects.isNull(nextElement)) {
            return false;
        }
        if (nextElement instanceof BMap nextValue) {
            Object nextBytes = nextValue.get(StringUtils.fromString(STREAM_VALUE));
            if (nextBytes instanceof BArray nextBytesArray) {
                buffer = ByteBuffer.wrap((nextBytesArray).getBytes());
            } else {
                throw new IOException(UNEXPECTED_TYPE_ERROR);
            }
        } else {
            throw new IOException(UNEXPECTED_TYPE_ERROR);
        }
        return true;
    }
}

