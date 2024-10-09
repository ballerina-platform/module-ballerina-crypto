package io.ballerina.stdlib.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.Queue;

/**
 * Represents a pipe that can be used to connect an output stream to an input stream.
 * This Pipe implementation assumes the output stream write and input stream read operations are done
 * sequentially in the same thread and the output stream should be closed after writing is done.
 *
 * @since 2.8.0
 */
public class SequentialBufferedPipe {

    Queue<Byte> buffer = new LinkedList<>();
    boolean outputClosed = false;

    public InputStream getInputStream() {
        return new InputStream() {
            @Override
            public int read() {
                if (buffer.isEmpty()) {
                    if (outputClosed) {
                        return -1;
                    }
                    // This should not be reached with respect to the assumption
                    return 0;
                }
                return buffer.poll() & 0xFF;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                if (buffer.isEmpty()) {
                    if (outputClosed) {
                        return -1;
                    }
                    return 0;
                }
                int i = 0;
                while (i < len && !buffer.isEmpty()) {
                    b[off + i] = buffer.poll();
                    i++;
                }
                return i;
            }
        };
    }

    public OutputStream getOutputStream() {
        return new OutputStream() {
            @Override
            public void write(int b) {
                buffer.add((byte) b);
            }

            @Override
            public void write(byte[] b, int off, int len) {
                for (int i = off; i < off + len; i++) {
                    buffer.add(b[i]);
                }
            }

            @Override
            public void close() {
                outputClosed = true;
            }
        };
    }
}
