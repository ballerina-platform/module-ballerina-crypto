import ballerina/jballerina.java;

class DecryptedStreamIterator {
    boolean isClosed = false;

    public isolated function next() returns record {|byte[] value;|}|Error? {
        byte[]|Error? bytes = self.readDecryptedStream();
        if bytes is byte[] {
            return {value: bytes};
        } else {
            return bytes;
        }
    }

    public isolated function close() returns Error? {
        if !self.isClosed {
            var closeResult = self.closeDecryptedStream();
            if closeResult is () {
                self.isClosed = true;
            }
            return closeResult;
        }
        return;
    }

    isolated function readDecryptedStream() returns byte[]|Error? = @java:Method {
        'class: "io.ballerina.stdlib.crypto.nativeimpl.StreamUtils"
    } external;

    isolated function closeDecryptedStream() returns Error? = @java:Method {
        'class: "io.ballerina.stdlib.crypto.nativeimpl.StreamUtils"
    } external;
}

class EncryptedStreamIterator {
    boolean isClosed = false;

    public isolated function next() returns record {|byte[] value;|}|Error? {
        byte[]|Error? bytes = self.readEncryptedStream();
        if bytes is byte[] {
            return {value: bytes};
        } else {
            return bytes;
        }
    }

    public isolated function close() returns Error? {
        if !self.isClosed {
            var closeResult = self.closeEncryptedStream();
            if closeResult is () {
                self.isClosed = true;
            }
            return closeResult;
        }
        return;
    }

    isolated function readEncryptedStream() returns byte[]|Error? = @java:Method {
        'class: "io.ballerina.stdlib.crypto.nativeimpl.StreamUtils"
    } external;

    isolated function closeEncryptedStream() returns Error? = @java:Method {
        'class: "io.ballerina.stdlib.crypto.nativeimpl.StreamUtils"
    } external;
}
