import ballerina/jballerina.java;

class StreamIterator {
    boolean isClosed = false;

    isolated function next() returns record {|byte[] value;|}|Error? {
        byte[]|Error? bytes = self.read();
        if bytes is byte[] {
            return {value: bytes};
        } else {
            return bytes;
        }
    }

    isolated function close() returns Error? {
        if !self.isClosed {
            var closeResult = self.closeStream();
            if closeResult is () {
                self.isClosed = true;
            }
            return closeResult;
        }
        return;
    }

    isolated function read() returns byte[]|Error? = @java:Method {
        'class: "io.ballerina.stdlib.crypto.nativeimpl.StreamUtils"
    } external;

    isolated function closeStream() returns Error? = @java:Method {
        'class: "io.ballerina.stdlib.crypto.nativeimpl.StreamUtils"
    } external;
}
