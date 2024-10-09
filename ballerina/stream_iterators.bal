// Copyright (c) 2024 WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

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
