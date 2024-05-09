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

public type PgpEncryptionOptions record {|
    CompressionAlgorithmTags compressionAlgorithm = ZIP;
    SymmetricKeyAlgorithmTags symmetricKeyAlgorithm = AES_256;
    boolean armor = true;
    boolean withIntegrityCheck = true;
|};

public enum CompressionAlgorithmTags {
    UNCOMPRESSED = "0",
    ZIP = "1",
    ZLIB = "2",
    BZIP2= "3"
}

public enum SymmetricKeyAlgorithmTags {
    NULL = "0",
    IDEA = "1",
    TRIPLE_DES = "2",
    CAST5 = "3",
    BLOWFISH = "4",
    SAFER = "5",
    DES = "6",
    AES_128 = "7",
    AES_192 = "8",
    AES_256 = "9",
    TWOFISH = "10",
    CAMELLIA_128 = "11",
    CAMELLIA_192 = "12",
    CAMELLIA_256 = "13"
}