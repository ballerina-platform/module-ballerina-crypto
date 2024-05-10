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

# Represents the PGP encryption options.
# 
# + compressionAlgorithm - Specifies the compression algorithm used for PGP encryption
# + symmetricKeyAlgorithm - Specifies the symmetric key algorithm used for encryption
# + armor - Indicates whether ASCII armor is enabled for the encrypted output
# + withIntegrityCheck - Indicates whether integrity check is included in the encryption
public type PgpEncryptionOptions record {|
    CompressionAlgorithmTags compressionAlgorithm = ZIP;
    SymmetricKeyAlgorithmTags symmetricKeyAlgorithm = AES_256;
    boolean armor = true;
    boolean withIntegrityCheck = true;
|};

# Represents the compression algorithms available in PGP.
# 
# + UNCOMPRESSED - No compression
# + ZIP - Uses (RFC 1951) compression
# + ZLIB - Uses (RFC 1950) compression
# + BZIP2 - Uses Burrows–Wheeler algorithm
public enum CompressionAlgorithmTags {
    UNCOMPRESSED = "0",
    ZIP = "1",
    ZLIB = "2",
    BZIP2= "3"
}

# Represent the symmetric key algorithms available in PGP.
# 
# + NULL - No encryption
# + IDEA - IDEA symmetric key algorithm
# + TRIPLE_DES - Triple DES symmetric key algorithm
# + CAST5 - CAST5 symmetric key algorithm
# + BLOWFISH - Blowfish symmetric key algorithm
# + SAFER - SAFER symmetric key algorithm
# + DES - DES symmetric key algorithm
# + AES_128 - AES 128-bit symmetric key algorithm
# + AES_192 - AES 192-bit symmetric key algorithm
# + AES_256 - AES 256-bit symmetric key algorithm
# + TWOFISH - Twofish symmetric key algorithm
# + CAMELLIA_128 - Camellia 128-bit symmetric key algorithm
# + CAMELLIA_192 - Camellia 192-bit symmetric key algorithm
# + CAMMELIA_256 - Camellia 256-bit symmetric key algorithm
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
