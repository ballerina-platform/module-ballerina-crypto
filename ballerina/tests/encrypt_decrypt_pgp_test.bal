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

import ballerina/io;
import ballerina/test;

@test:Config {}
isolated function testEncryptAndDecryptWithPgp() returns error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] passphrase = "qCr3bv@5mj5n4eY".toBytes();
    byte[] cipherText = check encryptPgp(message, PGP_PUBLIC_KEY_PATH);
    byte[] plainText = check decryptPgp(cipherText, PGP_PRIVATE_KEY_PATH, passphrase);
    test:assertEquals(plainText.toBase16(), message.toBase16());
}

@test:Config {}
isolated function testEncryptAndDecryptWithPgpWithOptions() returns error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] passphrase = "qCr3bv@5mj5n4eY".toBytes();
    byte[] cipherText = check encryptPgp(message, PGP_PUBLIC_KEY_PATH, symmetricKeyAlgorithm = AES_128, armor = false);
    byte[] plainText = check decryptPgp(cipherText, PGP_PRIVATE_KEY_PATH, passphrase);
    test:assertEquals(plainText.toBase16(), message.toBase16());
}

@test:Config {}
isolated function testNegativeEncryptAndDecryptWithPgpInvalidPrivateKey() returns error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] passphrase = "p7S5@T2MRFD9TQb".toBytes();
    byte[] cipherText = check encryptPgp(message, PGP_PUBLIC_KEY_PATH);
    byte[]|Error plainText = decryptPgp(cipherText, PGP_INVALID_PRIVATE_KEY_PATH, passphrase);
    if plainText is Error {
        test:assertEquals(plainText.message(), "Error occurred while PGP decrypt: Could Not Extract private key");
    } else {
        test:assertFail("Should return a crypto Error");
    }
}

@test:Config {}
isolated function testNegativeEncryptAndDecryptWithPgpInvalidPassphrase() returns error? {
    byte[] message = "Ballerina crypto test           ".toBytes();
    byte[] passphrase = "p7S5@T2MRFD9TQb".toBytes();
    byte[] cipherText = check encryptPgp(message, PGP_PUBLIC_KEY_PATH);
    byte[]|Error plainText = decryptPgp(cipherText, PGP_PRIVATE_KEY_PATH, passphrase);
    if plainText is Error {
        test:assertEquals(plainText.message(),
                "Error occurred while PGP decrypt: checksum mismatch at in checksum of 20 bytes");
    } else {
        test:assertFail("Should return a crypto Error");
    }
}

@test:Config {
    serialExecution: true
}
isolated function testEncryptAndDecryptFileWithPgp() returns error? {
    byte[] passphrase = "qCr3bv@5mj5n4eY".toBytes();
    check encryptPgpAsFile(SAMPLE_TEXT, PGP_PUBLIC_KEY_PATH, TARGET_ENCRYPTION_OUTPUT);
    check decryptPgpAsFile(TARGET_ENCRYPTION_OUTPUT, PGP_PRIVATE_KEY_PATH, passphrase, TARGET_DECRYPTION_OUTPUT);
    test:assertTrue(check isSameFileContent(SAMPLE_TEXT, TARGET_DECRYPTION_OUTPUT));
}

@test:Config {
    serialExecution: true
}
isolated function testEncryptAndDecryptFileWithPgpWithOptions() returns error? {
    byte[] passphrase = "qCr3bv@5mj5n4eY".toBytes();
    check encryptPgpAsFile(SAMPLE_TEXT, PGP_PUBLIC_KEY_PATH, TARGET_ENCRYPTION_OUTPUT, symmetricKeyAlgorithm = AES_128, armor = false);
    check decryptPgpAsFile(TARGET_ENCRYPTION_OUTPUT, PGP_PRIVATE_KEY_PATH, passphrase, TARGET_DECRYPTION_OUTPUT);
    test:assertTrue(check isSameFileContent(SAMPLE_TEXT, TARGET_DECRYPTION_OUTPUT));
}

@test:Config {
    serialExecution: true
}
isolated function testNegativeEncryptAndDecryptFileWithPgpInvalidPrivateKey() returns error? {
    byte[] passphrase = "p7S5@T2MRFD9TQb".toBytes();
    check encryptPgpAsFile(SAMPLE_TEXT, PGP_PUBLIC_KEY_PATH, TARGET_ENCRYPTION_OUTPUT);
    error? err = decryptPgpAsFile(TARGET_ENCRYPTION_OUTPUT, PGP_INVALID_PRIVATE_KEY_PATH, passphrase, TARGET_DECRYPTION_OUTPUT);
    if err is Error {
        test:assertEquals(err.message(), "Error occurred while PGP decrypt: Could Not Extract private key");
    } else {
        test:assertFail("Should return a crypto Error");
    }
}

@test:Config {
    serialExecution: true
}
isolated function testNegativeEncryptAndDecryptFileWithPgpInvalidPassphrase() returns error? {
    byte[] passphrase = "p7S5@T2MRFD9TQb".toBytes();
    check encryptPgpAsFile(SAMPLE_TEXT, PGP_PUBLIC_KEY_PATH, TARGET_ENCRYPTION_OUTPUT);
    error? err = decryptPgpAsFile(TARGET_ENCRYPTION_OUTPUT, PGP_PRIVATE_KEY_PATH, passphrase, TARGET_DECRYPTION_OUTPUT);
    if err is Error {
        test:assertEquals(err.message(),
                "Error occurred while PGP decrypt: checksum mismatch at in checksum of 20 bytes");
    } else {
        test:assertFail("Should return a crypto Error");
    }
}

isolated function isSameFileContent(string inputFilePath, string outputFilePath) returns boolean|error {
    byte[] input = check io:fileReadBytes(inputFilePath);
    byte[] output = check io:fileReadBytes(outputFilePath);
    return input == output;
}
