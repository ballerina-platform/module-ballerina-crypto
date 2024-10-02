/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.Constants;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.crypto.PgpDecryptionGenerator;
import org.bouncycastle.openpgp.PGPException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Extern functions ballerina decrypt algorithms.
 *
 * @since 0.990.4
 */
public class Decrypt {

    private Decrypt() {}

    public static Object decryptAesCbc(BArray inputValue, BArray keyValue, BArray ivValue, Object padding) {
        byte[] input = inputValue.getBytes();
        byte[] key = keyValue.getBytes();
        byte[] iv = ivValue.getBytes();
        return CryptoUtils.aesEncryptDecrypt(CryptoUtils.CipherMode.DECRYPT, Constants.CBC, padding.toString(), key,
                input, iv, -1);
    }

    public static Object decryptAesEcb(BArray inputValue, BArray keyValue, Object padding) {
        byte[] input = inputValue.getBytes();
        byte[] key = keyValue.getBytes();
        return CryptoUtils.aesEncryptDecrypt(CryptoUtils.CipherMode.DECRYPT, Constants.ECB, padding.toString(), key,
                input, null, -1);
    }

    public static Object decryptAesGcm(BArray inputValue, BArray keyValue, BArray ivValue,  Object padding,
                                       long tagSize) {
        byte[] input = inputValue.getBytes();
        byte[] key = keyValue.getBytes();
        byte[] iv = ivValue.getBytes();
        return CryptoUtils.aesEncryptDecrypt(CryptoUtils.CipherMode.DECRYPT, Constants.GCM, padding.toString(), key,
                input, iv, tagSize);
    }

    public static Object decryptRsaEcb(BArray inputValue, Object keys, Object padding) {
        byte[] input = inputValue.getBytes();
        BMap<?, ?> keyMap = (BMap<?, ?>) keys;
        Key key;
        if (keyMap.getNativeData(Constants.NATIVE_DATA_PRIVATE_KEY) != null) {
            key = (PrivateKey) keyMap.getNativeData(Constants.NATIVE_DATA_PRIVATE_KEY);
        } else if (keyMap.getNativeData(Constants.NATIVE_DATA_PUBLIC_KEY) != null) {
            key = (PublicKey) keyMap.getNativeData(Constants.NATIVE_DATA_PUBLIC_KEY);
        } else {
            return CryptoUtils.createError("Uninitialized private/public key.");
        }
        return CryptoUtils.rsaEncryptDecrypt(CryptoUtils.CipherMode.DECRYPT, Constants.ECB, padding.toString(), key,
                input, null, -1);
    }

    public static Object decryptPgp(BArray cipherTextValue, BString privateKeyPath, BArray passphrase) {
        byte[] cipherText = cipherTextValue.getBytes();
        byte[] passphraseInBytes = passphrase.getBytes();
        byte[] privateKey;
        try {
            privateKey = Files.readAllBytes(Path.of(privateKeyPath.toString()));
        } catch (IOException e) {
            return CryptoUtils.createError("Error occurred while reading public key: " + e.getMessage());
        }

        try (InputStream keyStream = new ByteArrayInputStream(privateKey)) {
            PgpDecryptionGenerator pgpDecryptionGenerator = new PgpDecryptionGenerator(keyStream, passphraseInBytes);
            return pgpDecryptionGenerator.decrypt(cipherText);
        } catch (IOException | PGPException e) {
            return CryptoUtils.createError("Error occurred while PGP decrypt: " + e.getMessage());
        }
    }

    public static Object decryptPgpAsFile(BString inputFilePath, BString privateKeyPath, BArray passphrase,
                                          BString outputFilePath) {
        byte[] passphraseInBytes = passphrase.getBytes();
        byte[] privateKey;
        try {
            privateKey = Files.readAllBytes(Path.of(privateKeyPath.toString()));
        } catch (IOException e) {
            return CryptoUtils.createError("Error occurred while reading public key: " + e.getMessage());
        }

        try (InputStream keyStream = new ByteArrayInputStream(privateKey);
             InputStream cipherTextStream = Files.newInputStream(Path.of(inputFilePath.toString()))) {
            PgpDecryptionGenerator pgpDecryptionGenerator = new PgpDecryptionGenerator(keyStream, passphraseInBytes);
            pgpDecryptionGenerator.decrypt(cipherTextStream, outputFilePath.getValue());
            return null;
        } catch (IOException | PGPException e) {
            return CryptoUtils.createError("Error occurred while PGP decrypt: " + e.getMessage());
        }
    }
}
