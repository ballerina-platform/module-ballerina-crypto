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

import io.ballerina.runtime.api.Environment;
import io.ballerina.runtime.api.PredefinedTypes;
import io.ballerina.runtime.api.creators.TypeCreator;
import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.types.Type;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BObject;
import io.ballerina.runtime.api.values.BStream;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.BallerinaInputStream;
import io.ballerina.stdlib.crypto.Constants;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.crypto.PgpEncryptionGenerator;
import org.bouncycastle.openpgp.PGPException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import static io.ballerina.stdlib.crypto.Constants.ENCRYPTION_STARTED;
import static io.ballerina.stdlib.crypto.Constants.INPUT_STREAM_TO_ENCRYPT;

/**
 * Extern functions ballerina encrypt algorithms.
 *
 * @since 0.990.4
 */
public class Encrypt {

    private static final BString COMPRESSION_ALGORITHM = StringUtils.fromString("compressionAlgorithm");
    private static final BString SYMMETRIC_KEY_ALGORITHM = StringUtils.fromString("symmetricKeyAlgorithm");
    private static final BString ARMOR = StringUtils.fromString("armor");
    private static final BString WITH_INTEGRITY_CHECK = StringUtils.fromString("withIntegrityCheck");
    public static final String ERROR_OCCURRED_WHILE_READING_PUBLIC_KEY = "Error occurred while reading public key: ";
    public static final String ERROR_OCCURRED_WHILE_PGP_ENCRYPT = "Error occurred while PGP encrypt: ";

    private Encrypt() {}

    public static Object encryptAesCbc(BArray inputValue, BArray keyValue, BArray ivValue, Object padding) {
        byte[] input = inputValue.getBytes();
        byte[] key = keyValue.getBytes();
        byte[] iv = null;
        if (ivValue != null) {
            iv = ivValue.getBytes();
        }
        return CryptoUtils.aesEncryptDecrypt(CryptoUtils.CipherMode.ENCRYPT, Constants.CBC, padding.toString(), key,
                input, iv, -1);
    }

    public static Object encryptAesEcb(BArray inputValue, BArray keyValue,  Object padding) {
        byte[] input = inputValue.getBytes();
        byte[] key = keyValue.getBytes();
        return CryptoUtils.aesEncryptDecrypt(CryptoUtils.CipherMode.ENCRYPT, Constants.ECB, padding.toString(), key,
                input, null, -1);
    }

    public static Object encryptAesGcm(BArray inputValue, BArray keyValue,
                                       BArray ivValue, Object padding, long tagSize) {
        byte[] input = inputValue.getBytes();
        byte[] key = keyValue.getBytes();
        byte[] iv = null;
        if (ivValue != null) {
            iv = ivValue.getBytes();
        }
        return CryptoUtils.aesEncryptDecrypt(CryptoUtils.CipherMode.ENCRYPT, Constants.GCM, padding.toString(), key,
                input, iv, tagSize);
    }

    public static Object encryptRsaEcb(BArray inputValue, Object keys, Object padding) {
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
        return CryptoUtils.rsaEncryptDecrypt(CryptoUtils.CipherMode.ENCRYPT, Constants.ECB, padding.toString(), key,
                input, null, -1);
    }

    public static Object encryptPgp(BArray plainTextValue, BString publicKeyPath, BMap options) {
        byte[] plainText = plainTextValue.getBytes();
        byte[] publicKey;
        try {
            publicKey = Files.readAllBytes(Path.of(publicKeyPath.toString()));
        } catch (IOException e) {
            return CryptoUtils.createError(ERROR_OCCURRED_WHILE_READING_PUBLIC_KEY + e.getMessage());
        }

        try (InputStream publicKeyStream = new ByteArrayInputStream(publicKey)) {
            PgpEncryptionGenerator pgpEncryptionGenerator = new PgpEncryptionGenerator(
                    Integer.parseInt(options.get(COMPRESSION_ALGORITHM).toString()),
                    Integer.parseInt(options.get(SYMMETRIC_KEY_ALGORITHM).toString()),
                    Boolean.parseBoolean(options.get(ARMOR).toString()),
                    Boolean.parseBoolean(options.get(WITH_INTEGRITY_CHECK).toString())
            );
            return pgpEncryptionGenerator.encrypt(plainText, publicKeyStream);
        } catch (IOException | PGPException e) {
            return CryptoUtils.createError(ERROR_OCCURRED_WHILE_PGP_ENCRYPT + e.getMessage());
        }
    }

    public static Object encryptPgpAsFile(BString inputFilePath, BString publicKeyPath, BString outputFilePath,
                                          BMap options) {
        byte[] publicKey;
        try {
            publicKey = Files.readAllBytes(Path.of(publicKeyPath.toString()));
        } catch (IOException e) {
            return CryptoUtils.createError(ERROR_OCCURRED_WHILE_READING_PUBLIC_KEY + e.getMessage());
        }

        try (InputStream publicKeyStream = new ByteArrayInputStream(publicKey);
             InputStream inputStream = Files.newInputStream(Path.of(inputFilePath.toString()))
        ) {
            PgpEncryptionGenerator pgpEncryptionGenerator = new PgpEncryptionGenerator(
                    Integer.parseInt(options.get(COMPRESSION_ALGORITHM).toString()),
                    Integer.parseInt(options.get(SYMMETRIC_KEY_ALGORITHM).toString()),
                    Boolean.parseBoolean(options.get(ARMOR).toString()),
                    Boolean.parseBoolean(options.get(WITH_INTEGRITY_CHECK).toString())
            );
            pgpEncryptionGenerator.encrypt(inputStream, publicKeyStream, outputFilePath.getValue());
            return null;
        } catch (IOException | PGPException e) {
            return CryptoUtils.createError(ERROR_OCCURRED_WHILE_PGP_ENCRYPT + e.getMessage());
        }
    }

    public static Object encryptStreamPgp(Environment environment, BStream inputBalStream, BString publicKeyPath,
                                          BMap options) {
        byte[] publicKey;
        try {
            publicKey = Files.readAllBytes(Path.of(publicKeyPath.toString()));
        } catch (IOException e) {
            return CryptoUtils.createError(ERROR_OCCURRED_WHILE_READING_PUBLIC_KEY + e.getMessage());
        }

        try (InputStream publicKeyStream = new ByteArrayInputStream(publicKey)) {
            InputStream inputStream = new BallerinaInputStream(environment, inputBalStream);
            PgpEncryptionGenerator pgpEncryptionGenerator = new PgpEncryptionGenerator(
                    Integer.parseInt(options.get(COMPRESSION_ALGORITHM).toString()),
                    Integer.parseInt(options.get(SYMMETRIC_KEY_ALGORITHM).toString()),
                    Boolean.parseBoolean(options.get(ARMOR).toString()),
                    Boolean.parseBoolean(options.get(WITH_INTEGRITY_CHECK).toString())
            );
            BObject iteratorObj = ValueCreator.createObjectValue(ModuleUtils.getModule(), "EncryptedStreamIterator");
            iteratorObj.addNativeData(ENCRYPTION_STARTED, false);
            iteratorObj.addNativeData(INPUT_STREAM_TO_ENCRYPT, inputStream);
            pgpEncryptionGenerator.encryptStream(publicKeyStream, iteratorObj);
            Type constrainedType = TypeCreator.createArrayType(PredefinedTypes.TYPE_BYTE);
            return ValueCreator.createStreamValue(TypeCreator.createStreamType(constrainedType), iteratorObj);
        } catch (IOException | PGPException e) {
            return CryptoUtils.createError(ERROR_OCCURRED_WHILE_PGP_ENCRYPT + e.getMessage());
        }
    }
}
