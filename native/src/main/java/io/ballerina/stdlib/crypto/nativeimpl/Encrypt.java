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

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.runtime.api.values.BValue;
import io.ballerina.stdlib.crypto.Constants;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.crypto.PgpEncryptionGenerator;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Extern functions ballerina encrypt algorithms.
 *
 * @since 0.990.4
 */
public class Encrypt {

    public static final String COMPRESSION_ALGORITHM = "compressionAlgorithm";
    public static final String SYMMETRIC_KEY_ALGORITHM = "symmetricKeyAlgorithm";
    public static final String ARMOR = "armor";
    public static final String WITH_INTEGRITY_CHECK = "withIntegrityCheck";

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

    public static Object encryptPgp(BArray inputValue, BArray keyValue, BMap options) {
        byte[] input = inputValue.getBytes();
        byte[] key = keyValue.getBytes();
        InputStream keyStream = new ByteArrayInputStream(key);

        PgpEncryptionGenerator pgpEncryptionGenerator = new PgpEncryptionGenerator(
                Integer.parseInt(options.get(StringUtils.fromString(COMPRESSION_ALGORITHM)).toString()),
                Integer.parseInt(options.get(StringUtils.fromString(SYMMETRIC_KEY_ALGORITHM)).toString()),
                Boolean.parseBoolean(options.get(StringUtils.fromString(ARMOR)).toString()),
                Boolean.parseBoolean(options.get(StringUtils.fromString(WITH_INTEGRITY_CHECK)).toString())
        );

        try {
            return pgpEncryptionGenerator.encrypt(input, keyStream);
        } catch (PGPException | IOException e) {
            return CryptoUtils.createError("Error occurred while PGP encrypt: " + e.getMessage());
        }
    }
}
