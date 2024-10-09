/*
 * Copyright (c) 2024 WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
package io.ballerina.stdlib.crypto;

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.values.BObject;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;

import static io.ballerina.stdlib.crypto.Constants.COMPRESSED_DATA_GENERATOR;
import static io.ballerina.stdlib.crypto.Constants.DATA_STREAM;
import static io.ballerina.stdlib.crypto.Constants.ENCRYPTED_OUTPUT_STREAM;
import static io.ballerina.stdlib.crypto.Constants.PIPED_INPUT_STREAM;
import static io.ballerina.stdlib.crypto.Constants.PIPED_OUTPUT_STREAM;
import static io.ballerina.stdlib.crypto.Constants.TARGET_STREAM;

/**
 * Provides functionality for PGP encryption operations.
 *
 * @since 2.7.0
 */
public class PgpEncryptionGenerator {

    static {
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final int compressionAlgorithm;
    private final int symmetricKeyAlgorithm;
    private final boolean armor;
    private final boolean withIntegrityCheck;
    public static final int BUFFER_SIZE = 8192;

    // The constructor of the PGP encryption generator.
    public PgpEncryptionGenerator(int compressionAlgorithm, int symmetricKeyAlgorithm, boolean armor,
                             boolean withIntegrityCheck) {
        this.compressionAlgorithm = compressionAlgorithm;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.armor = armor;
        this.withIntegrityCheck = withIntegrityCheck;
    }

    private void encryptStream(OutputStream encryptOut, InputStream clearIn, InputStream publicKeyIn)
            throws IOException, PGPException {
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(compressionAlgorithm);
        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
                // Configure the encrypted data generator
                new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );
        // Add public key
        pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(
                getPublicKey(publicKeyIn)));
        if (armor) {
            encryptOut = new ArmoredOutputStream(encryptOut);
        }

        try (OutputStream cipherOutStream = pgpEncryptedDataGenerator.open(encryptOut, new byte[BUFFER_SIZE])) {
            copyAsLiteralData(compressedDataGenerator.open(cipherOutStream), clearIn);
            compressedDataGenerator.close();
        }
        encryptOut.close();
    }

    public void encryptStream(InputStream publicKeyIn, BObject iteratorObj)
            throws IOException, PGPException {
        OutputStream encryptOut = new PipedOutputStream();
        iteratorObj.addNativeData(PIPED_OUTPUT_STREAM, encryptOut);
        PipedInputStream pipedInputStream = new PipedInputStream((PipedOutputStream) encryptOut,
                PgpEncryptionGenerator.BUFFER_SIZE);
        iteratorObj.addNativeData(PIPED_INPUT_STREAM, pipedInputStream);
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(compressionAlgorithm);
        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
                // Configure the encrypted data generator
                new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );
        // Add public key
        pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(
                getPublicKey(publicKeyIn)));
        if (armor) {
            encryptOut = new ArmoredOutputStream(encryptOut);
        }

        iteratorObj.addNativeData(ENCRYPTED_OUTPUT_STREAM, encryptOut);
        OutputStream cipherOutStream = pgpEncryptedDataGenerator.open(encryptOut, new byte[BUFFER_SIZE]);
        OutputStream compressedOutStream = compressedDataGenerator.open(cipherOutStream);
        iteratorObj.addNativeData(DATA_STREAM, cipherOutStream);
        iteratorObj.addNativeData(COMPRESSED_DATA_GENERATOR, compressedDataGenerator);
        copyAsLiteralData(compressedOutStream, iteratorObj);
    }

    // Encrypts the given byte array of plain text data using PGP encryption.
    public Object encrypt(byte[] clearData, InputStream publicKeyIn) throws PGPException, IOException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(clearData);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            encryptStream(outputStream, inputStream, publicKeyIn);
            return ValueCreator.createArrayValue(outputStream.toByteArray());
        }
    }

    public void encrypt(InputStream inputStream, InputStream publicKeyIn, String outputPath)
            throws PGPException, IOException {
        try (OutputStream outputStream = Files.newOutputStream(Path.of(outputPath))) {
            encryptStream(outputStream, inputStream, publicKeyIn);
        }
    }

    private static PGPPublicKey getPublicKey(InputStream keyInputStream) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRings.getKeyRings();
        while (keyRingIterator.hasNext()) {
            PGPPublicKeyRing pgpPublicKeyRing = keyRingIterator.next();
            Optional<PGPPublicKey> pgpPublicKey = extractPgpKeyFromRing(pgpPublicKeyRing);
            if (pgpPublicKey.isPresent()) {
                return pgpPublicKey.get();
            }
        }
        throw new PGPException("Invalid public key");
    }

    private static void copyAsLiteralData(OutputStream outputStream, InputStream in)
            throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        byte[] buff = new byte[BUFFER_SIZE];
        try (OutputStream pOut = lData.open(outputStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[BUFFER_SIZE]);
             InputStream inputStream = in) {

            int len;
            while ((len = inputStream.read(buff)) > 0) {
                pOut.write(buff, 0, len);
            }
        } finally {
            Arrays.fill(buff, (byte) 0);
        }
    }

    private static void copyAsLiteralData(OutputStream outputStream, BObject iteratorObj)
            throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(outputStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[BUFFER_SIZE]);
        iteratorObj.addNativeData(TARGET_STREAM, pOut);
    }

    private static Optional<PGPPublicKey> extractPgpKeyFromRing(PGPPublicKeyRing pgpPublicKeyRing) {
        for (PGPPublicKey publicKey : pgpPublicKeyRing) {
            if (publicKey.isEncryptionKey()) {
                return Optional.of(publicKey);
            }
        }
        return Optional.empty();
    }
}
