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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;

/**
 * Provides functionality for PGP decryption operations.
 *
 * @since 2.7.0
 */
public final class PgpDecryptionGenerator {

    static {
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final char[] passCode;
    private final PGPSecretKeyRingCollection pgpSecretKeyRingCollection;

    // The constructor of the PGP decryption generator.
    public PgpDecryptionGenerator(InputStream privateKeyIn, byte[] passCode) throws IOException, PGPException {
        this.passCode = new String(passCode, StandardCharsets.UTF_8).toCharArray();
        this.pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyIn)
                , new JcaKeyFingerprintCalculator());
    }

    private Optional<PGPPrivateKey> findSecretKey(long keyID) throws PGPException {
        Optional<PGPSecretKey> pgpSecretKey = Optional.ofNullable(pgpSecretKeyRingCollection.getSecretKey(keyID));
        if (pgpSecretKey.isPresent()) {
            PGPPrivateKey privateKey = pgpSecretKey.get().extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder()
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                            .build(passCode));
            return Optional.of(privateKey);
        } else {
            return Optional.empty();
        }
    }

    private void decryptStream(InputStream encryptedIn, OutputStream clearOut)
            throws PGPException, IOException {
        // Remove armour and return the underlying binary encrypted stream
        encryptedIn = PGPUtil.getDecoderStream(encryptedIn);
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encryptedIn);

        Object obj = pgpObjectFactory.nextObject();
        // Verify the marker packet
        PGPEncryptedDataList pgpEncryptedDataList = (obj instanceof PGPEncryptedDataList)
                ? (PGPEncryptedDataList) obj : (PGPEncryptedDataList) pgpObjectFactory.nextObject();

        Optional<PGPPrivateKey> pgpPrivateKey = Optional.empty();
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;

        Iterator<PGPEncryptedData> encryptedDataItr = pgpEncryptedDataList.getEncryptedDataObjects();
        while (pgpPrivateKey.isEmpty() && encryptedDataItr.hasNext()) {
            publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataItr.next();
            pgpPrivateKey = findSecretKey(publicKeyEncryptedData.getKeyID());
        }

        if (Objects.isNull(publicKeyEncryptedData)) {
            throw new PGPException("Could not generate PGPPublicKeyEncryptedData object");
        }

        if (pgpPrivateKey.isEmpty()) {
            throw new PGPException("Could Not Extract private key");
        }
        decrypt(clearOut, pgpPrivateKey, publicKeyEncryptedData);
    }

    // Decrypts the given byte array of encrypted data using PGP decryption.
    public Object decrypt(byte[] encryptedBytes) throws PGPException, IOException {
        try (ByteArrayInputStream encryptedIn = new ByteArrayInputStream(encryptedBytes);
             ByteArrayOutputStream clearOut = new ByteArrayOutputStream()) {
            decryptStream(encryptedIn, clearOut);
            return ValueCreator.createArrayValue(clearOut.toByteArray());
        }
    }

    private static void decrypt(OutputStream clearOut, Optional<PGPPrivateKey> pgpPrivateKey,
                        PGPPublicKeyEncryptedData publicKeyEncryptedData) throws IOException, PGPException {
        if (pgpPrivateKey.isPresent()) {
            PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pgpPrivateKey.get());
            try (InputStream decryptedCompressedIn = publicKeyEncryptedData.getDataStream(decryptorFactory)) {

                JcaPGPObjectFactory decCompObjFac = new JcaPGPObjectFactory(decryptedCompressedIn);
                PGPCompressedData pgpCompressedData = (PGPCompressedData) decCompObjFac.nextObject();

                try (InputStream compressedDataStream = new BufferedInputStream(pgpCompressedData.getDataStream())) {
                    JcaPGPObjectFactory pgpCompObjFac = new JcaPGPObjectFactory(compressedDataStream);

                    Object message = pgpCompObjFac.nextObject();

                    if (message instanceof PGPLiteralData pgpLiteralData) {
                        try (InputStream decDataStream = pgpLiteralData.getInputStream()) {
                            byte[] buffer = new byte[1024];
                            int bytesRead;
                            while ((bytesRead = decDataStream.read(buffer)) != -1) {
                                clearOut.write(buffer, 0, bytesRead);
                            }
                        }
                    } else if (message instanceof PGPOnePassSignatureList) {
                        throw new PGPException("Encrypted message contains a signed message not literal data");
                    } else {
                        throw new PGPException("Unknown message type encountered during decryption");
                    }
                }
            }
            // Perform the integrity check
            if (publicKeyEncryptedData.isIntegrityProtected()) {
                if (!publicKeyEncryptedData.verify()) {
                    throw new PGPException("Message failed integrity check");
                }
            }
        }
    }
}
