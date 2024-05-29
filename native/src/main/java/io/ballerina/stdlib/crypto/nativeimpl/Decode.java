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

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.Constants;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.time.util.TimeValueHandler;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Extern functions ballerina decoding keys.
 *
 * @since 0.990.3
 */
public class Decode {

    private Decode() {}

    public static Object decodeRsaPrivateKeyFromKeyStore(BMap<BString, BString> keyStoreRecord, BString keyAlias,
                                                         BString keyPassword) {
        Object decodedPrivateKey = getPrivateKey(keyStoreRecord, keyAlias, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildRsPrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    public static Object decodeEcPrivateKeyFromKeyStore(BMap<BString, BString> keyStoreRecord, BString keyAlias,
                                                         BString keyPassword) {

        Object decodedPrivateKey = getPrivateKey(keyStoreRecord, keyAlias, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildEcPrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    public static Object decodeMlDsa65PrivateKeyFromKeyStore(BMap<BString, BString> keyStoreRecord, BString keyAlias,
                                                        BString keyPassword) {

        CryptoUtils.addBCProvider();
        Object decodedPrivateKey = getPrivateKey(keyStoreRecord, keyAlias, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildMlDsa65PrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    public static Object decodeMlKem768PrivateKeyFromKeyStore(BMap<BString, BString> keyStoreRecord, BString keyAlias,
                                                                 BString keyPassword) {
        CryptoUtils.addBCPQCProvider();
        Object decodedPrivateKey = getPrivateKey(keyStoreRecord, keyAlias, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildMlKem768PrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    private static Object getPrivateKey(BMap<BString, BString> keyStoreRecord, BString keyAlias, BString keyPassword) {
        File keyStoreFile = new File(keyStoreRecord.get(Constants.KEY_STORE_RECORD_PATH_FIELD).toString());
        try (FileInputStream fileInputStream = new FileInputStream(keyStoreFile)) {
            KeyStore keyStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE_PKCS12);
            try {
                keyStore.load(fileInputStream, keyStoreRecord.get(Constants.KEY_STORE_RECORD_PASSWORD_FIELD).toString()
                        .toCharArray());
            } catch (NoSuchAlgorithmException e) {
                return CryptoUtils.createError("Keystore integrity check algorithm is not found: " + e.getMessage());
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias.getValue(),
                    keyPassword.getValue().toCharArray());
            if (privateKey == null) {
                return CryptoUtils.createError("Key cannot be recovered by using given key alias: " + keyAlias);
            }
            return privateKey;
        } catch (FileNotFoundException e) {
            return CryptoUtils.createError("PKCS12 KeyStore not found at: " + keyStoreFile.getAbsoluteFile());
        } catch (KeyStoreException | CertificateException | IOException e) {
            return CryptoUtils.createError("Unable to open KeyStore: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            return CryptoUtils.createError("Algorithm for key recovery is not found: " + e.getMessage());
        } catch (UnrecoverableKeyException e) {
            return CryptoUtils.createError("Key cannot be recovered: " + e.getMessage());
        }
    }

    public static Object decodeRsaPrivateKeyFromKeyFile(BString keyFilePath, Object keyPassword) {
        Object decodedPrivateKey = getPrivateKey(keyFilePath, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildRsPrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    public static Object decodeRsaPrivateKeyFromContent(BArray content, Object keyPassword) {
        CryptoUtils.addBCProvider();
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(content.getBytes());
             InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream,
                     StandardCharsets.UTF_8);
             PEMParser pemParser = new PEMParser(inputStreamReader)) {
            Object obj = pemParser.readObject();
            Object decodedPrivateKey = getPrivateKeyInfo(keyPassword, obj);
            if (decodedPrivateKey instanceof PrivateKey privateKey) {
                return buildRsPrivateKeyRecord(privateKey);
            }
            return decodedPrivateKey;
        } catch (IOException | PKCSException e) {
            return CryptoUtils.createError("Unable to do private key operations: " + e.getMessage());
        }
    }

    public static Object decodeEcPrivateKeyFromKeyFile(BString keyFilePath, Object keyPassword) {
        Object decodedPrivateKey = getPrivateKey(keyFilePath, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildEcPrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    public static Object decodeMlDsa65PrivateKeyFromKeyFile(BString keyFilePath, Object keyPassword) {
        Object decodedPrivateKey = getPrivateKey(keyFilePath, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildMlDsa65PrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    public static Object decodeMlKem768PrivateKeyFromKeyFile(BString keyFilePath, Object keyPassword) {
        CryptoUtils.addBCPQCProvider();
        Object decodedPrivateKey = getPrivateKey(keyFilePath, keyPassword);
        if (decodedPrivateKey instanceof PrivateKey privateKey) {
            return buildMlKem768PrivateKeyRecord(privateKey);
        }
        return decodedPrivateKey;
    }

    private static Object getPrivateKey(BString keyFilePath, Object keyPassword) {
        CryptoUtils.addBCProvider();
        File privateKeyFile = new File(keyFilePath.getValue());
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile, StandardCharsets.UTF_8))) {
            Object obj = pemParser.readObject();
            return getPrivateKeyInfo(keyPassword, obj);
        } catch (FileNotFoundException e) {
            return CryptoUtils.createError("Key file not found at: " + privateKeyFile.getAbsoluteFile());
        } catch (PKCSException | IOException e) {
            return CryptoUtils.createError("Unable to do private key operations: " + e.getMessage());
        }
    }

    private static Object getPrivateKeyInfo(Object keyPassword, Object obj) throws IOException, PKCSException {
        PrivateKeyInfo privateKeyInfo;
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        if (obj instanceof PEMEncryptedKeyPair) {
            if (keyPassword == null) {
                return CryptoUtils.createError("Failed to read the encrypted private key without a password.");
            }
            char[] pwd = ((BString) keyPassword).getValue().toCharArray();
            PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pwd);
            PEMKeyPair pemKeyPair = ((PEMEncryptedKeyPair) obj).decryptKeyPair(decryptorProvider);
            privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
        } else if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
            if (keyPassword == null) {
                return CryptoUtils.createError("Failed to read the encrypted private key without a password.");
            }
            char[] pwd = ((BString) keyPassword).getValue().toCharArray();
            InputDecryptorProvider decryptorProvider = new JcePKCSPBEInputDecryptorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pwd);
            privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo) obj).decryptPrivateKeyInfo(decryptorProvider);
        } else if (obj instanceof PEMKeyPair) {
            privateKeyInfo = ((PEMKeyPair) obj).getPrivateKeyInfo();
        } else if (obj instanceof PrivateKeyInfo) {
            privateKeyInfo = (PrivateKeyInfo) obj;
        } else {
            return CryptoUtils.createError("Failed to parse private key information from the given input");
        }
        return converter.getPrivateKey(privateKeyInfo);
    }

    private static Object buildRsPrivateKeyRecord(PrivateKey privateKey) {
        if (privateKey.getAlgorithm().equals(Constants.RSA_ALGORITHM)) {
            return getPrivateKeyRecord(privateKey);
        } else {
            return CryptoUtils.createError("Not a valid RSA key");
        }
    }

    private static Object getPrivateKeyRecord(PrivateKey privateKey) {
        BMap<BString, Object> privateKeyRecord = ValueCreator.
                createRecordValue(ModuleUtils.getModule(), Constants.PRIVATE_KEY_RECORD);
        privateKeyRecord.addNativeData(Constants.NATIVE_DATA_PRIVATE_KEY, privateKey);
        privateKeyRecord.put(StringUtils.fromString(Constants.PRIVATE_KEY_RECORD_ALGORITHM_FIELD),
                             StringUtils.fromString(privateKey.getAlgorithm()));
        return privateKeyRecord;
    }

    private static Object buildEcPrivateKeyRecord(PrivateKey privateKey) {
        if (privateKey.getAlgorithm().startsWith(Constants.EC_ALGORITHM)) {
            return getPrivateKeyRecord(privateKey);
        }
        return CryptoUtils.createError("Not a valid EC key");
    }

    private static Object buildMlDsa65PrivateKeyRecord(PrivateKey privateKey) {
        if (privateKey.getAlgorithm().equals(Constants.MLDSA65_ALGORITHM)) {
            return getPrivateKeyRecord(privateKey);
        } else {
            return CryptoUtils.createError("Not a valid ML-DSA-65 key");
        }
    }

    private static Object buildMlKem768PrivateKeyRecord(PrivateKey privateKey) {
        if (privateKey.getAlgorithm().equals(Constants.MLKEM768_ALGORITHM)) {
            return getPrivateKeyRecord(privateKey);
        } else {
            return CryptoUtils.createError("Not a valid ML-KEM-768 key");
        }
    }

    public static Object decodeRsaPublicKeyFromTrustStore(BMap<BString, BString> trustStoreRecord, BString keyAlias) {
        Object certificate = getPublicKey(trustStoreRecord, keyAlias);
        if (certificate instanceof Certificate publicKey) {
            return buildRsaPublicKeyRecord(publicKey);
        }
        return certificate;
    }

    public static Object decodeEcPublicKeyFromTrustStore(BMap<BString, BString> trustStoreRecord, BString keyAlias) {
        Object certificate = getPublicKey(trustStoreRecord, keyAlias);
        if (certificate instanceof Certificate publicKey) {
            return buildEcPublicKeyRecord(publicKey);
        }
        return certificate;
    }

    public static Object decodeMlDsa65PublicKeyFromTrustStore(BMap<BString, BString> trustStoreRecord,
                                                                 BString keyAlias) {
        CryptoUtils.addBCProvider();
        Object certificate = getPublicKey(trustStoreRecord, keyAlias);
        if (certificate instanceof Certificate publicKey) {
            return buildMlDsa65PublicKeyRecord(publicKey);
        }
        return certificate;
    }

    public static Object decodeMlKem768PublicKeyFromTrustStore(BMap<BString, BString> trustStoreRecord,
                                                                 BString keyAlias) {
        CryptoUtils.addBCPQCProvider();
        Object certificate = getPublicKey(trustStoreRecord, keyAlias);
        if (certificate instanceof Certificate publicKey) {
            return buildMlKem768PublicKeyRecord(publicKey);
        }
        return certificate;
    }

    private static Object getPublicKey(BMap<BString, BString> trustStoreRecord, BString keyAlias) {
        File keyStoreFile = new File(trustStoreRecord.get(Constants.KEY_STORE_RECORD_PATH_FIELD).toString());
        try (FileInputStream fileInputStream = new FileInputStream(keyStoreFile)) {
            KeyStore keyStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE_PKCS12);
            try {
                keyStore.load(fileInputStream, trustStoreRecord.get(Constants.KEY_STORE_RECORD_PASSWORD_FIELD)
                        .toString().toCharArray());
            } catch (NoSuchAlgorithmException e) {
                return CryptoUtils.createError("Keystore integrity check algorithm is not found: " + e.getMessage());
            }

            Certificate certificate = keyStore.getCertificate(keyAlias.getValue());
            if (certificate == null) {
                return CryptoUtils.createError("Certificate cannot be recovered by using given key alias: " + keyAlias);
            }
            return certificate;
        } catch (FileNotFoundException e) {
            return CryptoUtils.createError("PKCS12 KeyStore not found at: " + keyStoreFile.getAbsoluteFile());
        } catch (KeyStoreException | CertificateException | IOException e) {
            return CryptoUtils.createError("Unable to open KeyStore: " + e.getMessage());
        }
    }

    public static Object decodeRsaPublicKeyFromCertFile(BString certFilePath) {
        File certFile = new File(certFilePath.getValue());
        try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.CERTIFICATE_TYPE_X509);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            return buildRsaPublicKeyRecord(certificate);
        } catch (FileNotFoundException e) {
            return CryptoUtils.createError("Certificate file not found at: " + certFile.getAbsolutePath());
        } catch (CertificateException | IOException e) {
            return CryptoUtils.createError("Unable to do public key operations: " + e.getMessage());
        }
    }

    public static Object decodeRsaPublicKeyFromContent(BArray content) {
        try (InputStream inputStream = new ByteArrayInputStream(content.getBytes())) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.CERTIFICATE_TYPE_X509);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            return buildRsaPublicKeyRecord(certificate);
        } catch (CertificateException | IOException e) {
            return CryptoUtils.createError("Unable to do public key operations: " + e.getMessage());
        }
    }

    public static Object decodeEcPublicKeyFromCertFile(BString certFilePath) {
        File certFile = new File(certFilePath.getValue());
        try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.CERTIFICATE_TYPE_X509);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            return buildEcPublicKeyRecord(certificate);
        } catch (FileNotFoundException e) {
            return CryptoUtils.createError("Certificate file not found at: " + certFile.getAbsolutePath());
        } catch (CertificateException | IOException e) {
            return CryptoUtils.createError("Unable to do public key operations: " + e.getMessage());
        }
    }

    public static Object decodeMlDsa65PublicKeyFromCertFile(BString certFilePath) {
        CryptoUtils.addBCProvider();
        File certFile = new File(certFilePath.getValue());
        try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.CERTIFICATE_TYPE_X509);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            return buildMlDsa65PublicKeyRecord(certificate);
        } catch (FileNotFoundException e) {
            return CryptoUtils.createError("Certificate file not found at: " + certFile.getAbsolutePath());
        } catch (CertificateException | IOException e) {
            return CryptoUtils.createError("Unable to do public key operations: " + e.getMessage());
        }
    }

    public static Object decodeMlKem768PublicKeyFromCertFile(BString certFilePath) {
        CryptoUtils.addBCPQCProvider();
        File certFile = new File(certFilePath.getValue());
        try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.CERTIFICATE_TYPE_X509);
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
            return buildMlKem768PublicKeyRecord(certificate);
        } catch (FileNotFoundException e) {
            return CryptoUtils.createError("Certificate file not found at: " + certFile.getAbsolutePath());
        } catch (CertificateException | IOException e) {
            return CryptoUtils.createError("Unable to do public key operations: " + e.getMessage());
        }
    }

    private static Object buildRsaPublicKeyRecord(Certificate certificate) {
        BMap<BString, Object> certificateBMap = enrichPublicKeyInfo(certificate);
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey.getAlgorithm().equals(Constants.RSA_ALGORITHM)) {
            return getPublicKeyRecord(certificate, certificateBMap, publicKey);
        }
        return CryptoUtils.createError("Not a valid RSA public key");
    }

    private static Object buildEcPublicKeyRecord(Certificate certificate) {
        BMap<BString, Object> certificateBMap = enrichPublicKeyInfo(certificate);
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey.getAlgorithm().equals(Constants.EC_ALGORITHM)) {
            return getPublicKeyRecord(certificate, certificateBMap, publicKey);
        }
        return CryptoUtils.createError("Not a valid EC public key");
    }

    private static Object buildMlDsa65PublicKeyRecord(Certificate certificate) {
        BMap<BString, Object> certificateBMap = enrichPublicKeyInfo(certificate);
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey.getAlgorithm().equals(Constants.MLDSA65_ALGORITHM)) {
            return getPublicKeyRecord(certificate, certificateBMap, publicKey);
        }
        return CryptoUtils.createError("Not a valid ML-DSA-65 public key");
    }

    private static Object buildMlKem768PublicKeyRecord(Certificate certificate) {
        BMap<BString, Object> certificateBMap = enrichPublicKeyInfo(certificate);
        PublicKey publicKey = certificate.getPublicKey();
        if (publicKey.getAlgorithm().equals(Constants.MLKEM768_ALGORITHM)) {
            return getPublicKeyRecord(certificate, certificateBMap, publicKey);
        }
        return CryptoUtils.createError("Not a valid ML-KEM-768 public key");
    }

    private static Object getPublicKeyRecord(Certificate certificate, BMap<BString, Object> certificateBMap,
                                             PublicKey publicKey) {
        BMap<BString, Object> publicKeyMap = ValueCreator.
                createRecordValue(ModuleUtils.getModule(), Constants.PUBLIC_KEY_RECORD);
        publicKeyMap.addNativeData(Constants.NATIVE_DATA_PUBLIC_KEY, publicKey);
        publicKeyMap.addNativeData(Constants.NATIVE_DATA_PUBLIC_KEY_CERTIFICATE, certificate);
        publicKeyMap.put(StringUtils.fromString(Constants.PUBLIC_KEY_RECORD_ALGORITHM_FIELD),
                         StringUtils.fromString(publicKey.getAlgorithm()));
        if (certificateBMap.size() > 0) {
            publicKeyMap.put(StringUtils.fromString(Constants.PUBLIC_KEY_RECORD_CERTIFICATE_FIELD),
                    certificateBMap);
        }
        return publicKeyMap;
    }

    private static BMap<BString, Object> enrichPublicKeyInfo(Certificate certificate) {
        BMap<BString, Object> certificateBMap = ValueCreator.
                createRecordValue(ModuleUtils.getModule(), Constants.CERTIFICATE_RECORD);
        if (certificate instanceof X509Certificate) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_ISSUER_FIELD),
                                StringUtils.fromString(x509Certificate.getIssuerX500Principal().getName()));
            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_SUBJECT_FIELD),
                                StringUtils.fromString(x509Certificate.getSubjectX500Principal().getName()));
            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_VERSION_FIELD),
                                x509Certificate.getVersion());
            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_SERIAL_FIELD),
                                x509Certificate.getSerialNumber().longValue());

            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_NOT_BEFORE_FIELD),
                                TimeValueHandler.createUtcFromMilliSeconds(x509Certificate.getNotBefore().getTime()));
            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_NOT_AFTER_FIELD),
                                TimeValueHandler.createUtcFromMilliSeconds(x509Certificate.getNotAfter().getTime()));

            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_SIGNATURE_FIELD),
                                ValueCreator.createArrayValue(x509Certificate.getSignature()));
            certificateBMap.put(StringUtils.fromString(Constants.CERTIFICATE_RECORD_SIGNATURE_ALG_FIELD),
                                StringUtils.fromString(x509Certificate.getSigAlgName()));
        }
        return certificateBMap;
    }

    public static Object buildRsaPublicKey(BString modulus, BString exponent) {
        try {
            byte[] decodedModulus = Base64.getUrlDecoder().decode(modulus.getValue());
            byte[] decodedExponent = Base64.getUrlDecoder().decode(exponent.getValue());
            RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, decodedModulus),
                                                         new BigInteger(1, decodedExponent));
            RSAPublicKey publicKey =
                    (RSAPublicKey) KeyFactory.getInstance(Constants.RSA_ALGORITHM).generatePublic(spec);

            BMap<BString, Object> publicKeyMap = ValueCreator.
                    createRecordValue(ModuleUtils.getModule(), Constants.PUBLIC_KEY_RECORD);
            publicKeyMap.addNativeData(Constants.NATIVE_DATA_PUBLIC_KEY, publicKey);
            publicKeyMap.put(StringUtils.fromString(Constants.PUBLIC_KEY_RECORD_ALGORITHM_FIELD),
                             StringUtils.fromString(publicKey.getAlgorithm()));
            return publicKeyMap;
        } catch (InvalidKeySpecException e) {
            return CryptoUtils.createError("Invalid modulus or exponent: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            return CryptoUtils.createError("Algorithm of the key factory is not found: " + e.getMessage());
        }
    }
}
