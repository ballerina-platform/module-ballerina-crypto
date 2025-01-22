/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package io.ballerina.stdlib.crypto;

import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.stdlib.crypto.nativeimpl.ModuleUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.kems.RSAKEMExtractor;
import org.bouncycastle.crypto.kems.RSAKEMGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static io.ballerina.stdlib.crypto.Constants.CRYPTO_ERROR;

/**
 * Utility functions relevant to crypto operations.
 *
 * @since 0.95.1
 */
public class CryptoUtils {

    /**
     * Cipher mode that is used to decide if encryption or decryption operation should be performed.
     */
    public enum CipherMode { ENCRYPT, DECRYPT }

    /**
     * Valid tag sizes usable with GCM mode encryption.
     */
    private static final int[] VALID_GCM_TAG_SIZES = new int[]{32, 63, 96, 104, 112, 120, 128};

    /**
     * Valid AES key sizes.
     */
    private static final int[] VALID_AES_KEY_SIZES = new int[]{16, 24, 32};

    private CryptoUtils() {}

    /**
     * Generate HMAC of a byte array based on the provided HMAC algorithm.
     *
     * @param algorithm algorithm used during HMAC generation
     * @param key       key used during HMAC generation
     * @param input     input byte array for HMAC generation
     * @return calculated HMAC value or error if key is invalid
     */
    public static Object hmac(String algorithm, byte[] key, byte[] input) {
        try {
            SecretKey secretKey = new SecretKeySpec(key, algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(secretKey);
            return ValueCreator.createArrayValue(mac.doFinal(input));
        } catch (InvalidKeyException | IllegalArgumentException e) {
            return CryptoUtils.createError("Error occurred while calculating HMAC: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw CryptoUtils.createError("Error occurred while calculating HMAC: " + e.getMessage());
        }
    }

    /**
     * Generate Hash of a byte array based on the provided hashing algorithm.
     *
     * @param algorithm algorithm used during hashing
     * @param input     input byte array for hashing
     * @param salt      salt byte array for hashing
     * @return calculated hash value
     */
    public static byte[] hash(String algorithm, byte[] input, Object salt) {
        try {
            CryptoUtils.addBCProvider();  
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm); 

            if (salt != null) {
                messageDigest.update(((BArray) salt).getBytes());
            }
            return messageDigest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw CryptoUtils.createError("Error occurred while calculating hash: " + e.getMessage());
        }
    }

    /**
     * Generate signature of a byte array based on the provided signing algorithm.
     *
     * @param algorithm  algorithm used during signing
     * @param privateKey private key to be used during signing
     * @param input      input byte array for signing
     * @return calculated signature or error if key is invalid
     */
    public static Object sign(String algorithm, PrivateKey privateKey, byte[] input) {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initSign(privateKey);
            sig.update(input);
            return ValueCreator.createArrayValue(sig.sign());
        } catch (InvalidKeyException e) {
            return CryptoUtils.createError("Uninitialized private key: " + e.getMessage());
        } catch (SignatureException e) {
            return CryptoUtils.createError("Error occurred while calculating signature: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw CryptoUtils.createError("Error occurred while calculating signature: " + e.getMessage());
        }
    }

    /**
     * Verify signature of a byte array based on the provided signing algorithm.
     *
     * @param algorithm algorithm used during verification
     * @param publicKey public key to be used during verification
     * @param data      input byte array for verification
     * @param signature signature byte array for verification
     * @return validity of the signature or error if key is invalid
     */
    public static Object verify(String algorithm, PublicKey publicKey, byte[] data, byte[] signature) {
        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (InvalidKeyException e) {
            return CryptoUtils.createError("Uninitialized public key: " + e.getMessage());
        } catch (SignatureException e) {
            return CryptoUtils.createError("Error occurred while calculating signature: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw CryptoUtils.createError("Error occurred while calculating signature: " + e.getMessage());
        }
    }

    public static Object hkdf(String digestAlgorithm, byte[] ikm, byte[] salt, byte[] info, int length) {
        Digest hash = selectHash(digestAlgorithm);
        byte[] okm = new byte[length];

        HKDFParameters params = new HKDFParameters(ikm, salt, info);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(hash);
        hkdf.init(params);
        hkdf.generateBytes(okm, 0, length);
        return ValueCreator.createArrayValue(okm);
    }

    public static Object generateEncapsulated(String algorithm, PublicKey publicKey, String provider) {
        try {
            KEMGenerateSpec kemGenerateSpec = new KEMGenerateSpec(publicKey, algorithm);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, provider);
            keyGenerator.init(kemGenerateSpec);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            return CryptoUtils.createError("Error occurred while generating encapsulated key: " + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw CryptoUtils.createError("Provider not found: " + provider);
        }
    }

    public static Object generateRsaEncapsulated(PublicKey publicKey) {
        if (!(publicKey instanceof RSAPublicKey)) {
            return CryptoUtils.createError("Error occurred while generating encapsulated key: valid RSA " + 
                                                "public key expected");
        }
        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        RSAKEMGenerator keyGenerator = new RSAKEMGenerator(
                32, new KDF2BytesGenerator(new SHA256Digest()), new SecureRandom());
        RSAKeyParameters rsaKeyParams = new RSAKeyParameters(
                false, rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
        SecretWithEncapsulation secretWithEncapsulation = keyGenerator.generateEncapsulated(rsaKeyParams);
        SecretKey secretKey = new SecretKeySpec(secretWithEncapsulation.getSecret(), Constants.RSA_ALGORITHM);
        return new SecretKeyWithEncapsulation(secretKey, secretWithEncapsulation.getEncapsulation());
    }

    public static Object extractSecret(byte[] encapsulation, String algorithm, PrivateKey privateKey, String provider) {
        try {
            KEMExtractSpec kemExtractSpec = new KEMExtractSpec(privateKey, encapsulation, algorithm);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, provider);
            keyGenerator.init(kemExtractSpec);
            SecretKeyWithEncapsulation secretKeyWithEncapsulation =
                    (SecretKeyWithEncapsulation) keyGenerator.generateKey();
            return ValueCreator.createArrayValue(secretKeyWithEncapsulation.getEncoded());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            return CryptoUtils.createError("Error occurred while extracting secret: " + e.getMessage());
        } catch (NoSuchProviderException e) {
            throw CryptoUtils.createError("Provider not found: " + e.getMessage());
        }
    }

    public static Object extractRsaSecret(byte[] encapsulation, PrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateKey)) {
            return CryptoUtils.createError("Error occurred while extracting secret: valid RSA private" + 
                                                "key expected");
        }
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
        RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(
                true, rsaPrivateKey.getModulus(), rsaPrivateKey.getPrivateExponent());
        RSAKEMExtractor keyExtractor = new RSAKEMExtractor(
                rsaKeyParameters, 32, new KDF2BytesGenerator(new SHA256Digest()));
        KeyParameter keyParameter = new KeyParameter(keyExtractor.extractSecret(encapsulation));
        return ValueCreator.createArrayValue(keyParameter.getKey());
    }

    /**
     * Create crypto error.
     *
     * @param errMsg error description
     * @return conversion error
     */
    public static BError createError(String errMsg) {
        return ErrorCreator.createDistinctError(CRYPTO_ERROR, ModuleUtils.getModule(), StringUtils.fromString(errMsg));
    }

    /**
     * Encrypt or decrypt byte array based on RSA algorithm.
     *
     * @param cipherMode       cipher mode depending on encryption or decryption
     * @param algorithmMode    mode used during encryption
     * @param algorithmPadding padding used during encryption
     * @param key              key to be used during encryption
     * @param input            input byte array for encryption
     * @param iv               initialization vector
     * @param tagSize          tag size used for GCM encryption
     * @return Decrypted data or error if key is invalid
     */
    public static Object rsaEncryptDecrypt(CipherMode cipherMode, String algorithmMode,
                                           String algorithmPadding, Key key, byte[] input, byte[] iv, long tagSize) {
        try {
            String transformedAlgorithmPadding = transformAlgorithmPadding(algorithmPadding);
            if (tagSize != -1 && Arrays.stream(VALID_GCM_TAG_SIZES).noneMatch(i -> tagSize == i)) {
                return CryptoUtils.createError("Valid tag sizes are: " + Arrays.toString(VALID_GCM_TAG_SIZES));
            }
            AlgorithmParameterSpec paramSpec = buildParameterSpec(algorithmMode, iv, (int) tagSize);
            Cipher cipher = Cipher.getInstance(Constants.RSA + "/" + algorithmMode + "/" + transformedAlgorithmPadding);
            initCipher(cipher, cipherMode, key, paramSpec);
            return ValueCreator.createArrayValue(cipher.doFinal(input));
        } catch (NoSuchAlgorithmException e) {
            return CryptoUtils.createError("Unsupported algorithm: RSA " + algorithmMode + " " + algorithmPadding +
                                                   ": " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            return CryptoUtils.createError("Unsupported padding scheme defined in the algorithm: RSA "
                                                   + algorithmMode + " " + algorithmPadding + ": " + e.getMessage());
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException |
                IllegalBlockSizeException | BError e) {
            return CryptoUtils.createError("Error occurred while RSA encrypt/decrypt: " + e.getMessage());
        }
    }

    /**
     * Encrypt or decrypt byte array based on AES algorithm.
     *
     * @param cipherMode       cipher mode depending on encryption or decryption
     * @param algorithmMode    mode used during encryption
     * @param algorithmPadding padding used during encryption
     * @param key              key to be used during encryption
     * @param input            input byte array for encryption
     * @param iv               initialization vector
     * @param tagSize          tag size used for GCM encryption
     * @return Decrypted data or error if key is invalid
     */
    public static Object aesEncryptDecrypt(CipherMode cipherMode, String algorithmMode,
                                           String algorithmPadding, byte[] key, byte[] input, byte[] iv, long tagSize) {
        try {
            if (Arrays.stream(VALID_AES_KEY_SIZES).noneMatch(validSize -> validSize == key.length)) {
                return CryptoUtils.createError("Invalid key size. Valid key sizes in bytes: " +
                                                       Arrays.toString(VALID_AES_KEY_SIZES));
            }
            String transformedAlgorithmPadding = transformAlgorithmPadding(algorithmPadding);
            SecretKeySpec keySpec = new SecretKeySpec(key, Constants.AES);
            if (tagSize != -1 && Arrays.stream(VALID_GCM_TAG_SIZES).noneMatch(validSize -> validSize == tagSize)) {
                return CryptoUtils.createError("Invalid tag size. Valid tag sizes in bytes: " +
                                                       Arrays.toString(VALID_GCM_TAG_SIZES));
            }
            AlgorithmParameterSpec paramSpec = buildParameterSpec(algorithmMode, iv, (int) tagSize);
            Cipher cipher = Cipher.getInstance("AES/" + algorithmMode + "/" + transformedAlgorithmPadding);
            initCipher(cipher, cipherMode, keySpec, paramSpec);
            return ValueCreator.createArrayValue(cipher.doFinal(input));
        } catch (NoSuchAlgorithmException e) {
            return CryptoUtils.createError("Unsupported algorithm: AES " + algorithmMode + " " + algorithmPadding +
                                                   ": " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            return CryptoUtils.createError("Unsupported padding scheme defined in  the algorithm: AES " +
                                                   algorithmMode + " " + algorithmPadding + ": " + e.getMessage());
        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException |
                InvalidKeyException | BError e) {
            return CryptoUtils.createError("Error occurred while AES encrypt/decrypt: " + e.getMessage());
        }
    }

    /**
     * Add Bouncy Castle Post Quantum Cryptography provider to the security providers list.
     */
    public static void addBCPQCProvider() {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    /**
     * Add Bouncy Castle provider to the security providers list.
     */
    public static void addBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Initialize cipher for encryption and decryption operations.
     *
     * @param cipher     cipher instance to initialize
     * @param cipherMode mode denoting if cipher is used for encryption or decryption
     * @param key        key used for crypto operation
     * @param paramSpec  cipher parameter specification
     * @throws InvalidKeyException                if provided key was not valid
     * @throws InvalidAlgorithmParameterException if algorithm parameters are insufficient
     */
    private static void initCipher(Cipher cipher, CipherMode cipherMode, Key key, AlgorithmParameterSpec paramSpec)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        switch (cipherMode) {
            case ENCRYPT:
                if (paramSpec == null) {
                    cipher.init(Cipher.ENCRYPT_MODE, key);
                } else {
                    cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
                }
                break;
            case DECRYPT:
                if (paramSpec == null) {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
                }
                break;
        }
    }

    /**
     * Build algorithm parameter specification based on the cipher mode.
     *
     * @param algorithmMode algorithm mode
     * @param iv            initialization vector for CBC and GCM mode
     * @param tagSize       tag size for GCM mode
     * @return algorithm parameter specification
     * @throws BError if initialization vector is not specified
     */
    private static AlgorithmParameterSpec buildParameterSpec(String algorithmMode, byte[] iv, int tagSize) {
        switch (algorithmMode) {
            case Constants.GCM:
                return new GCMParameterSpec(tagSize, iv);
            case Constants.CBC:
                return new IvParameterSpec(iv);
            default:
                return null;
        }
    }

    /**
     * Transform Ballerina padding algorithm names to Java padding algorithm names.
     *
     * @param algorithmPadding padding algorithm name
     * @return transformed  padding algorithm name
     * @throws BError if padding algorithm is not supported
     */
    private static String transformAlgorithmPadding(String algorithmPadding) throws BError {
        switch (algorithmPadding) {
            case "PKCS1":
                algorithmPadding = "PKCS1Padding";
                break;
            case "PKCS5":
                algorithmPadding = "PKCS5Padding";
                break;
            case "OAEPwithMD5andMGF1":
                algorithmPadding = "OAEPWithMD5AndMGF1Padding";
                break;
            case "OAEPWithSHA1AndMGF1":
                algorithmPadding = "OAEPWithSHA-1AndMGF1Padding";
                break;
            case "OAEPWithSHA256AndMGF1":
                algorithmPadding = "OAEPWithSHA-256AndMGF1Padding";
                break;
            case "OAEPwithSHA384andMGF1":
                algorithmPadding = "OAEPWithSHA-384AndMGF1Padding";
                break;
            case "OAEPwithSHA512andMGF1":
                algorithmPadding = "OAEPWithSHA-512AndMGF1Padding";
                break;
            case "NONE":
                algorithmPadding = "NoPadding";
                break;
            default:
                throw CryptoUtils.createError("Unsupported padding: " + algorithmPadding);
        }
        return algorithmPadding;
    }

    private static Digest selectHash(String algorithm) {
        if ("SHA-256".equals(algorithm)) {
            return new SHA256Digest();
        }
        throw CryptoUtils.createError("Unsupported algorithm: " + algorithm);
    }
}
