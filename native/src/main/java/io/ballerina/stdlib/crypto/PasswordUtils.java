/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.bouncycastle.util.encoders.Base64;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * Utility functions relevant to password hashing and validation operations.
 */
public class PasswordUtils {

    /**
     * Minimum allowed work factor for BCrypt password hashing.
     */
    public static final int MIN_WORK_FACTOR = 4;

    /**
     * Maximum allowed work factor for BCrypt password hashing.
     */
    public static final int MAX_WORK_FACTOR = 31;

    /**
     * Default work factor used for BCrypt password hashing if not specified.
     */
    public static final int DEFAULT_WORK_FACTOR = 12;

    /**
     * Length of the random salt used in password hashing.
     */
    public static final int SALT_LENGTH = 16;

    /**
     * Default number of iterations for Argon2.
     */
    public static final int DEFAULT_ITERATIONS = 3;
       
    /**
     * Default memory usage in KB (64MB) for Argon2.
     */
    public static final int DEFAULT_MEMORY = 65536;
    
    /**
     * Default number of parallel threads for Argon2.
     */
    public static final int DEFAULT_PARALLELISM = 4;
    
    /**
     * Length of the generated hash in bytes for Argon2.
     */
    public static final int HASH_LENGTH = 32;
    
    /**
     * Default number of iterations for PBKDF2.
     */
    public static final int DEFAULT_PBKDF2_ITERATIONS = 10000;
    
    /**
     * Minimum number of iterations for PBKDF2.
     */
    public static final int MIN_PBKDF2_ITERATIONS = 10000;
    
    /**
     * Length of the generated hash in bytes for PBKDF2.
     */
    public static final int PBKDF2_HASH_LENGTH = 32;
    
    /**
     * Default HMAC algorithm for PBKDF2.
     */
    public static final String DEFAULT_PBKDF2_ALGORITHM = "SHA256";
    
    /**
     * Supported HMAC algorithms for PBKDF2.
     */
    static final String[] SUPPORTED_PBKDF2_ALGORITHMS = {"SHA1", "SHA256", "SHA512"}; 
    
    /**
     * Secure random number generator for salt generation.
     */
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    private PasswordUtils() {}

    /**
     * Validate if the provided work factor is within acceptable bounds.
     *
     * @param workFactor the work factor to validate
     * @return null if valid, error if invalid
     */
    public static Object validateWorkFactor(long workFactor) {
        if (workFactor < MIN_WORK_FACTOR || workFactor > MAX_WORK_FACTOR) {
            return CryptoUtils.createError(
                String.format("Work factor must be between %d and %d", MIN_WORK_FACTOR, MAX_WORK_FACTOR)
            );
        }
        return null;
    }
    
    /**
     * Validate if the provided PBKDF2 iterations is within acceptable bounds.
     *
     * @param iterations the iterations count to validate
     * @return null if valid, error if invalid
     */
    public static Object validatePBKDF2Iterations(long iterations) {
        if (iterations < MIN_PBKDF2_ITERATIONS) {
            return CryptoUtils.createError(
                String.format("Iterations must be at least %d", MIN_PBKDF2_ITERATIONS)
            );
        }
        return null;
    }
    
    /**
     * Validate if the provided PBKDF2 algorithm is supported.
     *
     * @param algorithm the HMAC algorithm to validate
     * @return null if valid, error if invalid
     */
    public static Object validatePBKDF2Algorithm(String algorithm) {
        for (String supportedAlg : SUPPORTED_PBKDF2_ALGORITHMS) {
            if (supportedAlg.equalsIgnoreCase(algorithm)) {
                return null;
            }
        }
        return CryptoUtils.createError(
            String.format("Unsupported algorithm. Must be one of: %s", 
                String.join(", ", SUPPORTED_PBKDF2_ALGORITHMS))
        );
    }

    /**
     * Generate a cryptographically secure random salt.
     *
     * @return byte array containing the generated salt
     */
    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Format a BCrypt hash string according to the standard format.
     *
     * @param workFactor the work factor used in hashing
     * @param saltAndHash combined salt and hash byte array
     * @return formatted BCrypt hash string
     */
    public static String formatBCryptHash(long workFactor, byte[] saltAndHash) {
        String saltAndHashBase64 = Base64.toBase64String(saltAndHash);
        return String.format(Locale.ROOT, "$2a$%02d$%s", workFactor, saltAndHashBase64);
    }

    /**
     * Format an Argon2 hash string according to the standard format.
     *
     * @param memory memory cost parameter
     * @param iterations time cost parameter
     * @param parallelism parallelism parameter
     * @param saltBase64 Base64 encoded salt
     * @param hashBase64 Base64 encoded hash
     * @return formatted Argon2 hash string
     */
    public static String formatArgon2Hash(long memory, long iterations, long parallelism, 
            String saltBase64, String hashBase64) {
        return String.format(Locale.ROOT, "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
                memory, iterations, parallelism, saltBase64, hashBase64);
    }

    /**
     * Format an Argon2 salt string according to the standard format.
     *
     * @param memory memory cost parameter
     * @param iterations time cost parameter
     * @param parallelism parallelism parameter
     * @param saltBase64 Base64 encoded salt
     * @return formatted Argon2 salt string
     */
    public static String formatArgon2Salt(long memory, long iterations, long parallelism, String saltBase64) {
        return String.format(Locale.ROOT, "$argon2id$v=19$m=%d,t=%d,p=%d$%s",
                memory, iterations, parallelism, saltBase64);
    }
    
    /**
     * Format a PBKDF2 hash string according to the standard format.
     *
     * @param algorithm the HMAC algorithm used
     * @param iterations iteration count
     * @param saltBase64 Base64 encoded salt
     * @param hashBase64 Base64 encoded hash
     * @return formatted PBKDF2 hash string
     */
    public static String formatPBKDF2Hash(String algorithm, long iterations, 
            String saltBase64, String hashBase64) {
        return String.format(Locale.ROOT, "$pbkdf2-%s$i=%d$%s$%s",
                algorithm.toLowerCase(Locale.ROOT), iterations, saltBase64, hashBase64);
    }
    
    /**
     * Format a PBKDF2 salt string according to the standard format.
     *
     * @param algorithm the HMAC algorithm used
     * @param iterations iteration count
     * @param saltBase64 Base64 encoded salt
     * @return formatted PBKDF2 salt string
     */
    public static String formatPBKDF2Salt(String algorithm, long iterations, String saltBase64) {
        return String.format(Locale.ROOT, "$pbkdf2-%s$i=%d$%s",
                algorithm.toLowerCase(Locale.ROOT), iterations, saltBase64);
    }

    /**
     * Combine salt and hash byte arrays into a single array.
     *
     * @param salt salt byte array
     * @param hash hash byte array
     * @return combined byte array containing salt followed by hash
     */
    public static byte[] combine(byte[] salt, byte[] hash) {
        byte[] combined = new byte[salt.length + hash.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hash, 0, combined, salt.length, hash.length);
        return combined;
    }

    /**
     * Compare two byte arrays in constant time to prevent timing attacks.
     *
     * @param a first byte array
     * @param b second byte array
     * @return true if arrays are equal, false otherwise
     */
    public static boolean constantTimeArrayEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
