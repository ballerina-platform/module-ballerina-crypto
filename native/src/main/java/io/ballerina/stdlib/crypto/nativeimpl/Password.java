package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.CryptoUtils;
import org.bouncycastle.crypto.generators.BCrypt;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Password {
    
    private static final int DEFAULT_WORK_FACTOR = 12;
    private static final int MIN_WORK_FACTOR = 4;
    private static final int MAX_WORK_FACTOR = 31;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    private Password() {}

    /**
     * Hash a password using BCrypt with a randomly generated salt.
     *
     * @param password The password to hash
     * @param workFactor The work factor to use (cost parameter)
     * @return Hashed password string or error
     */
    public static Object hashPassword(BString password, long workFactor) {
        try {
            if (workFactor < MIN_WORK_FACTOR || workFactor > MAX_WORK_FACTOR) {
                return CryptoUtils.createError(
                    String.format("Work factor must be between %d and %d", MIN_WORK_FACTOR, MAX_WORK_FACTOR)
                );
            }

            // Generate a random salt
            byte[] salt = new byte[16];
            SECURE_RANDOM.nextBytes(salt);

            // Generate the hash
            byte[] passwordBytes = password.getValue().getBytes(StandardCharsets.UTF_8);
            byte[] hash = BCrypt.generate(passwordBytes, salt, (int) workFactor);

            // Format the final string in BCrypt format: $2a$XX$<combined-salt-and-hash>
            String saltAndHash = Base64.toBase64String(combine(salt, hash));
            String result = String.format("$2a$%02d$%s", workFactor, saltAndHash);
            
            return StringUtils.fromString(result);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while hashing password: " + e.getMessage());
        }
    }

    /**
     * Hash a password using BCrypt with default work factor (12).
     *
     * @param password The password to hash
     * @return Hashed password string or error
     */
    public static Object hashPassword(BString password) {
        return hashPassword(password, DEFAULT_WORK_FACTOR);
    }

    /**
     * Verify a password against a stored hash.
     *
     * @param password The password to verify
     * @param hashedPassword The stored hash to verify against
     * @return Boolean indicating if the password matches
     */
    public static Object verifyPassword(BString password, BString hashedPassword) {
        try {
            String hash = hashedPassword.getValue();
            if (!hash.startsWith("$2a$")) {
                return CryptoUtils.createError("Invalid hash format");
            }

            // Extract work factor and salt+hash from the stored hash
            int workFactor = Integer.parseInt(hash.substring(4, 6));
            String saltAndHashBase64 = hash.substring(7);
            byte[] saltAndHash = Base64.decode(saltAndHashBase64);

            // Split the salt and hash
            byte[] salt = new byte[16];
            System.arraycopy(saltAndHash, 0, salt, 0, 16);

            // Generate new hash with the same salt and work factor
            byte[] passwordBytes = password.getValue().getBytes(StandardCharsets.UTF_8);
            byte[] newHash = BCrypt.generate(passwordBytes, salt, workFactor);

            // Compare the hashes
            byte[] originalHash = new byte[saltAndHash.length - 16];
            System.arraycopy(saltAndHash, 16, originalHash, 0, originalHash.length);
            
            return constantTimeArrayEquals(newHash, originalHash);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while verifying password: " + e.getMessage());
        }
    }

    /**
     * Generate a salt with specified work factor.
     *
     * @param workFactor The work factor to use (cost parameter)
     * @return Generated salt string or error
     */
    public static Object generateSalt(long workFactor) {
        try {
            if (workFactor < MIN_WORK_FACTOR || workFactor > MAX_WORK_FACTOR) {
                return CryptoUtils.createError(
                    String.format("Work factor must be between %d and %d", MIN_WORK_FACTOR, MAX_WORK_FACTOR)
                );
            }

            byte[] salt = new byte[16];
            SECURE_RANDOM.nextBytes(salt);
            String saltBase64 = Base64.toBase64String(salt);
            String result = String.format("$2a$%02d$%s", workFactor, saltBase64);
            
            return StringUtils.fromString(result);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while generating salt: " + e.getMessage());
        }
    }

    /**
     * Generate a salt with default work factor (12).
     *
     * @return Generated salt string or error
     */
    public static Object generateSalt() {
        return generateSalt(DEFAULT_WORK_FACTOR);
    }

    /**
     * Combines salt and hash arrays.
     */
    private static byte[] combine(byte[] salt, byte[] hash) {
        byte[] combined = new byte[salt.length + hash.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hash, 0, combined, salt.length, hash.length);
        return combined;
    }

    /**
     * Constant time array comparison to prevent timing attacks.
     */
    private static boolean constantTimeArrayEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
