package io.ballerina.stdlib.crypto;

import org.bouncycastle.util.encoders.Base64;

import java.security.SecureRandom;

public class PasswordUtils {
    public static final int MIN_WORK_FACTOR = 4;
    public static final int MAX_WORK_FACTOR = 31;
    public static final int DEFAULT_WORK_FACTOR = 12;
    public static final int SALT_LENGTH = 16;
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    private PasswordUtils() {}

    public static Object validateWorkFactor(long workFactor) {
        if (workFactor < MIN_WORK_FACTOR || workFactor > MAX_WORK_FACTOR) {
            return CryptoUtils.createError(
                String.format("Work factor must be between %d and %d", MIN_WORK_FACTOR, MAX_WORK_FACTOR)
            );
        }
        return null;
    }

    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public static String formatBCryptHash(long workFactor, byte[] saltAndHash) {
        String saltAndHashBase64 = Base64.toBase64String(saltAndHash);
        return String.format("$2a$%02d$%s", workFactor, saltAndHashBase64);
    }

    public static String formatArgon2Hash(long memory, long iterations, long parallelism, String saltBase64, String hashBase64) {
        return String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
            memory, iterations, parallelism, saltBase64, hashBase64);
    }

    public static String formatArgon2Salt(long memory, long iterations, long parallelism, String saltBase64) {
        return String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s",
            memory, iterations, parallelism, saltBase64);
    }

    public static byte[] combine(byte[] salt, byte[] hash) {
        byte[] combined = new byte[salt.length + hash.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hash, 0, combined, salt.length, hash.length);
        return combined;
    }

    public static boolean constantTimeArrayEquals(byte[] a, byte[] b) {
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