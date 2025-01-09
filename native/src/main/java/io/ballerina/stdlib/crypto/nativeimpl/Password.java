package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.CryptoUtils;
import io.ballerina.stdlib.crypto.PasswordUtils;
import org.bouncycastle.crypto.generators.BCrypt;

import java.nio.charset.StandardCharsets;

public class Password {
    
    private Password() {}

    public static Object hashPassword(BString password, long workFactor) {
        try {
            Object validationError = PasswordUtils.validateWorkFactor(workFactor);
            if (validationError != null) {
                return validationError;
            }

            byte[] salt = PasswordUtils.generateRandomSalt();
            byte[] passwordBytes = password.getValue().getBytes(StandardCharsets.UTF_8);
            byte[] hash = BCrypt.generate(passwordBytes, salt, (int) workFactor);
            
            return StringUtils.fromString(
                PasswordUtils.formatBCryptHash(workFactor, PasswordUtils.combine(salt, hash))
            );
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while hashing password: " + e.getMessage());
        }
    }

    public static Object hashPassword(BString password) {
        return hashPassword(password, PasswordUtils.DEFAULT_WORK_FACTOR);
    }

    public static Object verifyPassword(BString password, BString hashedPassword) {
        try {
            String hash = hashedPassword.getValue();
            if (!hash.startsWith("$2a$")) {
                return CryptoUtils.createError("Invalid hash format");
            }

            int workFactor = Integer.parseInt(hash.substring(4, 6));
            String saltAndHashBase64 = hash.substring(7);
            byte[] saltAndHash = org.bouncycastle.util.encoders.Base64.decode(saltAndHashBase64);

            byte[] salt = new byte[PasswordUtils.SALT_LENGTH];
            System.arraycopy(saltAndHash, 0, salt, 0, PasswordUtils.SALT_LENGTH);

            byte[] passwordBytes = password.getValue().getBytes(StandardCharsets.UTF_8);
            byte[] newHash = BCrypt.generate(passwordBytes, salt, workFactor);

            byte[] originalHash = new byte[saltAndHash.length - PasswordUtils.SALT_LENGTH];
            System.arraycopy(saltAndHash, PasswordUtils.SALT_LENGTH, originalHash, 0, originalHash.length);
            
            return PasswordUtils.constantTimeArrayEquals(newHash, originalHash);
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while verifying password: " + e.getMessage());
        }
    }

    public static Object generateSalt(long workFactor) {
        try {
            Object validationError = PasswordUtils.validateWorkFactor(workFactor);
            if (validationError != null) {
                return validationError;
            }

            byte[] salt = PasswordUtils.generateRandomSalt();
            return StringUtils.fromString(
                PasswordUtils.formatBCryptHash(workFactor, salt)
            );
        } catch (Exception e) {
            return CryptoUtils.createError("Error occurred while generating salt: " + e.getMessage());
        }
    }

    public static Object generateSalt() {
        return generateSalt(PasswordUtils.DEFAULT_WORK_FACTOR);
    }
}
