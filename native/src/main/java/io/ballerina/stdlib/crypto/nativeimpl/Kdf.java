package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.values.BArray;
import io.ballerina.stdlib.crypto.CryptoUtils;

public class Kdf {

    private Kdf() {}

    public static Object hkdfSha256(BArray inputValue, long length, BArray saltValue, BArray infoValue) {

        byte[] input = inputValue.getBytes();
        byte[] salt = saltValue.getBytes();
        byte[] info = infoValue.getBytes();

        return CryptoUtils.hkdf("SHA-256", input, salt, info, (int) length);
    }

}
