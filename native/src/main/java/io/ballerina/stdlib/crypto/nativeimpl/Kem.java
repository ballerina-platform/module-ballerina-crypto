/*
 * Copyright (c) 2024, WSO2 LLC. (https://www.wso2.com).
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
package io.ballerina.stdlib.crypto.nativeimpl;

import io.ballerina.runtime.api.creators.ValueCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.Constants;
import io.ballerina.stdlib.crypto.CryptoUtils;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class Kem {

    private Kem() {
    }

    public static Object encapsulateMlKem768(BMap<?, ?> publicKey) {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        PublicKey key = (PublicKey) publicKey.getNativeData(Constants.NATIVE_DATA_PUBLIC_KEY);
        Object encapsulate = CryptoUtils.generateEncapsulated(Constants.MLKEM768_ALGORITHM, key,
                BouncyCastlePQCProvider.PROVIDER_NAME);
        if (encapsulate instanceof SecretKeyWithEncapsulation secretKeyWithEncapsulation) {
            return getEncapsulationResultRecord(secretKeyWithEncapsulation);
        }
        return encapsulate;
    }

    public static Object encapsulateRsaKem(BMap<?, ?> publicKey) {
        PublicKey key = (PublicKey) publicKey.getNativeData(Constants.NATIVE_DATA_PUBLIC_KEY);
        Object encapsulate = CryptoUtils.generateRsaEncapsulated(key);
        if (encapsulate instanceof SecretKeyWithEncapsulation secretKeyWithEncapsulation) {
            return getEncapsulationResultRecord(secretKeyWithEncapsulation);
        }
        return encapsulate;
    }

    private static Object getEncapsulationResultRecord(SecretKeyWithEncapsulation secretKeyWithEncapsulation) {
        BMap<BString, Object> encapsulationResultRecord = ValueCreator.
                createRecordValue(ModuleUtils.getModule(), Constants.ENCAPSULATED_RESULT_RECORD);
        encapsulationResultRecord.put(StringUtils.fromString(Constants.ENCAPSULATED_RESULT_RECORD_SECRET_FIELD),
                ValueCreator.createArrayValue(secretKeyWithEncapsulation.getEncoded()));
        encapsulationResultRecord.put(StringUtils.fromString(Constants.ENCAPSULATED_RESULT_RECORD_ENCAPSULATED_FIELD),
                ValueCreator.createArrayValue(secretKeyWithEncapsulation.getEncapsulation()));
        return encapsulationResultRecord;
    }

    public static Object decapsulateMlKem768(BArray inputValue, BMap<?, ?> privateKey) {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        byte[] input = inputValue.getBytes();
        PrivateKey key = (PrivateKey) privateKey.getNativeData(Constants.NATIVE_DATA_PRIVATE_KEY);
        return CryptoUtils.extractSecret(input, Constants.MLKEM768_ALGORITHM, key,
                BouncyCastlePQCProvider.PROVIDER_NAME);
    }

    public static Object decapsulateRsaKem(BArray inputValue, BMap<?, ?> privateKey) {
        byte[] input = inputValue.getBytes();
        PrivateKey key = (PrivateKey) privateKey.getNativeData(Constants.NATIVE_DATA_PRIVATE_KEY);
        return CryptoUtils.extractRsaSecret(input, key);
    }
}
