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

import io.ballerina.runtime.api.values.BArray;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.stdlib.crypto.CryptoUtils;

import static io.ballerina.stdlib.crypto.Constants.MLKEM768_ALGORITHM;
import static io.ballerina.stdlib.crypto.Constants.NOT_SUPPORTED_IN_FIPS_MODE;
import static io.ballerina.stdlib.crypto.Constants.RSA_KEM;

public class Kem {

    private Kem() {
    }

    public static Object encapsulateMlKem768(BMap<?, ?> publicKey) {
        throw CryptoUtils.createFipsError(MLKEM768_ALGORITHM + NOT_SUPPORTED_IN_FIPS_MODE);
    }

    public static Object encapsulateRsaKem(BMap<?, ?> publicKey) {
        throw CryptoUtils.createFipsError(RSA_KEM + NOT_SUPPORTED_IN_FIPS_MODE);
    }

    public static Object decapsulateMlKem768(BArray inputValue, BMap<?, ?> privateKey) {
        throw CryptoUtils.createFipsError(MLKEM768_ALGORITHM + NOT_SUPPORTED_IN_FIPS_MODE);
    }

    public static Object decapsulateRsaKem(BArray inputValue, BMap<?, ?> privateKey) {
        throw CryptoUtils.createFipsError(RSA_KEM + NOT_SUPPORTED_IN_FIPS_MODE);
    }
}
