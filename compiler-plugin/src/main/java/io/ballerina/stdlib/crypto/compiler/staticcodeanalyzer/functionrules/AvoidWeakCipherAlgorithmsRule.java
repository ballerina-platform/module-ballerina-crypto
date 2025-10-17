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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.functionrules;

import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Optional;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getStringValue;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_WEAK_CIPHER_ALGORITHMS;

/**
 * Rule to avoid weak cipher algorithms in crypto functions.
 * Analyzes the usage of AES in ECB/CBC modes and RSA with PKCS1 padding.
 *
 * @since 2.9.1
 */
public class AvoidWeakCipherAlgorithmsRule implements CryptoFunctionRule {

    public static final String ENCRYPT_AES_ECB = "encryptAesEcb";
    public static final String ENCRYPT_AES_CBC = "encryptAesCbc";
    public static final String ENCRYPT_RSA_ECB = "encryptRsaEcb";
    public static final String PADDING_PARAM = "padding";
    public static final String PKCS1_PADDING = "PKCS1";

    @Override
    public void analyze(FunctionContext context) {
        String functionName = context.functionName();
        if (functionName.equals(ENCRYPT_AES_CBC) || functionName.equals(ENCRYPT_AES_ECB)
                || (functionName.equals(ENCRYPT_RSA_ECB) && isRsbEcbWithPKCS1Padding(context))) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_WEAK_CIPHER_ALGORITHMS.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        String functionName = context.functionName();
        return functionName.equals(ENCRYPT_AES_CBC) || functionName.equals(ENCRYPT_AES_ECB)
                || functionName.equals(ENCRYPT_RSA_ECB);
    }

    private boolean isRsbEcbWithPKCS1Padding(FunctionContext context) {
        Optional<String> paddingExprOpt = getStringValue(PADDING_PARAM, context);
        // If padding parameter is not provided, it defaults to PKCS1 padding which is considered weak
        return paddingExprOpt
                .map(s -> s.equals(PKCS1_PADDING))
                .orElse(true);
    }
}
