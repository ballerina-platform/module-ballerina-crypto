/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Optional;
import java.util.Set;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_WEAK_PGP_ALGORITHMS;

/**
 * Rule to avoid weak symmetric algorithms in PGP encryption.
 * <p>
 * {@code SymmetricKeyAlgorithmTags} allows several algorithms that are no longer fit for use. {@code NULL} applies
 * no encryption at all; DES, IDEA, CAST5, SAFER and BLOWFISH have inadequate key or block sizes; and Triple DES is
 * vulnerable to birthday attacks on its 64-bit block. AES-128 or stronger should be used instead.
 * <p>
 * The enum members carry numeric string values, so the check compares the resolved constant value rather than the
 * member name. Values "0" through "6" are the weak members.
 *
 * @since 2.12.2
 */
public class AvoidWeakPgpAlgorithmsRule implements CryptoFunctionRule {

    private static final String SYMMETRIC_KEY_ALGORITHM_PARAM = "symmetricKeyAlgorithm";
    private static final Set<String> PGP_ENCRYPT_FUNCTIONS = Set.of("encryptPgp", "encryptStreamAsPgp");

    // NULL, IDEA, TRIPLE_DES, CAST5, BLOWFISH, SAFER, DES
    private static final Set<String> WEAK_ALGORITHM_VALUES = Set.of("0", "1", "2", "3", "4", "5", "6");

    @Override
    public void analyze(FunctionContext context) {
        Optional<String> algorithm = CryptoAnalyzerUtils.getStringValue(SYMMETRIC_KEY_ALGORITHM_PARAM, context);
        if (algorithm.isPresent() && WEAK_ALGORITHM_VALUES.contains(algorithm.get())) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_WEAK_PGP_ALGORITHMS.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        return PGP_ENCRYPT_FUNCTIONS.contains(context.functionName());
    }
}
