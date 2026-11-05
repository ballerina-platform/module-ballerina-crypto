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

import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Set;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.ENSURE_VERIFICATION_RESULT_USED;

/**
 * Rule to ensure the result of a signature, password hash or MAC verification is used.
 * <p>
 * These functions return whether the check passed; they do not fail when it does not. Discarding that boolean means
 * a forged message or a wrong password is accepted, while the code reads as though verification is happening.
 *
 * @since 2.13.1
 */
public class EnsureVerificationResultUsedRule implements CryptoFunctionRule {

    private static final Set<String> VERIFY_FUNCTIONS = Set.of(
            "verifyRsaMd5Signature",
            "verifyRsaSha1Signature",
            "verifyRsaSha256Signature",
            "verifyRsaSha384Signature",
            "verifyRsaSha512Signature",
            "verifyRsaSsaPss256Signature",
            "verifySha256withEcdsaSignature",
            "verifySha384withEcdsaSignature",
            "verifyMlDsa65Signature",
            "verifyBcrypt",
            "verifyArgon2",
            "verifyPbkdf2",
            "equalConstantTime");

    @Override
    public void analyze(FunctionContext context) {
        if (context.isResultDiscarded()) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return ENSURE_VERIFICATION_RESULT_USED.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        return VERIFY_FUNCTIONS.contains(context.functionName());
    }
}
