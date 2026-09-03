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

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.ENSURE_SIGNATURE_VERIFICATION;

/**
 * Rule to ensure the result of a signature verification is used.
 * <p>
 * The verify functions return whether the signature is valid; they do not fail when it is invalid. Discarding that
 * boolean means the signature is computed and then ignored, so a forged or tampered message is accepted. The code
 * reads as though verification is happening, which is what makes this worth reporting.
 *
 * @since 2.12.2
 */
public class EnsureSignatureVerificationRule implements CryptoFunctionRule {

    private static final Set<String> VERIFY_FUNCTIONS = Set.of(
            "verifyRsaMd5Signature",
            "verifyRsaSha1Signature",
            "verifyRsaSha256Signature",
            "verifyRsaSha384Signature",
            "verifyRsaSha512Signature",
            "verifyRsaSsaPss256Signature",
            "verifySha256withEcdsaSignature",
            "verifySha384withEcdsaSignature",
            "verifyMlDsa65Signature");

    @Override
    public void analyze(FunctionContext context) {
        if (context.isResultDiscarded()) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return ENSURE_SIGNATURE_VERIFICATION.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        return VERIFY_FUNCTIONS.contains(context.functionName());
    }
}
