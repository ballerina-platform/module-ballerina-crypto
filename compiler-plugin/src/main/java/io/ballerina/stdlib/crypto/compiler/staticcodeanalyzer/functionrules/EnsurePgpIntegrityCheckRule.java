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

import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Optional;
import java.util.Set;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.ENSURE_PGP_INTEGRITY_CHECK;

/**
 * Rule to keep PGP integrity protection enabled.
 * <p>
 * Setting {@code withIntegrityCheck} to false omits the modification detection code from the message. Without it a
 * recipient cannot tell whether the ciphertext was altered in transit, so tampering succeeds silently.
 *
 * @since 2.12.2
 */
public class EnsurePgpIntegrityCheckRule implements CryptoFunctionRule {

    private static final String WITH_INTEGRITY_CHECK_PARAM = "withIntegrityCheck";
    private static final Set<String> PGP_ENCRYPT_FUNCTIONS = Set.of("encryptPgp", "encryptStreamAsPgp");

    @Override
    public void analyze(FunctionContext context) {
        Optional<ExpressionNode> integrityCheck = context.getParamExpression(WITH_INTEGRITY_CHECK_PARAM);
        // Only an explicit `false` is actionable. The default is true, and a non-literal value cannot be resolved.
        if (integrityCheck.isPresent()
                && "false".equals(integrityCheck.get().toSourceCode().trim())) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return ENSURE_PGP_INTEGRITY_CHECK.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        return PGP_ENCRYPT_FUNCTIONS.contains(context.functionName());
    }
}
