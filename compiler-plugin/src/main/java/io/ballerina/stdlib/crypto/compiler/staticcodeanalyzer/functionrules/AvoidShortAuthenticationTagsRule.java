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

import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.ConstantSymbol;
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.values.ConstantValue;
import io.ballerina.compiler.syntax.tree.BasicLiteralNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.NameReferenceNode;
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Optional;
import java.util.Set;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_SHORT_AUTHENTICATION_TAGS;

/**
 * Rule to avoid short GCM authentication tags.
 * <p>
 * The authentication tag is what makes GCM an authenticated mode. Shortening it reduces the work an attacker needs
 * to forge a valid ciphertext: a 32-bit tag can be forged in roughly four billion attempts, which is tractable
 * against a service that accepts repeated attempts.
 * <p>
 * The API documentation states the minimum is 96 bits, but the runtime validator also accepts 32 and 63, so a value
 * below the documented minimum passes silently.
 *
 * @since 2.12.2
 */
public class AvoidShortAuthenticationTagsRule implements CryptoFunctionRule {

    private static final String TAG_SIZE_PARAM = "tagSize";
    private static final int MINIMUM_TAG_SIZE = 96;
    private static final Set<String> GCM_FUNCTIONS = Set.of("encryptAesGcm", "decryptAesGcm");

    @Override
    public void analyze(FunctionContext context) {
        Optional<ExpressionNode> tagSize = context.getParamExpression(TAG_SIZE_PARAM);
        // If the parameter is absent the default of 128 applies, which is secure.
        if (tagSize.isPresent() && isBelowMinimum(tagSize.get(), context.semanticModel())) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_SHORT_AUTHENTICATION_TAGS.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        return GCM_FUNCTIONS.contains(context.functionName());
    }

    private boolean isBelowMinimum(ExpressionNode valueExpr, SemanticModel semanticModel) {
        if (valueExpr.kind().equals(SyntaxKind.NUMERIC_LITERAL)) {
            try {
                return Integer.parseInt(((BasicLiteralNode) valueExpr).literalToken().text()) < MINIMUM_TAG_SIZE;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        if (valueExpr instanceof NameReferenceNode refNode) {
            Optional<Symbol> refSymbol = semanticModel.symbol(refNode);
            if (refSymbol.isPresent() && refSymbol.get() instanceof ConstantSymbol constantRef &&
                    constantRef.constValue() instanceof ConstantValue constantValue &&
                    constantValue.value() instanceof Long longValue) {
                return longValue < MINIMUM_TAG_SIZE;
            }
        }
        return false;
    }
}
