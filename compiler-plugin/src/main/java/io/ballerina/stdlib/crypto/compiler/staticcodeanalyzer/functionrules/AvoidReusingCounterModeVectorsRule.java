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

import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.symbols.SymbolKind;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.ListConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MethodCallExpressionNode;
import io.ballerina.compiler.syntax.tree.NameReferenceNode;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Optional;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.unescapeIdentifier;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_REUSING_COUNTER_MODE_VECTORS;

/**
 * Rule to avoid reusing initialization vectors (IVs) in counter mode encryption algorithms such as AES-CBC
 * and AES-GCM.
 *
 * @since 2.9.1
 */
public class AvoidReusingCounterModeVectorsRule implements CryptoFunctionRule {

    public static final String ENCRYPT_AES_CBC = "encryptAesCbc";
    public static final String ENCRYPT_AES_GCM = "encryptAesGcm";
    public static final String INITIALIZATION_VECTOR = "iv";
    public static final String TO_BYTES_METHOD = "toBytes";

    @Override
    public void analyze(FunctionContext context) {
        Optional<ExpressionNode> paramExpression = context.getParamExpression(INITIALIZATION_VECTOR);
        if (paramExpression.isEmpty()) {
            // The IV is a required parameter for these functions, so this case should not occur.
            throw new IllegalStateException("Initialization vector parameter is missing for function: "
                    + context.functionName());
        }

        if (hasHardCodedIV(paramExpression.get(), context)) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_REUSING_COUNTER_MODE_VECTORS.getId();

    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        String functionName = context.functionName();
        return functionName.equals(ENCRYPT_AES_CBC) || functionName.equals(ENCRYPT_AES_GCM);
    }

    private boolean hasHardCodedIV(ExpressionNode ivExpression, FunctionContext context) {
        // Check for list constructor with numeric literals (e.g., [1, 2, 3, ...])
        if (ivExpression instanceof ListConstructorExpressionNode listExpression) {
            return listExpression.expressions().stream()
                    .allMatch(expr -> expr.kind().equals(SyntaxKind.NUMERIC_LITERAL));
        }

        // Check for toBytes() method called on a string literal or name reference referring to a constant
        if (ivExpression instanceof MethodCallExpressionNode methodCallExpression) {
            ExpressionNode expression = methodCallExpression.expression();
            if (!isMethodCallOnConstantExpr(expression, context)) {
                return false;
            }
            NameReferenceNode nameReferenceNode = methodCallExpression.methodName();
            if (nameReferenceNode instanceof SimpleNameReferenceNode simpleNameRef) {
                return simpleNameRef.name().text().equals(TO_BYTES_METHOD);
            }
        }

        return false;
    }

    private boolean isMethodCallOnConstantExpr(ExpressionNode expression, FunctionContext context) {
        if (expression.kind().equals(SyntaxKind.STRING_LITERAL)) {
            return true;
        }
        if (expression.kind().equals(SyntaxKind.SIMPLE_NAME_REFERENCE) ||
                expression.kind().equals(SyntaxKind.QUALIFIED_NAME_REFERENCE)) {
            Optional<Symbol> symbol = context.semanticModel().symbol(expression);
            if (symbol.isPresent() && symbol.get().kind().equals(SymbolKind.CONSTANT)) {
                return true;
            }
        }

        // If the value is not constant, check if it's a parameter referring to a constant where the value can be
        // determined at compile time
        if (expression instanceof SimpleNameReferenceNode simpleNameRef) {
            String varName = unescapeIdentifier(simpleNameRef.name().text());
            Optional<ExpressionNode> paramExpression = context.getVarExpression(varName);
            return paramExpression.isPresent() &&
                    isMethodCallOnConstantExpr(paramExpression.get(), context);
        }
        return false;
    }
}
