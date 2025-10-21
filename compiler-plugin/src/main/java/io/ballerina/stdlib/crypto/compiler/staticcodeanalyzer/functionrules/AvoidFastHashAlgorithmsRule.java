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

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getStringValue;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_FAST_HASH_ALGORITHMS;

/**
 * Rule to avoid fast hash algorithms.
 * Analyzes the usage of bcrypt, argon2, and pbkdf2 hashing functions with weak parameters.
 *
 * @since 2.9.1
 */
public class AvoidFastHashAlgorithmsRule implements CryptoFunctionRule {

    public static final String HASH_BCRYPT = "hashBcrypt";
    public static final String HASH_ARGON2 = "hashArgon2";
    public static final String HASH_PBKDF2 = "hashPbkdf2";
    public static final String WORK_FACTOR = "workFactor";
    public static final String ITERATIONS = "iterations";
    public static final String MEMORY = "memory";
    public static final String PARALLELISM = "parallelism";
    public static final String ALGORITHM = "algorithm";
    public static final String HMAC_SHA1 = "SHA1";
    public static final String HMAC_SHA256 = "SHA256";
    public static final String HMAC_SHA512 = "SHA512";

    public static final int BCRYPT_RECOMMENDED_WORK_FACTOR = 10;
    public static final int ARGON2_RECOMMENDED_ITERATIONS = 2;
    public static final int ARGON2_RECOMMENDED_MEMORY = 19456;
    public static final int PBKDF2_RECOMMENDED_ITERATIONS_FOR_SHA1 = 1300000;
    public static final int PBKDF2_RECOMMENDED_ITERATIONS_FOR_SHA256 = 600000;
    public static final int PBKDF2_RECOMMENDED_ITERATIONS_FOR_SHA512 = 210000;

    @Override
    public void analyze(FunctionContext context) {
        if (isBCryptWithLowWorkFactor(context) || isArgon2WithWeakParams(context)
                || isPBKDF2WithLowIterations(context)) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_FAST_HASH_ALGORITHMS.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        String functionName = context.functionName();
        return functionName.equals(HASH_BCRYPT) || functionName.equals(HASH_ARGON2)
                || functionName.equals(HASH_PBKDF2);
    }

    private boolean isBCryptWithLowWorkFactor(FunctionContext context) {
        if (!context.functionName().equals(HASH_BCRYPT)) {
            return false;
        }
        SemanticModel semanticModel = context.semanticModel();
        Optional<ExpressionNode> workFactorOpt = context.getParamExpression(WORK_FACTOR);
        // If work factor is not provided, default is 12 which is considered secure
        return workFactorOpt
                .filter(expr -> hasLowerIntegerValue(expr, BCRYPT_RECOMMENDED_WORK_FACTOR, semanticModel))
                .isPresent();

    }

    private boolean isArgon2WithWeakParams(FunctionContext context) {
        if (!context.functionName().equals(HASH_ARGON2)) {
            return false;
        }
        SemanticModel semanticModel = context.semanticModel();
        // Check if any parameter is below the recommended threshold
        // Parallelism should be a positive integer value and the minimum recommended value is 1
        // So, we do not need to check for parallelism here
        return isArgon2ParamBelowThreshold(context, ITERATIONS, ARGON2_RECOMMENDED_ITERATIONS, semanticModel) ||
               isArgon2ParamBelowThreshold(context, MEMORY, ARGON2_RECOMMENDED_MEMORY, semanticModel);
    }

    private boolean isArgon2ParamBelowThreshold(FunctionContext context, String paramName,
                                                int recommendedValue, SemanticModel semanticModel) {
        Optional<ExpressionNode> paramOpt = context.getParamExpression(paramName);
        // If parameter is not provided, defaults are used which are considered secure
        // Default iterations: 3, Default memory: 65536, Default parallelism: 4
        return paramOpt
                .filter(expr -> hasLowerIntegerValue(expr, recommendedValue, semanticModel))
                .isPresent();
    }

    private boolean isPBKDF2WithLowIterations(FunctionContext context) {
        if (!context.functionName().equals(HASH_PBKDF2)) {
            return false;
        }

        // If algorithm is not provided, default is HMAC_SHA256
        String algorithm = getStringValue(ALGORITHM, context).orElse(HMAC_SHA256);

        SemanticModel semanticModel = context.semanticModel();
        Optional<ExpressionNode> iterationsOpt = context.getParamExpression(ITERATIONS);
        if (iterationsOpt.isEmpty()) {
            // Default iterations for is 10000 which is lower than recommended for all algorithms
            return true;
        }

        int recommendedIterations = getRecommendedIterationsForPBKDF2(algorithm);
        return hasLowerIntegerValue(iterationsOpt.get(), recommendedIterations, semanticModel);
    }

    private static int getRecommendedIterationsForPBKDF2(String algorithm) {
        return switch (algorithm) {
            case HMAC_SHA1 -> PBKDF2_RECOMMENDED_ITERATIONS_FOR_SHA1;
            case HMAC_SHA256 -> PBKDF2_RECOMMENDED_ITERATIONS_FOR_SHA256;
            case HMAC_SHA512 -> PBKDF2_RECOMMENDED_ITERATIONS_FOR_SHA512;
            default -> throw new IllegalArgumentException("Unsupported HMAC algorithm: " + algorithm +
                    " found for PBKDF2 hashing function");
        };
    }

    private static boolean hasLowerIntegerValue(ExpressionNode valueExpr, Integer targetValue,
                                                SemanticModel semanticModel) {
        if (valueExpr.kind().equals(SyntaxKind.NUMERIC_LITERAL)) {
            String iterationsValue = ((BasicLiteralNode) valueExpr).literalToken().text();
            try {
                int iterationsInt = Integer.parseInt(iterationsValue);
                return iterationsInt < targetValue;
            } catch (NumberFormatException e) {
                // Ignore and continue
            }
        } else if (valueExpr instanceof NameReferenceNode refNode) {
            Optional<Symbol> refSymbol = semanticModel.symbol(refNode);
            if (refSymbol.isPresent() && refSymbol.get() instanceof ConstantSymbol constantRef &&
                    constantRef.constValue() instanceof ConstantValue constantValue &&
                    constantValue.value() instanceof Long longValue) {
                return longValue < targetValue;
            }
        }
        return false;
    }
}
