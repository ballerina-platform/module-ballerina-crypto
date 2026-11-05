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

import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Optional;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.isByteArrayLiteral;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_HARD_CODED_INITIALIZATION_VECTORS;

/**
 * Rule to avoid hard-coded initialization vectors (IVs) in AES-CBC and AES-GCM encryption.
 *
 * @since 2.9.1
 */
public class AvoidHardCodedInitializationVectorsRule implements CryptoFunctionRule {

    public static final String ENCRYPT_AES_CBC = "encryptAesCbc";
    public static final String ENCRYPT_AES_GCM = "encryptAesGcm";
    public static final String INITIALIZATION_VECTOR = "iv";

    @Override
    public void analyze(FunctionContext context) {
        Optional<ExpressionNode> paramExpression = context.getRawParamExpression(INITIALIZATION_VECTOR);
        if (paramExpression.isEmpty()) {
            // The IV is a required parameter for these functions, so this case should not occur.
            throw new IllegalStateException("Initialization vector parameter is missing for function: "
                    + context.functionName());
        }

        if (isByteArrayLiteral(paramExpression.get(), context, context::resolve)) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_HARD_CODED_INITIALIZATION_VECTORS.getId();

    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        String functionName = context.functionName();
        return functionName.equals(ENCRYPT_AES_CBC) || functionName.equals(ENCRYPT_AES_GCM);
    }
}
