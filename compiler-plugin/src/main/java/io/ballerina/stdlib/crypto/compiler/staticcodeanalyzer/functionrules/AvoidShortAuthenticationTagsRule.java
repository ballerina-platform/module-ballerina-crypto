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

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.hasLowerIntegerValue;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_SHORT_AUTHENTICATION_TAGS;

/**
 * Rule to avoid GCM authentication tags shorter than 96 bits.
 * <p>
 * The tag length sets the work an attacker needs to forge a valid ciphertext. The runtime rejects tag sizes below
 * 96 bits, so such a call always returns an error; reporting it at compile time surfaces the mistake before it
 * becomes a run-time failure on every encryption.
 *
 * @since 2.13.1
 */
public class AvoidShortAuthenticationTagsRule implements CryptoFunctionRule {

    private static final String TAG_SIZE_PARAM = "tagSize";
    private static final int MINIMUM_TAG_SIZE = 96;
    private static final Set<String> GCM_FUNCTIONS = Set.of("encryptAesGcm", "decryptAesGcm");

    @Override
    public void analyze(FunctionContext context) {
        Optional<ExpressionNode> tagSize = context.getStableParamExpression(TAG_SIZE_PARAM);
        // If the parameter is absent the default of 128 applies, which is secure.
        if (tagSize.isPresent() && hasLowerIntegerValue(tagSize.get(), MINIMUM_TAG_SIZE, context.semanticModel())) {
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
}
