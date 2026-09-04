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
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_HARDCODED_KEY_MATERIAL;

/**
 * Rule to avoid hard-coded key material.
 * <p>
 * A key embedded in source is shared with everyone who can read the repository, cannot be rotated without a code
 * change, and survives in version history after it is removed. Key material belongs in a {@code configurable}
 * variable supplied at deployment.
 * <p>
 * This rule covers byte-array key material only. String literals in credential-shaped fields are covered by the
 * language-level hard-coded secret rule; reporting them here as well would produce two findings for one problem.
 *
 * @since 2.12.2
 */
public class AvoidHardcodedKeyMaterialRule implements CryptoFunctionRule {

    private static final String KEY_PARAM = "key";
    private static final String PASSPHRASE_PARAM = "passphrase";

    // Function name -> the parameter carrying key material
    private static final Map<String, String> KEY_MATERIAL_PARAMS = Map.ofEntries(
            Map.entry("hmacMd5", KEY_PARAM),
            Map.entry("hmacSha1", KEY_PARAM),
            Map.entry("hmacSha256", KEY_PARAM),
            Map.entry("hmacSha384", KEY_PARAM),
            Map.entry("hmacSha512", KEY_PARAM),
            Map.entry("encryptAesCbc", KEY_PARAM),
            Map.entry("encryptAesEcb", KEY_PARAM),
            Map.entry("encryptAesGcm", KEY_PARAM),
            Map.entry("decryptAesCbc", KEY_PARAM),
            Map.entry("decryptAesEcb", KEY_PARAM),
            Map.entry("decryptAesGcm", KEY_PARAM),
            Map.entry("decryptPgp", PASSPHRASE_PARAM),
            Map.entry("decryptStreamFromPgp", PASSPHRASE_PARAM));

    private static final Set<String> APPLICABLE_FUNCTIONS = KEY_MATERIAL_PARAMS.keySet();

    @Override
    public void analyze(FunctionContext context) {
        Optional<ExpressionNode> keyExpression =
                context.getRawParamExpression(KEY_MATERIAL_PARAMS.get(context.functionName()));
        if (keyExpression.isPresent() && CryptoAnalyzerUtils.isByteArrayLiteral(keyExpression.get())) {
            context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
        }
    }

    @Override
    public int getRuleId() {
        return AVOID_HARDCODED_KEY_MATERIAL.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        return APPLICABLE_FUNCTIONS.contains(context.functionName());
    }
}
