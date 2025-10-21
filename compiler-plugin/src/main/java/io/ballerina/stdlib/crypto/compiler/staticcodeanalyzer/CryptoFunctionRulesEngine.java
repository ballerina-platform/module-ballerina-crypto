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
package io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer;

import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.functionrules.AvoidFastHashAlgorithmsRule;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.functionrules.AvoidReusingCounterModeVectorsRule;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.functionrules.AvoidWeakCipherAlgorithmsRule;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.functionrules.CryptoFunctionRule;

import java.util.ArrayList;
import java.util.List;

/**
 * Engine to execute crypto function rules.
 *
 * @since 2.9.1
 */
public class CryptoFunctionRulesEngine {

    private final List<CryptoFunctionRule> rules;

    public CryptoFunctionRulesEngine() {
        this.rules = new ArrayList<>();
        initializeDefaultRules();
    }

    public void executeRules(FunctionContext context) {
        for (CryptoFunctionRule rule : rules) {
            if (rule.isApplicable(context)) {
                rule.analyze(context);
            }
        }
    }

    public void addRule(CryptoFunctionRule rule) {
        if (rule != null && !rules.contains(rule)) {
            rules.add(rule);
        }
    }

    private void initializeDefaultRules() {
        addRule(new AvoidWeakCipherAlgorithmsRule());
        addRule(new AvoidFastHashAlgorithmsRule());
        addRule(new AvoidReusingCounterModeVectorsRule());
        // Add more default rules here as needed
    }
}
