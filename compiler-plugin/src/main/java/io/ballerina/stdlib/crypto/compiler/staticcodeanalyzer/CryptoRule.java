/*
 *  Copyright (c) 2025 WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
 *  OF ANY KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer;

import io.ballerina.scan.Rule;

import static io.ballerina.scan.RuleKind.VULNERABILITY;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.RuleFactory.createRule;

public enum CryptoRule {
    AVOID_WEAK_CIPHER_ALGORITHMS(createRule(1, "An encryption operation uses a cipher mode or padding scheme " +
            "that is known to be insecure.", VULNERABILITY)),
    AVOID_FAST_HASH_ALGORITHMS(createRule(2, "A password hashing function is configured with a work factor " +
            "too low to resist brute-force attacks.", VULNERABILITY)),
    AVOID_HARD_CODED_INITIALIZATION_VECTORS(createRule(3, "An AES-CBC or AES-GCM encryption operation uses a " +
            "hard-coded initialization vector.", VULNERABILITY));

    private final Rule rule;

    CryptoRule(Rule rule) {
        this.rule = rule;
    }

    public int getId() {
        return this.rule.numericId();
    }

    public String getDescription() {
        return this.rule.description();
    }

    @Override
    public String toString() {
        return "{\"id\":" + this.getId() + ", \"kind\":\"" + this.rule.kind() + "\"," +
                " \"description\" : \"" + this.rule.description() + "\"}";
    }
}
