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
    AVOID_WEAK_CIPHER_ALGORITHMS(createRule(1,
            "Avoid using insecure cipher modes or padding schemes", VULNERABILITY)),
    AVOID_FAST_HASH_ALGORITHMS(createRule(2,
            "Avoid using fast hashing algorithms", VULNERABILITY)),
    AVOID_REUSING_COUNTER_MODE_VECTORS(createRule(3,
            "Avoid reusing counter mode initialization vectors", VULNERABILITY)),
    AVOID_WEAK_HASH_ALGORITHMS(createRule(4,
            "Avoid using weak hashing and signature algorithms", VULNERABILITY)),
    AVOID_HARDCODED_KEY_MATERIAL(createRule(5,
            "Avoid hard-coded key material", VULNERABILITY)),
    AVOID_WEAK_PGP_ALGORITHMS(createRule(6,
            "Avoid using weak symmetric algorithms for PGP encryption", VULNERABILITY)),
    ENSURE_PGP_INTEGRITY_CHECK(createRule(7,
            "Avoid disabling integrity protection for PGP encryption", VULNERABILITY)),
    AVOID_SHORT_AUTHENTICATION_TAGS(createRule(8,
            "Avoid using short authentication tags for counter mode encryption", VULNERABILITY)),
    ENSURE_SIGNATURE_VERIFICATION(createRule(9,
            "Avoid discarding the result of a signature verification", VULNERABILITY));

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
