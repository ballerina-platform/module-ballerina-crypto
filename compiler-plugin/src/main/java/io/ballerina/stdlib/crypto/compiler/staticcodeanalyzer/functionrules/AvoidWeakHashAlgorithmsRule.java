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

import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.FunctionContext;

import java.util.Set;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoRule.AVOID_WEAK_HASH_ALGORITHMS;

/**
 * Rule to avoid MD5 and SHA-1 for hashing, message authentication and digital signatures.
 * <p>
 * Both algorithms are broken for security purposes: practical collisions exist for MD5 and SHA-1, so neither
 * provides the collision resistance that integrity checking and signature verification depend on. SHA-256 or
 * stronger should be used instead.
 * <p>
 * This rule is distinct from {@code crypto:2}, which covers the parameters of the password hashing functions.
 * Here the algorithm itself is unsuitable regardless of how it is configured.
 *
 * @since 2.12.2
 */
public class AvoidWeakHashAlgorithmsRule implements CryptoFunctionRule {

    private static final Set<String> WEAK_ALGORITHM_FUNCTIONS = Set.of(
            // Hashing
            "hashMd5",
            "hashSha1",
            // Message authentication
            "hmacMd5",
            "hmacSha1",
            // Digital signatures
            "signRsaMd5",
            "signRsaSha1",
            // Signature verification
            "verifyRsaMd5Signature",
            "verifyRsaSha1Signature"
    );

    @Override
    public void analyze(FunctionContext context) {
        context.reporter().reportIssue(context.document(), context.functionLocation(), getRuleId());
    }

    @Override
    public int getRuleId() {
        return AVOID_WEAK_HASH_ALGORITHMS.getId();
    }

    @Override
    public boolean isApplicable(FunctionContext context) {
        return WEAK_ALGORITHM_FUNCTIONS.contains(context.functionName());
    }
}
