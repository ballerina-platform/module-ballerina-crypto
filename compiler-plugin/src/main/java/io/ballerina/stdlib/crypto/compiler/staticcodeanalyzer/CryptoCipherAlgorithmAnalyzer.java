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

import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.QualifiedNameReferenceNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

/**
 * Analyzes the syntax tree for function calls to crypto module functions and checks for weak cipher algorithms.
 * It reports issues related to the use of weak cipher algorithms.
 */
public class CryptoCipherAlgorithmAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;
    private static final String CRYPTO = "crypto";
    private static final String ENCRYPT_AES_ECB = "encryptAesEcb";
    private static final String ENCRYPT_AES_CBC = "encryptAesCbc";

    public CryptoCipherAlgorithmAnalyzer(Reporter reporter) {
        this.reporter = reporter;
    }

    /**
     * Analyzes the syntax tree for function calls to crypto module functions.
     *
     * @param context the syntax node analysis context
     */
    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        FunctionCallExpressionNode functionCall = (FunctionCallExpressionNode) context.node();

        if (!(functionCall.functionName() instanceof QualifiedNameReferenceNode qualifiedName)) {
            return;
        }

        if (!CRYPTO.equals(qualifiedName.modulePrefix().text())) {
            return;
        }

        String functionName = qualifiedName.identifier().text();

        if (isWeakCipherFunction(functionName)) {
            report(context, CryptoRule.AVOID_WEAK_CIPHER_ALGORITHMS.getId());
        }
    }

    /**
     * Checks if the given function name corresponds to a weak cipher function.
     *
     * @param functionName the name of the function
     * @return true if the function is a weak cipher function, false otherwise
     */
    private boolean isWeakCipherFunction(String functionName) {
        return ENCRYPT_AES_ECB.equals(functionName) || ENCRYPT_AES_CBC.equals(functionName);
    }

    /**
     * Reports an issue for the given context and rule ID.
     *
     * @param context the syntax node analysis context
     * @param ruleId  the ID of the rule to report
     */
    private void report(SyntaxNodeAnalysisContext context, int ruleId) {
        reporter.reportIssue(
                getDocument(context.currentPackage().module(context.moduleId()), context.documentId()),
                context.node().location(),
                ruleId
        );
    }

    /**
     * Retrieves the Document corresponding to the given module and document ID.
     *
     * @param module     the module
     * @param documentId the document ID
     * @return the Document for the given module and document ID
     */
    private static Document getDocument(Module module, DocumentId documentId) {
        return module.document(documentId);
    }
}
