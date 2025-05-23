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
 * Analyzes Crypto cipher algorithm usage in Ballerina code to detect weak cipher algorithms.
 *<p>
 * This analyzer checks for the usage of weak cipher algorithms such as AES in ECB and CBC modes.
 * It reports an issue if any of these algorithms are found in the code.
 *</p>
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
     * Analyzes the given context to check for weak cipher algorithms.
     *
     * @param context the syntax node analysis context
     */
    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        FunctionCallExpressionNode functionCall = (FunctionCallExpressionNode) context.node();

        if (!(functionCall.functionName() instanceof QualifiedNameReferenceNode qualifiedName)) {
            return;
        }

        if (CRYPTO.equals(qualifiedName.modulePrefix().text())
                && (ENCRYPT_AES_ECB.equals(qualifiedName.identifier().text()) ||
                ENCRYPT_AES_CBC.equals(qualifiedName.identifier().text()))) {
            reporter.reportIssue(
                    getDocument(context.currentPackage().module(context.moduleId()), context.documentId()),
                    context.node().location(),
                    CryptoRule.AVOID_WEAK_CIPHER_ALGORITHMS.getId()
            );
        }
    }

    /**
     * Retrieves the Document corresponding to the given module and document ID.
     *
     * @param module     the module
     * @param documentId the document ID
     * @return the Document for the given module and document ID
     */
    private static Document getDocument(Module module,
                                        DocumentId documentId) {
        return module.document(documentId);
    }
}
