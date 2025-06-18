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
import io.ballerina.compiler.syntax.tree.ImportOrgNameNode;
import io.ballerina.compiler.syntax.tree.ImportPrefixNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.QualifiedNameReferenceNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.HashSet;
import java.util.Set;

/**
 * Analyzes the syntax tree for function calls to crypto module functions and checks for weak cipher algorithms.
 */
public class CryptoCipherAlgorithmAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;
    private static final String CRYPTO = "crypto";
    private static final String ENCRYPT_AES_ECB = "encryptAesEcb";
    private static final String ENCRYPT_AES_CBC = "encryptAesCbc";
    private static final String BALLERINA_ORG = "ballerina";
    private final Set<String> cryptoPrefixes = new HashSet<>();

    public CryptoCipherAlgorithmAnalyzer(Reporter reporter) {
        this.reporter = reporter;
        this.cryptoPrefixes.add(CRYPTO);
    }

    /**
     * Analyzes the syntax tree for function calls to crypto module functions.
     *
     * @param context the syntax node analysis context
     */
    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        analyzeImports(context);

        FunctionCallExpressionNode functionCall = (FunctionCallExpressionNode) context.node();

        if (!(functionCall.functionName() instanceof QualifiedNameReferenceNode qualifiedName)) {
            return;
        }

        String modulePrefix = qualifiedName.modulePrefix().text();

        if (!cryptoPrefixes.contains(modulePrefix)) {
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

    /**
     * Analyzes imports to identify all prefixes used for the crypto module.
     *
     * @param context the syntax node analysis context
     */
    private void analyzeImports(SyntaxNodeAnalysisContext context) {
        Document document = getDocument(context.currentPackage().module(context.moduleId()), context.documentId());

        if (document.syntaxTree().rootNode() instanceof ModulePartNode modulePartNode) {
            modulePartNode.imports().forEach(importDeclarationNode -> {
                ImportOrgNameNode importOrgNameNode = importDeclarationNode.orgName().orElse(null);

                if (importOrgNameNode != null && BALLERINA_ORG.equals(importOrgNameNode.orgName().text())
                        && importDeclarationNode.moduleName().stream()
                        .anyMatch(moduleNameNode -> CRYPTO.equals(moduleNameNode.text()))) {

                    ImportPrefixNode importPrefixNode = importDeclarationNode.prefix().orElse(null);
                    String prefix = importPrefixNode != null ? importPrefixNode.prefix().text() : CRYPTO;

                    cryptoPrefixes.add(prefix);
                }
            });
        }
    }
}
