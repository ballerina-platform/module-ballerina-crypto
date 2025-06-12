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

import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.ImportOrgNameNode;
import io.ballerina.compiler.syntax.tree.ImportPrefixNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.NamedArgumentNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.PositionalArgumentNode;
import io.ballerina.compiler.syntax.tree.QualifiedNameReferenceNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.HashSet;
import java.util.Set;

/**
 * Analyzes the syntax tree for function calls and checks for weak cipher and
 * hash algorithms in the crypto module.
 * It reports issues related to the use of weak cipher algorithms such as AES in
 * ECB and CBC modes,
 * and weak hash algorithms like bcrypt, Argon2, and PBKDF2 with insufficient
 * parameters.
 */
public class CryptoCipherAlgorithmAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;
    private static final String BALLERINA_ORG = "ballerina";
    private static final String CRYPTO = "crypto";
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

        if (CryptoAnalyzerUtils.isWeakCipherFunction(functionName)) {
            report(context, CryptoRule.AVOID_WEAK_CIPHER_ALGORITHMS.getId());
        }

        if (CryptoAnalyzerUtils.requiresSecureIV(functionName)) {
            checkHardcodedIVUsage(functionCall, context);
        }

        if (CryptoAnalyzerUtils.HASH_BCRYPT.equals(functionName)) {
            checkWeakBcryptUsage(functionCall, context);
        } else if (CryptoAnalyzerUtils.HASH_ARGON2.equals(functionName)) {
            checkWeakArgon2Usage(functionCall, context);
        } else if (CryptoAnalyzerUtils.HASH_PBKDF2.equals(functionName)) {
            checkWeakPbkdf2Usage(functionCall, context);
        }
    }

    /**
     * Checks if the bcrypt hash function is used with weak parameters.
     *
     * @param functionCall the function call node
     * @param context      the syntax node analysis context
     */
    private void checkWeakBcryptUsage(FunctionCallExpressionNode functionCall, SyntaxNodeAnalysisContext context) {
        if (functionCall.arguments().stream().count() < 2) {
            return;
        }

        Node workFactor = functionCall.arguments().get(1);

        if (workFactor instanceof PositionalArgumentNode positional) {
            ExpressionNode expr = positional.expression();
            if (CryptoAnalyzerUtils.isWeakBcryptParameter(expr)) {
                report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
            }
        } else if (workFactor instanceof NamedArgumentNode named) {
            ExpressionNode expr = named.expression();
            if (CryptoAnalyzerUtils.isWeakBcryptParameter(expr)) {
                report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
            }
        }
    }

    /**
     * Checks if the Argon2 hash function is used with weak parameters.
     *
     * @param functionCall the function call node
     * @param context      the syntax node analysis context
     */
    private void checkWeakArgon2Usage(FunctionCallExpressionNode functionCall, SyntaxNodeAnalysisContext context) {
        // Check if there are enough arguments to analyze
        int argsCount = (int) functionCall.arguments().stream().count();
        if (argsCount < 2) {
            return;
        }

        boolean hasWeakParameters = false;

        // Check for named arguments
        for (Node arg : functionCall.arguments()) {
            if (arg instanceof NamedArgumentNode named) {
                String paramName = named.argumentName().name().text();
                ExpressionNode expr = named.expression();

                if (CryptoAnalyzerUtils.ITERATIONS.equals(paramName)) {
                    hasWeakParameters |= CryptoAnalyzerUtils.isWeakArgon2Parameter(expr,
                            CryptoAnalyzerUtils.ArgonParameter.ITERATIONS);
                } else if (CryptoAnalyzerUtils.MEMORY.equals(paramName)) {
                    hasWeakParameters |= CryptoAnalyzerUtils.isWeakArgon2Parameter(expr,
                            CryptoAnalyzerUtils.ArgonParameter.MEMORY);
                } else if (CryptoAnalyzerUtils.PARALLELISM.equals(paramName)) {
                    hasWeakParameters |= CryptoAnalyzerUtils.isWeakArgon2Parameter(expr,
                            CryptoAnalyzerUtils.ArgonParameter.PARALLELISM);
                }
            }
        }

        // Check for positional arguments
        if (functionCall.arguments().get(1) instanceof PositionalArgumentNode iterationsArg) {
            hasWeakParameters |= CryptoAnalyzerUtils.isWeakArgon2Parameter(iterationsArg.expression(),
                    CryptoAnalyzerUtils.ArgonParameter.ITERATIONS);
        }

        if (argsCount >= 3 && functionCall.arguments().get(2) instanceof PositionalArgumentNode memoryArg) {
            hasWeakParameters |= CryptoAnalyzerUtils.isWeakArgon2Parameter(memoryArg.expression(),
                    CryptoAnalyzerUtils.ArgonParameter.MEMORY);
        }

        if (argsCount >= 4 && functionCall.arguments().get(3) instanceof PositionalArgumentNode parallelismArg) {
            hasWeakParameters |= CryptoAnalyzerUtils.isWeakArgon2Parameter(parallelismArg.expression(),
                    CryptoAnalyzerUtils.ArgonParameter.PARALLELISM);
        }

        if (hasWeakParameters) {
            report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
        }
    }

    /**
     * Checks if the PBKDF2 hash function is used with weak parameters.
     *
     * @param functionCall the function call node
     * @param context      the syntax node analysis context
     */
    private void checkWeakPbkdf2Usage(FunctionCallExpressionNode functionCall, SyntaxNodeAnalysisContext context) {
        // Check if there are enough arguments to analyze
        int argsCount = (int) functionCall.arguments().stream().count();
        if (argsCount < 2) {
            report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
            return;
        }

        boolean hasWeakParameters = false;

        // Check for named arguments
        for (Node arg : functionCall.arguments()) {
            if (arg instanceof NamedArgumentNode named) {
                String paramName = named.argumentName().name().text();
                if (CryptoAnalyzerUtils.ITERATIONS.equals(paramName)) {
                    hasWeakParameters |= CryptoAnalyzerUtils.isWeakPbkdf2Parameter(named.expression());
                }
            }
        }

        // Check for positional arguments
        if (functionCall.arguments().get(1) instanceof PositionalArgumentNode iterationsArg) {
            hasWeakParameters |= CryptoAnalyzerUtils.isWeakPbkdf2Parameter(iterationsArg.expression());
        }

        if (hasWeakParameters) {
            report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
        }
    }

    /**
     * Checks if the AES-GCM function is used with hardcoded initialization vectors.
     * For encryptAesGcm(input, key, iv, padding, tagSize), the third parameter (iv)
     * is checked.
     *
     * @param functionCall the function call node
     * @param context      the syntax node analysis context
     */
    private void checkHardcodedIVUsage(FunctionCallExpressionNode functionCall, SyntaxNodeAnalysisContext context) {
        // Check if there are enough arguments to analyze
        if (functionCall.arguments().stream().count() < 3) {
            return;
        }

        Node ivArgument = functionCall.arguments().get(2);

        // Check for positional arguments
        if (ivArgument instanceof PositionalArgumentNode positional) {
            ExpressionNode expr = positional.expression();
            if (CryptoAnalyzerUtils.isHardcodedIV(expr)) {
                report(context, CryptoRule.AVOID_HARDCODED_INITIALIZATION_VECTORS.getId());
            }
        } else if (ivArgument instanceof NamedArgumentNode named) {
            // Check for named arguments
            String paramName = named.argumentName().name().text();
            if ("iv".equals(paramName)) {
                ExpressionNode expr = named.expression();
                if (CryptoAnalyzerUtils.isHardcodedIV(expr)) {
                    report(context, CryptoRule.AVOID_HARDCODED_INITIALIZATION_VECTORS.getId());
                }
            }
        }
    }

    /**
     * Reports an issue for the given context and rule ID.
     *
     * @param context the syntax node analysis context
     * @param ruleId  the ID of the rule to report
     */
    private void report(SyntaxNodeAnalysisContext context, int ruleId) {
        reporter.reportIssue(
                CryptoAnalyzerUtils.getDocument(context.currentPackage().module(context.moduleId()),
                        context.documentId()),
                context.node().location(),
                ruleId);
    }

    /**
     * Analyzes imports to identify all prefixes used for the crypto module.
     *
     * @param context the syntax node analysis context
     */
    private void analyzeImports(SyntaxNodeAnalysisContext context) {
        Document document = CryptoAnalyzerUtils.getDocument(context.currentPackage().module(context.moduleId()),
                context.documentId());

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
