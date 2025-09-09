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

import io.ballerina.compiler.syntax.tree.BasicLiteralNode;
import io.ballerina.compiler.syntax.tree.CaptureBindingPatternNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionBodyBlockNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.ImportOrgNameNode;
import io.ballerina.compiler.syntax.tree.ImportPrefixNode;
import io.ballerina.compiler.syntax.tree.ModuleMemberDeclarationNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.ModuleVariableDeclarationNode;
import io.ballerina.compiler.syntax.tree.NamedArgumentNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.NodeList;
import io.ballerina.compiler.syntax.tree.PositionalArgumentNode;
import io.ballerina.compiler.syntax.tree.QualifiedNameReferenceNode;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.HashSet;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

/**
 * Analyzes the syntax tree for function calls and checks for weak cipher and hash algorithms in the crypto module.
 * It reports issues related to the use of weak cipher algorithms such as AES in ECB and CBC modes,
 * and weak hash algorithms like bcrypt, Argon2, and PBKDF2 with insufficient parameters.
 */
public class CryptoCipherAlgorithmAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {
    private final Reporter reporter;
    private static final String BALLERINA_ORG = "ballerina";
    private static final String CRYPTO = "crypto";
    private static final String ENCRYPT_AES_ECB = "encryptAesEcb";
    private static final String ENCRYPT_AES_CBC = "encryptAesCbc";
    private static final String HASH_BCRYPT = "hashBcrypt";
    private static final String HASH_ARGON2 = "hashArgon2";
    private static final String HASH_PBKDF2 = "hashPbkdf2";
    private static final String ITERATIONS = "iterations";
    private static final String MEMORY = "memory";
    private static final String PARALLELISM = "parallelism";
    private static final int BCRYPT_RECOMMENDED_WORK_FACTOR = 10;
    private static final int ARGON2_RECOMMENDED_ITERATIONS = 2;
    private static final int ARGON2_RECOMMENDED_MEMORY = 19456;
    private static final int ARGON2_RECOMMENDED_PARALLELISM = 1;
    private static final int PBKDF2_RECOMMENDED_ITERATIONS = 100000;
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
        if (HASH_BCRYPT.equals(functionName)) {
            checkWeakBcryptUsage(functionCall, context);
        } else if (HASH_ARGON2.equals(functionName)) {
            checkWeakArgon2Usage(functionCall, context);
        } else if (HASH_PBKDF2.equals(functionName)) {
            checkWeakPbkdf2Usage(functionCall, context);
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
     * Checks if the bcrypt hash function is used with weak parameters.
     *
     * @param functionCall the function call node
     * @param context      the syntax node analysis context
     */
    private void checkWeakBcryptUsage(FunctionCallExpressionNode functionCall, SyntaxNodeAnalysisContext context) {
        if (functionCall.arguments().size() < 2) {
            return;
        }

        Node workFactor = functionCall.arguments().get(1);

        if (workFactor instanceof PositionalArgumentNode positional) {
            ExpressionNode expr = positional.expression();
            if (isWeakBcryptParameter(expr)) {
                report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
            }
        } else if (workFactor instanceof NamedArgumentNode named) {
            ExpressionNode expr = named.expression();
            if (isWeakBcryptParameter(expr)) {
                report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
            }
        }
    }

    /**
     * Checks if the given expression represents a weak bcrypt work factor.
     *
     * @param expression the expression to check
     * @return true if the work factor is weak, false otherwise
     */
    private boolean isWeakBcryptParameter(ExpressionNode expression) {
        if (expression instanceof BasicLiteralNode basicLiteral) {
            try {
                return Integer.parseInt(basicLiteral.literalToken().text()) < BCRYPT_RECOMMENDED_WORK_FACTOR;
            } catch (NumberFormatException e) {
                return false;
            }
        } else if (expression instanceof SimpleNameReferenceNode varRef) {
            return hasWeakParameterSettings(varRef, this::isWeakBcryptVariable);
        }
        return false;
    }

    /**
     * Checks if the Argon2 hash function is used with weak parameters.
     *
     * @param functionCall the function call node
     * @param context      the syntax node analysis context
     */
    private void checkWeakArgon2Usage(FunctionCallExpressionNode functionCall, SyntaxNodeAnalysisContext context) {
        // Check if there are enough arguments to analyze
        int argsCount = functionCall.arguments().size();
        if (argsCount < 2) {
            return;
        }

        boolean hasWeakParameters = false;

        // Check for named arguments
        for (Node arg : functionCall.arguments()) {
            if (arg instanceof NamedArgumentNode named) {
                String paramName = named.argumentName().name().text();
                ExpressionNode expr = named.expression();

                if (ITERATIONS.equals(paramName)) {
                    hasWeakParameters |= isWeakArgon2Parameter(expr, ArgonParameter.ITERATIONS);
                } else if (MEMORY.equals(paramName)) {
                    hasWeakParameters |= isWeakArgon2Parameter(expr, ArgonParameter.MEMORY);
                } else if (PARALLELISM.equals(paramName)) {
                    hasWeakParameters |= isWeakArgon2Parameter(expr, ArgonParameter.PARALLELISM);
                }
            }
        }

        // Check for positional arguments
        if (functionCall.arguments().get(1) instanceof PositionalArgumentNode iterationsArg) {
            hasWeakParameters |= isWeakArgon2Parameter(iterationsArg.expression(), ArgonParameter.ITERATIONS);
        }

        if (argsCount >= 3 && functionCall.arguments().get(2) instanceof PositionalArgumentNode memoryArg) {
            hasWeakParameters |= isWeakArgon2Parameter(memoryArg.expression(), ArgonParameter.MEMORY);
        }

        if (argsCount >= 4 && functionCall.arguments().get(3) instanceof PositionalArgumentNode parallelismArg) {
            hasWeakParameters |= isWeakArgon2Parameter(parallelismArg.expression(), ArgonParameter.PARALLELISM);
        }

        if (hasWeakParameters) {
            report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
        }
    }

    /**
     * Enum representing the different parameters of Argon2.
     */
    private enum ArgonParameter {
        ITERATIONS,
        MEMORY,
        PARALLELISM
    }

    /**
     * Checks if the given expression represents a weak Argon2 parameter value.
     *
     * @param expression the expression to check
     * @param paramType  the parameter type (iterations, memory, or parallelism)
     * @return true if the parameter is weak, false otherwise
     */
    private boolean isWeakArgon2Parameter(ExpressionNode expression, ArgonParameter paramType) {
        if (expression instanceof BasicLiteralNode basicLiteral) {
            try {
                int value = Integer.parseInt(basicLiteral.literalToken().text());
                return switch (paramType) {
                    case ITERATIONS -> value < ARGON2_RECOMMENDED_ITERATIONS;
                    case MEMORY -> value < ARGON2_RECOMMENDED_MEMORY;
                    case PARALLELISM -> value < ARGON2_RECOMMENDED_PARALLELISM;
                };
            } catch (NumberFormatException e) {
                return false;
            }
        } else if (expression instanceof SimpleNameReferenceNode varRef) {
            return hasWeakParameterSettings(varRef, (stmt, varName) -> isWeakArgon2Variable(stmt, varName, paramType));
        }
        return false;
    }

    /**
     * Checks if the PBKDF2 hash function is used with weak parameters.
     *
     * @param functionCall the function call node
     * @param context      the syntax node analysis context
     */
    private void checkWeakPbkdf2Usage(FunctionCallExpressionNode functionCall, SyntaxNodeAnalysisContext context) {
        // Check if there are enough arguments to analyze
        int argsCount = functionCall.arguments().size();
        if (argsCount < 2) {
            report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
            return;
        }

        boolean hasWeakParameters = false;

        // Check for named arguments
        for (Node arg : functionCall.arguments()) {
            if (arg instanceof NamedArgumentNode named) {
                String paramName = named.argumentName().name().text();
                if (ITERATIONS.equals(paramName)) {
                    hasWeakParameters |= isWeakPbkdf2Parameter(named.expression());
                }
            }
        }

        // Check for positional arguments
        if (functionCall.arguments().get(1) instanceof PositionalArgumentNode iterationsArg) {
            hasWeakParameters |= isWeakPbkdf2Parameter(iterationsArg.expression());
        }

        if (hasWeakParameters) {
            report(context, CryptoRule.AVOID_FAST_HASH_ALGORITHMS.getId());
        }
    }

    /**
     * Checks if the given expression represents a weak PBKDF2 iterations count.
     *
     * @param expression the expression to check
     * @return true if the iterations count is weak, false otherwise
     */
    private boolean isWeakPbkdf2Parameter(ExpressionNode expression) {
        if (expression instanceof BasicLiteralNode basicLiteral) {
            try {
                int value = Integer.parseInt(basicLiteral.literalToken().text());
                return value < PBKDF2_RECOMMENDED_ITERATIONS;
            } catch (NumberFormatException e) {
                return false;
            }
        } else if (expression instanceof SimpleNameReferenceNode varRef) {
            return hasWeakParameterSettings(varRef, this::isWeakPbkdf2Variable);
        }
        return false;
    }

    /**
     * Checks if the given statement declares a variable with a weak bcrypt work factor.
     *
     * @param stmt    the statement to check
     * @param varName the name of the variable
     * @return true if the statement declares a variable with a weak bcrypt work factor, false otherwise
     */
    private boolean isWeakBcryptVariable(Node stmt, String varName) {
        return isWeakVariableWithInitializer(stmt, varName, initText -> {
            try {
                return Integer.parseInt(initText) < BCRYPT_RECOMMENDED_WORK_FACTOR;
            } catch (NumberFormatException e) {
                return false;
            }
        });
    }

    /**
     * Checks if the given statement declares a variable with a weak Argon2 parameter value.
     *
     * @param stmt      the statement to check
     * @param varName   the name of the variable
     * @param paramType the parameter type (iterations, memory, or parallelism)
     * @return true if the statement declares a variable with a weak parameter value, false otherwise
     */
    private boolean isWeakArgon2Variable(Node stmt, String varName, ArgonParameter paramType) {
        return isWeakVariableWithInitializer(stmt, varName, initText -> {
            try {
                int value = Integer.parseInt(initText);
                return switch (paramType) {
                    case ITERATIONS -> value < ARGON2_RECOMMENDED_ITERATIONS;
                    case MEMORY -> value < ARGON2_RECOMMENDED_MEMORY;
                    case PARALLELISM -> value < ARGON2_RECOMMENDED_PARALLELISM;
                };
            } catch (NumberFormatException e) {
                return false;
            }
        });
    }

    /**
     * Checks if the given statement declares a variable with a weak PBKDF2 iterations count.
     *
     * @param stmt    the statement to check
     * @param varName the name of the variable
     * @return true if the statement declares a variable with a weak iterations count, false otherwise
     */
    private boolean isWeakPbkdf2Variable(Node stmt, String varName) {
        return isWeakVariableWithInitializer(stmt, varName, this::checkPbkdf2InitializerValue);
    }

    /**
     * Checks if the given initializer value is a weak PBKDF2 iterations count.
     *
     * @param initText the initializer text
     * @return true if the initializer value is weak, false otherwise
     */
    private boolean checkPbkdf2InitializerValue(String initText) {
        try {
            int value = Integer.parseInt(initText);
            return value < PBKDF2_RECOMMENDED_ITERATIONS;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Generic method to check if a variable declaration has a weak initializer value.
     *
     * @param stmt               the statement to check
     * @param varName            the name of the variable
     * @param initializerChecker predicate to check if the initializer value is weak
     * @return true if the statement declares a variable with a weak value, false otherwise
     */
    private boolean isWeakVariableWithInitializer(Node stmt, String varName, Predicate<String> initializerChecker) {
        if (stmt instanceof VariableDeclarationNode varDecl &&
                varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode capture &&
                capture.variableName().text().equals(varName) &&
                varDecl.initializer().isPresent() &&
                varDecl.initializer().get() instanceof BasicLiteralNode basicLiteral) {
            return initializerChecker.test(basicLiteral.literalToken().text());
        }

        if (stmt instanceof ModuleVariableDeclarationNode varDecl &&
                varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode capture &&
                capture.variableName().text().equals(varName) &&
                varDecl.initializer().isPresent() &&
                varDecl.initializer().get() instanceof BasicLiteralNode basicLiteral) {
            return initializerChecker.test(basicLiteral.literalToken().text());
        }

        return false;
    }

    /**
     * Checks if the given variable reference refers to a variable with a weak parameter value.
     *
     * @param varRef  the variable reference
     * @param checker predicate to check if a statement declares a variable with a weak value
     * @return true if the variable has a weak parameter value, false otherwise
     */
    private boolean hasWeakParameterSettings(SimpleNameReferenceNode varRef, BiPredicate<Node, String> checker) {
        String varName = varRef.name().text();
        return hasWeakParameterInScope(varRef.parent(), varName, checker);
    }

    /**
     * Checks if a variable with the given name has weak parameter values within a specific scope.
     *
     * @param startNode the node to start searching from
     * @param varName   the name of the variable
     * @param checker   predicate to check if a statement declares a variable with a weak value
     * @return true if a weak parameter value is found, false otherwise
     */
    private boolean hasWeakParameterInScope(Node startNode, String varName, BiPredicate<Node, String> checker) {
        Node current = startNode;
        while (current != null) {
            if (current instanceof FunctionBodyBlockNode functionBodyBlock) {
                if (checkStatementsForWeakParameter(functionBodyBlock.statements(), varName, checker)) {
                    return true;
                }
            } else if (current instanceof ModulePartNode modulePart
                    && checkModuleMembersForWeakParameter(modulePart.members(), varName, checker)) {
                return true;
            }

            current = current.parent();
        }
        return false;
    }

    /**
     * Checks a list of statements for a weak parameter value.
     *
     * @param statements the statements to check
     * @param varName    the name of the variable
     * @param checker    predicate to check if a statement declares a variable with a weak value
     * @return true if a weak parameter value is found, false otherwise
     */
    private boolean checkStatementsForWeakParameter(NodeList<StatementNode> statements, String varName,
                                                    BiPredicate<Node, String> checker) {
        for (StatementNode stmt : statements) {
            if (checker.test(stmt, varName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks a list of module members for a weak parameter value.
     *
     * @param members the module members to check
     * @param varName the name of the variable
     * @param checker predicate to check if a statement declares a variable with a weak value
     * @return true if a weak parameter value is found, false otherwise
     */
    private boolean checkModuleMembersForWeakParameter(NodeList<ModuleMemberDeclarationNode> members, String varName,
                                                       BiPredicate<Node, String> checker) {
        for (ModuleMemberDeclarationNode member : members) {
            if (checker.test(member, varName)) {
                return true;
            }
        }
        return false;
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
