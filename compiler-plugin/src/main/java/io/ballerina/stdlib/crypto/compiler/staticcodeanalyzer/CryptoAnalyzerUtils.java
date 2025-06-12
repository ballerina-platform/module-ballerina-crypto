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
import io.ballerina.compiler.syntax.tree.ModuleMemberDeclarationNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.ModuleVariableDeclarationNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.NodeList;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;

import java.util.function.BiPredicate;
import java.util.function.Predicate;

/**
 * Utility class containing helper methods for crypto cipher algorithm analysis.
 * This class provides common functionality for checking weak parameters and
 * variable analysis.
 */
public final class CryptoAnalyzerUtils {
    // Constants for crypto algorithms and parameters
    public static final String ENCRYPT_AES_ECB = "encryptAesEcb";
    public static final String ENCRYPT_AES_CBC = "encryptAesCbc";
    public static final String ENCRYPT_AES_GCM = "encryptAesGcm";
    public static final String HASH_BCRYPT = "hashBcrypt";
    public static final String HASH_ARGON2 = "hashArgon2";
    public static final String HASH_PBKDF2 = "hashPbkdf2";
    public static final String ITERATIONS = "iterations";
    public static final String MEMORY = "memory";
    public static final String PARALLELISM = "parallelism";
    public static final int BCRYPT_RECOMMENDED_WORK_FACTOR = 10;
    public static final int ARGON2_RECOMMENDED_ITERATIONS = 2;
    public static final int ARGON2_RECOMMENDED_MEMORY = 19456;
    public static final int ARGON2_RECOMMENDED_PARALLELISM = 1;
    public static final int PBKDF2_RECOMMENDED_ITERATIONS = 100000;

    /**
     * Enum representing the different parameters of Argon2.
     */
    public enum ArgonParameter {
        ITERATIONS,
        MEMORY,
        PARALLELISM
    }

    private CryptoAnalyzerUtils() {
        // Prevent instantiation
    }

    /**
     * Checks if the given function name corresponds to a weak cipher function.
     *
     * @param functionName the name of the function
     * @return true if the function is a weak cipher function, false otherwise
     */
    public static boolean isWeakCipherFunction(String functionName) {
        return ENCRYPT_AES_ECB.equals(functionName) || ENCRYPT_AES_CBC.equals(functionName);
    }

    /**
     * Checks if the given function requires secure initialization vectors.
     *
     * @param functionName the name of the function
     * @return true if the function requires secure IVs, false otherwise
     */
    public static boolean requiresSecureIV(String functionName) {
        return ENCRYPT_AES_GCM.equals(functionName);
    }

    /**
     * Checks if the given expression represents a weak bcrypt work factor.
     *
     * @param expression the expression to check
     * @return true if the work factor is weak, false otherwise
     */
    public static boolean isWeakBcryptParameter(ExpressionNode expression) {
        if (expression instanceof BasicLiteralNode basicLiteral) {
            try {
                return Integer.parseInt(basicLiteral.literalToken().text()) < BCRYPT_RECOMMENDED_WORK_FACTOR;
            } catch (NumberFormatException e) {
                return false;
            }
        } else if (expression instanceof SimpleNameReferenceNode varRef) {
            return hasWeakParameterSettings(varRef, CryptoAnalyzerUtils::isWeakBcryptVariable);
        }
        return false;
    }

    /**
     * Checks if the given expression represents a weak Argon2 parameter value.
     *
     * @param expression the expression to check
     * @param paramType  the parameter type (iterations, memory, or parallelism)
     * @return true if the parameter is weak, false otherwise
     */
    public static boolean isWeakArgon2Parameter(ExpressionNode expression, ArgonParameter paramType) {
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
     * Checks if the given expression represents a weak PBKDF2 iterations count.
     *
     * @param expression the expression to check
     * @return true if the iterations count is weak, false otherwise
     */
    public static boolean isWeakPbkdf2Parameter(ExpressionNode expression) {
        if (expression instanceof BasicLiteralNode basicLiteral) {
            try {
                int value = Integer.parseInt(basicLiteral.literalToken().text());
                return value < PBKDF2_RECOMMENDED_ITERATIONS;
            } catch (NumberFormatException e) {
                return false;
            }
        } else if (expression instanceof SimpleNameReferenceNode varRef) {
            return hasWeakParameterSettings(varRef, CryptoAnalyzerUtils::isWeakPbkdf2Variable);
        }
        return false;
    }

    /**
     * Checks if the given statement declares a variable with a weak bcrypt work
     * factor.
     *
     * @param stmt    the statement to check
     * @param varName the name of the variable
     * @return true if the statement declares a variable with a weak bcrypt work
     *         factor, false otherwise
     */
    public static boolean isWeakBcryptVariable(Node stmt, String varName) {
        return isWeakVariableWithInitializer(stmt, varName, initText -> {
            try {
                return Integer.parseInt(initText) < BCRYPT_RECOMMENDED_WORK_FACTOR;
            } catch (NumberFormatException e) {
                return false;
            }
        });
    }

    /**
     * Checks if the given statement declares a variable with a weak Argon2
     * parameter value.
     *
     * @param stmt      the statement to check
     * @param varName   the name of the variable
     * @param paramType the parameter type (iterations, memory, or parallelism)
     * @return true if the statement declares a variable with a weak parameter
     *         value, false otherwise
     */
    public static boolean isWeakArgon2Variable(Node stmt, String varName, ArgonParameter paramType) {
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
     * Checks if the given statement declares a variable with a weak PBKDF2
     * iterations count.
     *
     * @param stmt    the statement to check
     * @param varName the name of the variable
     * @return true if the statement declares a variable with a weak iterations
     *         count, false otherwise
     */
    public static boolean isWeakPbkdf2Variable(Node stmt, String varName) {
        return isWeakVariableWithInitializer(stmt, varName, CryptoAnalyzerUtils::checkPbkdf2InitializerValue);
    }

    /**
     * Checks if the given initializer value is a weak PBKDF2 iterations count.
     *
     * @param initText the initializer text
     * @return true if the initializer value is weak, false otherwise
     */
    public static boolean checkPbkdf2InitializerValue(String initText) {
        try {
            int value = Integer.parseInt(initText);
            return value < PBKDF2_RECOMMENDED_ITERATIONS;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Checks if the given expression represents a hardcoded initialization vector.
     * A hardcoded IV is considered one that contains literal values or array
     * literals.
     *
     * @param expression the expression to check
     * @return true if the expression is a hardcoded IV, false otherwise
     */
    public static boolean isHardcodedIV(ExpressionNode expression) {
        // Check for basic literals like 123, "abc", etc.
        if (expression instanceof BasicLiteralNode) {
            return true;
        } else if (expression instanceof SimpleNameReferenceNode varRef) {
            return hasHardcodedIVDeclaration(varRef);
        }
        // Check for array literals like [1, 2, 3, 4, ...] or byte array constructions
        String sourceCode = expression.toSourceCode().trim();
        return isArrayLiteralPattern(sourceCode);
    }

    /**
     * Checks if the source code represents an array literal pattern that indicates
     * hardcoded values.
     *
     * @param sourceCode the source code to check
     * @return true if it's an array literal pattern, false otherwise
     */
    private static boolean isArrayLiteralPattern(String sourceCode) {
        // Check for patterns like [1, 2, 3, ...] or similar hardcoded array constructions
        if (sourceCode.startsWith("[") && sourceCode.endsWith("]")) {
            String content = sourceCode.substring(1, sourceCode.length() - 1).trim();
            if (content.isEmpty()) {
                return false;
            }
            // Check if content contains only numbers, commas, and whitespace (indicating literal values)
            return content.matches("^[\\d,\\s]+$");
        }
        return false;
    }

    /**
     * Checks if the given variable reference refers to a variable with a hardcoded
     * IV declaration.
     *
     * @param varRef the variable reference
     * @return true if the variable has a hardcoded IV declaration, false otherwise
     */
    private static boolean hasHardcodedIVDeclaration(SimpleNameReferenceNode varRef) {
        String varName = varRef.name().text();
        return hasHardcodedIVInScope(varRef.parent(), varName);
    }

    /**
     * Checks if a variable with the given name has a hardcoded IV declaration
     * within a specific scope.
     *
     * @param startNode the node to start searching from
     * @param varName   the name of the variable
     * @return true if a hardcoded IV declaration is found, false otherwise
     */
    private static boolean hasHardcodedIVInScope(Node startNode, String varName) {
        Node current = startNode;
        while (current != null) {
            if (current instanceof FunctionBodyBlockNode functionBodyBlock) {
                if (checkStatementsForHardcodedIV(functionBodyBlock.statements(), varName)) {
                    return true;
                }
            } else if (current instanceof ModulePartNode modulePart
                    && checkModuleMembersForHardcodedIV(modulePart.members(), varName)) {
                return true;
            }

            current = current.parent();
        }
        return false;
    }

    /**
     * Checks a list of statements for a hardcoded IV declaration.
     *
     * @param statements the statements to check
     * @param varName    the name of the variable
     * @return true if a hardcoded IV declaration is found, false otherwise
     */
    private static boolean checkStatementsForHardcodedIV(NodeList<StatementNode> statements, String varName) {
        for (StatementNode stmt : statements) {
            if (isHardcodedIVVariable(stmt, varName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks a list of module members for a hardcoded IV declaration.
     *
     * @param members the module members to check
     * @param varName the name of the variable
     * @return true if a hardcoded IV declaration is found, false otherwise
     */
    private static boolean checkModuleMembersForHardcodedIV(NodeList<ModuleMemberDeclarationNode> members,
            String varName) {
        for (ModuleMemberDeclarationNode member : members) {
            if (isHardcodedIVVariable(member, varName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the given statement declares a variable with a hardcoded IV value.
     *
     * @param stmt    the statement to check
     * @param varName the name of the variable
     * @return true if the statement declares a variable with a hardcoded IV, false
     *         otherwise
     */
    private static boolean isHardcodedIVVariable(Node stmt, String varName) {
        return isWeakVariableWithInitializer(stmt, varName, CryptoAnalyzerUtils::isHardcodedIVInitializer);
    }

    /**
     * Checks if the given initializer represents a hardcoded IV.
     *
     * @param initText the initializer text
     * @return true if the initializer is a hardcoded IV, false otherwise
     */
    private static boolean isHardcodedIVInitializer(String initText) {
        initText = initText.trim();

        // Check for array literal patterns
        if (isArrayLiteralPattern(initText)) {
            return true;
        }

        // Check for patterns that indicate hardcoded values like byte[16] with literal assignments
        if (initText.contains("[") && initText.contains("]")) {
            return true;
        }

        // Check for simple literal values
        try {
            Integer.parseInt(initText);
            return true;
        } catch (NumberFormatException e) {
            // Not a simple integer
        }

        return false;
    }

    /**
     * Generic method to check if a variable declaration has a weak initializer
     * value.
     *
     * @param stmt               the statement to check
     * @param varName            the name of the variable
     * @param initializerChecker predicate to check if the initializer value is weak
     * @return true if the statement declares a variable with a weak value, false
     *         otherwise
     */
    public static boolean isWeakVariableWithInitializer(Node stmt, String varName,
            Predicate<String> initializerChecker) {
        if (stmt instanceof VariableDeclarationNode varDecl &&
                varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode capture &&
                capture.variableName().text().equals(varName) &&
                varDecl.initializer().isPresent()) {

            return initializerChecker.test(varDecl.initializer().get().toSourceCode());
        }

        if (stmt instanceof ModuleVariableDeclarationNode varDecl &&
                varDecl.typedBindingPattern().bindingPattern() instanceof CaptureBindingPatternNode capture &&
                capture.variableName().text().equals(varName) &&
                varDecl.initializer().isPresent()) {

            return initializerChecker.test(varDecl.initializer().get().toSourceCode());
        }

        return false;
    }

    /**
     * Checks if the given variable reference refers to a variable with a weak
     * parameter value.
     *
     * @param varRef  the variable reference
     * @param checker predicate to check if a statement declares a variable with a
     *                weak value
     * @return true if the variable has a weak parameter value, false otherwise
     */
    public static boolean hasWeakParameterSettings(SimpleNameReferenceNode varRef, BiPredicate<Node, String> checker) {
        String varName = varRef.name().text();
        return hasWeakParameterInScope(varRef.parent(), varName, checker);
    }

    /**
     * Checks if a variable with the given name has weak parameter values within a
     * specific scope.
     *
     * @param startNode the node to start searching from
     * @param varName   the name of the variable
     * @param checker   predicate to check if a statement declares a variable with a
     *                  weak value
     * @return true if a weak parameter value is found, false otherwise
     */
    public static boolean hasWeakParameterInScope(Node startNode, String varName, BiPredicate<Node, String> checker) {
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
     * @param checker    predicate to check if a statement declares a variable with
     *                   a weak value
     * @return true if a weak parameter value is found, false otherwise
     */
    public static boolean checkStatementsForWeakParameter(NodeList<StatementNode> statements, String varName,
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
     * @param checker predicate to check if a statement declares a variable with a
     *                weak value
     * @return true if a weak parameter value is found, false otherwise
     */
    public static boolean checkModuleMembersForWeakParameter(NodeList<ModuleMemberDeclarationNode> members,
            String varName,
            BiPredicate<Node, String> checker) {
        for (ModuleMemberDeclarationNode member : members) {
            if (checker.test(member, varName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Retrieves the Document corresponding to the given module and document ID.
     *
     * @param module     the module
     * @param documentId the document ID
     * @return the Document for the given module and document ID
     */
    public static Document getDocument(Module module, DocumentId documentId) {
        return module.document(documentId);
    }
}
