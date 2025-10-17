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

import io.ballerina.compiler.api.ModuleID;
import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.ConstantSymbol;
import io.ballerina.compiler.api.symbols.FunctionSymbol;
import io.ballerina.compiler.api.symbols.ParameterSymbol;
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.values.ConstantValue;
import io.ballerina.compiler.syntax.tree.AssignmentStatementNode;
import io.ballerina.compiler.syntax.tree.BasicLiteralNode;
import io.ballerina.compiler.syntax.tree.BindingPatternNode;
import io.ballerina.compiler.syntax.tree.BlockStatementNode;
import io.ballerina.compiler.syntax.tree.CaptureBindingPatternNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionArgumentNode;
import io.ballerina.compiler.syntax.tree.FunctionBodyBlockNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.IdentifierToken;
import io.ballerina.compiler.syntax.tree.ModuleMemberDeclarationNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.ModuleVariableDeclarationNode;
import io.ballerina.compiler.syntax.tree.NameReferenceNode;
import io.ballerina.compiler.syntax.tree.NamedArgumentNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.NodeList;
import io.ballerina.compiler.syntax.tree.PositionalArgumentNode;
import io.ballerina.compiler.syntax.tree.SeparatedNodeList;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Utility class containing helper methods for crypto cipher algorithm analysis.
 * This class provides common functionality for checking weak parameters and
 * variable analysis.
 */
public final class CryptoAnalyzerUtils {
    private static final String BALLERINA_ORG = "ballerina";
    private static final String CRYPTO = "crypto";

    // Private constructor to prevent instantiation
    private CryptoAnalyzerUtils() {

    }

    /**
     * Retrieves the FunctionSymbol for a given FunctionCallExpressionNode if it belongs to the Ballerina
     * crypto module.
     *
     * @param functionCall  the function call expression node
     * @param semanticModel the semantic model
     * @return an Optional containing the FunctionSymbol if it belongs to the crypto module, otherwise empty
     */
    public static Optional<FunctionSymbol> getCryptoFunctionSymbol(FunctionCallExpressionNode functionCall,
                                                                   SemanticModel semanticModel) {
        Optional<Symbol> functionCallSymbolOptional = semanticModel.symbol(functionCall);
        if (functionCallSymbolOptional.isEmpty()
                || !(functionCallSymbolOptional.get() instanceof FunctionSymbol functionSymbol)
                || functionSymbol.getModule().isEmpty()) {
            return Optional.empty();
        }
        ModuleID moduleId = (functionCallSymbolOptional.get()).getModule().get().id();
        if (BALLERINA_ORG.equals(moduleId.orgName()) && CRYPTO.equals(moduleId.packageName())) {
            return Optional.of(functionSymbol);
        }
        return Optional.empty();
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

    /**
     * Unescape the given identifier name by removing leading escape quote and backslashes.
     *
     * @param identifierName The identifier name to unescape
     * @return The unescaped identifier name
     */
    public static String unescapeIdentifier(String identifierName) {
        String result = identifierName;
        if (result.startsWith("'")) {
            result = result.substring(1);
        }
        return result.replace("\\\\", "");
    }


    /**
     * Maps parameter names to their corresponding argument expressions in a function call.
     *
     * @param params    List of ParameterSymbol representing the function parameters
     * @param arguments SeparatedNodeList of FunctionArgumentNode representing the function arguments
     * @return A map where keys are parameter names and values are the corresponding argument expressions
     */
    public static Map<String, ExpressionNode> getParamExpressions(List<ParameterSymbol> params,
                                                                  SeparatedNodeList<FunctionArgumentNode> arguments) {
        Map<String, ExpressionNode> paramExpressions = new HashMap<>();
        // Argument types: Positional, Named and Rest
        // Parameter types: Required, Defaultable, Included and Rest
        List<String> paramNames = params.stream()
                .map(ParameterSymbol::getName)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .map(CryptoAnalyzerUtils::unescapeIdentifier)
                .toList();
        // For each argument we need to find the corresponding parameter name and added it to the map
        for (int i = 0; i < arguments.size(); i++) {
            FunctionArgumentNode argument = arguments.get(i);
            if (argument instanceof PositionalArgumentNode positionalArg) {
                if (i < paramNames.size()) {
                    String paramName = paramNames.get(i);
                    paramName = unescapeIdentifier(paramName);
                    ExpressionNode expression = positionalArg.expression();
                    paramExpressions.put(paramName, expression);
                }
            } else if (argument instanceof NamedArgumentNode namedArg) {
                String paramName = namedArg.argumentName().name().text();
                paramName = unescapeIdentifier(paramName);
                ExpressionNode expression = namedArg.expression();
                paramExpressions.put(paramName, expression);
            }
            // Not handling RestArgumentNode at the moment as crypto functions do not have rest parameters
        }
        return paramExpressions;
    }

    /**
     * Retrieves the StatementNode that contains the given FunctionCallExpressionNode.
     *
     * @param functionCall the function call expression node
     * @return an Optional containing the StatementNode if found, otherwise empty
     */
    public static Optional<StatementNode> getStatementNode(FunctionCallExpressionNode functionCall) {
        Node parent = functionCall.parent();
        if (parent.kind().equals(SyntaxKind.CHECK_EXPRESSION)) {
            parent = parent.parent();
        }
        if (parent instanceof StatementNode statementNode) {
            return Optional.of(statementNode);
        }
        return Optional.empty();
    }

    /**
     * Recursively retrieves the nearest parent block node (FunctionBodyBlockNode or BlockStatementNode)
     * of the given node.
     *
     * @param node the starting node
     * @return an Optional containing the parent block node if found, otherwise empty
     */
    public static Optional<Node> getParentBlockNode(Node node) {
        Node parent = node.parent();
        return switch (parent) {
            case null -> Optional.empty();
            case FunctionBodyBlockNode functionBody -> Optional.of(functionBody);
            case BlockStatementNode blockStatementNode -> Optional.of(blockStatementNode);
            default -> getParentBlockNode(parent);
        };
    }

    /**
     * Recursively retrieves the ModulePartNode that contains the given node.
     *
     * @param node the starting node
     * @return an Optional containing the ModulePartNode if found, otherwise empty
     */
    public static Optional<ModulePartNode> getModulePartNode(Node node) {
        Node parent = node.parent();
        return switch (parent) {
            case null -> Optional.empty();
            case ModulePartNode modulePartNode -> Optional.of(modulePartNode);
            default -> getModulePartNode(parent);
        };
    }

    /**
     * Retrieves a map of module-level variable names to their initializer expressions
     * from the given ModulePartNode.
     *
     * @param modulePartNode the module part node
     * @return a map where keys are variable names and values are their initializer expressions
     */
    public static Map<String, ExpressionNode> getModuleLevelVarExpressions(ModulePartNode modulePartNode) {
        Map<String, ExpressionNode> varExpressions = new HashMap<>();
        for (ModuleMemberDeclarationNode member : modulePartNode.members()) {
            if (member instanceof ModuleVariableDeclarationNode variableDeclarationNode) {
                BindingPatternNode bindingPatternNode = variableDeclarationNode.typedBindingPattern().bindingPattern();
                if (variableDeclarationNode.initializer().isEmpty() ||
                        !(bindingPatternNode instanceof CaptureBindingPatternNode captureBindingPattern)) {
                    continue;
                }
                String varName = captureBindingPattern.variableName().text();
                varName = unescapeIdentifier(varName);
                ExpressionNode initializer = variableDeclarationNode.initializer().get();
                varExpressions.put(varName, initializer);
            }
        }
        return varExpressions;
    }

    /**
     * Collects variable declarations and assignments from the given block node
     * up to the specified statement node.
     *
     * @param blockNode      the block node (FunctionBodyBlockNode or BlockStatementNode)
     * @param statementNode  the statement node to stop at
     * @param varExpressions the map to store variable names and their expressions
     */
    public static void collectVariableExpressionsUntilStatement(Node blockNode, StatementNode statementNode,
                                                                Map<String, ExpressionNode> varExpressions) {
        NodeList<StatementNode> statements = switch (blockNode) {
            case FunctionBodyBlockNode functionBody -> functionBody.statements();
            case BlockStatementNode blockStatementNode -> blockStatementNode.statements();
            default -> throw new IllegalArgumentException("Unsupported block node type: " + blockNode.kind());
        };
        processStatementsForVariableExpressions(statements, statementNode, varExpressions);
    }

    /**
     * Checks if the given statement node is a block statement or not.
     *
     * @param statement the statement node to check
     * @return true if the statement is a block statement, false otherwise
     */
    public static boolean isBlockStatementNode(StatementNode statement) {
        SyntaxKind kind = statement.kind();
        return kind.equals(SyntaxKind.BLOCK_STATEMENT) || kind.equals(SyntaxKind.DO_STATEMENT)
                || kind.equals(SyntaxKind.FORK_STATEMENT) || kind.equals(SyntaxKind.IF_ELSE_STATEMENT)
                || kind.equals(SyntaxKind.LOCK_STATEMENT) || kind.equals(SyntaxKind.MATCH_STATEMENT)
                || kind.equals(SyntaxKind.FOREACH_STATEMENT) || kind.equals(SyntaxKind.WHILE_STATEMENT)
                || kind.equals(SyntaxKind.TRANSACTION_STATEMENT) || kind.equals(SyntaxKind.RETRY_STATEMENT);
    }

    /**
     * Retrieves the string value of a parameter from the function context.
     *
     * @param key     the parameter name
     * @param context the function context
     * @return an Optional containing the string value if found, otherwise empty
     */
    public static Optional<String> getStringValue(String key, FunctionContext context) {
        Optional<ExpressionNode> valueExprOpt = context.getParamExpression(key);
        if (valueExprOpt.isEmpty()) {
            return Optional.empty();
        }

        ExpressionNode valueExpr = valueExprOpt.get();
        if (valueExpr.kind().equals(SyntaxKind.STRING_LITERAL)) {
            // String literal values
            String stringValue = ((BasicLiteralNode) valueExpr).literalToken().text();
            // Remove the leading and trailing double quotes
            stringValue = stringValue.substring(1, stringValue.length() - 1);
            return Optional.of(stringValue);
        } else if (valueExpr instanceof NameReferenceNode refNode) {
            // Checking for constant values
            Optional<Symbol> refSymbol = context.semanticModel().symbol(refNode);
            if (refSymbol.isPresent() && refSymbol.get() instanceof ConstantSymbol constantRef &&
                    constantRef.constValue() instanceof ConstantValue constantValue &&
                    constantValue.value() instanceof String constString) {
                return Optional.of(constString);
            }
        }
        return Optional.empty();
    }

    /**
     * Processes statements to collect variable declarations and assignments
     * up to the specified target statement.
     *
     * @param statements      the list of statements
     * @param targetStatement the target statement to stop at
     * @param varExpressions  the map to store variable names and their expressions
     */
    public static void processStatementsForVariableExpressions(NodeList<StatementNode> statements,
                                                               StatementNode targetStatement,
                                                               Map<String, ExpressionNode> varExpressions) {
        for (StatementNode statement : statements) {
            boolean isBlockStatement = isBlockStatementNode(statement);

            // Stop processing if we reach the target statement or found a block statement
            if (statement.equals(targetStatement) || isBlockStatement) {
                if (isBlockStatement) {
                    // If we find any block nodes, we cannot verify variable declarations or assignments
                    // since they may be changed within those blocks. Clear collected expressions and stop.
                    varExpressions.clear();
                }
                break;
            }

            // Process assignment statements
            if (statement instanceof AssignmentStatementNode assignmentNode) {
                processAssignmentStatement(assignmentNode, varExpressions);
            } else if (statement instanceof VariableDeclarationNode variableDeclarationNode) {
                processVariableDeclaration(variableDeclarationNode, varExpressions);
            }
        }
    }

    /**
     * Processes an assignment statement and adds it to the variable expressions map.
     *
     * @param assignmentNode the assignment statement node
     * @param varExpressions the map to store variable names and their expressions
     */
    private static void processAssignmentStatement(AssignmentStatementNode assignmentNode,
                                                   Map<String, ExpressionNode> varExpressions) {
        Node varRef = assignmentNode.varRef();
        if (varRef instanceof IdentifierToken variableNameIdentifier) {
            String varName = unescapeIdentifier(variableNameIdentifier.text());
            ExpressionNode expression = assignmentNode.expression();
            varExpressions.put(varName, expression);
        }
    }

    /**
     * Processes a variable declaration statement and adds it to the variable expressions map.
     *
     * @param variableDeclarationNode the variable declaration node
     * @param varExpressions         the map to store variable names and their expressions
     */
    private static void processVariableDeclaration(VariableDeclarationNode variableDeclarationNode,
                                                   Map<String, ExpressionNode> varExpressions) {
        BindingPatternNode bindingPatternNode = variableDeclarationNode.typedBindingPattern().bindingPattern();

        // Only supporting capture binding patterns for variable declarations
        if (variableDeclarationNode.initializer().isEmpty() ||
                !(bindingPatternNode instanceof CaptureBindingPatternNode captureBindingPattern)) {
            return;
        }

        String varName = unescapeIdentifier(captureBindingPattern.variableName().text());
        ExpressionNode initializer = variableDeclarationNode.initializer().get();
        varExpressions.put(varName, initializer);
    }
}
