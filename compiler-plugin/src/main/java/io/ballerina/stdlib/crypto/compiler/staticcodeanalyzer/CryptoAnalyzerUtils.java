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
import io.ballerina.compiler.api.symbols.SymbolKind;
import io.ballerina.compiler.api.values.ConstantValue;
import io.ballerina.compiler.syntax.tree.AssignmentStatementNode;
import io.ballerina.compiler.syntax.tree.BasicLiteralNode;
import io.ballerina.compiler.syntax.tree.BindingPatternNode;
import io.ballerina.compiler.syntax.tree.BlockStatementNode;
import io.ballerina.compiler.syntax.tree.BracedExpressionNode;
import io.ballerina.compiler.syntax.tree.CaptureBindingPatternNode;
import io.ballerina.compiler.syntax.tree.CompoundAssignmentStatementNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FieldAccessExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionArgumentNode;
import io.ballerina.compiler.syntax.tree.FunctionBodyBlockNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.IndexedExpressionNode;
import io.ballerina.compiler.syntax.tree.ListConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingConstructorExpressionNode;
import io.ballerina.compiler.syntax.tree.MappingFieldNode;
import io.ballerina.compiler.syntax.tree.MethodCallExpressionNode;
import io.ballerina.compiler.syntax.tree.ModuleMemberDeclarationNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.ModuleVariableDeclarationNode;
import io.ballerina.compiler.syntax.tree.NameReferenceNode;
import io.ballerina.compiler.syntax.tree.NamedArgumentNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.NodeList;
import io.ballerina.compiler.syntax.tree.PositionalArgumentNode;
import io.ballerina.compiler.syntax.tree.SeparatedNodeList;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.SpecificFieldNode;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.compiler.syntax.tree.Token;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.projects.DocumentId;
import io.ballerina.projects.Module;
import io.ballerina.tools.text.LineRange;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * Utility class containing helper methods for crypto cipher algorithm analysis.
 * This class provides common functionality for checking weak parameters and
 * variable analysis.
 */
public final class CryptoAnalyzerUtils {
    public static final Set<String> PGP_ENCRYPT_FUNCTIONS = Set.of("encryptPgp", "encryptStreamAsPgp");
    public static final String PGP_OPTIONS_PARAM = "options";

    private static final String BALLERINA_ORG = "ballerina";
    private static final String CRYPTO = "crypto";
    private static final String TO_BYTES_METHOD = "toBytes";

    /**
     * A variable's most recently known value, together with where the variable is declared.
     *
     * @param value       the expression last assigned to the variable, or null if it has not been assigned
     * @param declaration the location of the variable name in its declaration, or null if it is not known
     * @param stable      whether the value can be relied on: false for a configurable or non-final module variable,
     *                    whose value can change outside the code being analysed
     */
    public record VariableBinding(ExpressionNode value, LineRange declaration, boolean stable) {
    }

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
     * Retrieves the nearest StatementNode enclosing the given FunctionCallExpressionNode, however deeply the call
     * is nested inside expressions.
     *
     * @param functionCall the function call expression node
     * @return an Optional containing the StatementNode if found, otherwise empty
     */
    public static Optional<StatementNode> getStatementNode(FunctionCallExpressionNode functionCall) {
        Node parent = functionCall.parent();
        while (parent != null && !(parent instanceof ModuleMemberDeclarationNode)) {
            if (parent instanceof StatementNode statementNode) {
                return Optional.of(statementNode);
            }
            parent = parent.parent();
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
     * Retrieves the bindings of the module-level variables declared in the given ModulePartNode.
     *
     * @param modulePartNode the module part node
     * @return a map where keys are variable names and values are their bindings
     */
    public static Map<String, VariableBinding> getModuleLevelVarExpressions(ModulePartNode modulePartNode) {
        Map<String, VariableBinding> varExpressions = new HashMap<>();
        for (ModuleMemberDeclarationNode member : modulePartNode.members()) {
            if (member instanceof ModuleVariableDeclarationNode variableDeclarationNode) {
                BindingPatternNode bindingPatternNode = variableDeclarationNode.typedBindingPattern().bindingPattern();
                if (variableDeclarationNode.initializer().isEmpty() ||
                        !(bindingPatternNode instanceof CaptureBindingPatternNode captureBindingPattern)) {
                    continue;
                }
                String varName = unescapeIdentifier(captureBindingPattern.variableName().text());
                ExpressionNode initializer = variableDeclarationNode.initializer().get();
                boolean isFinal = hasQualifier(variableDeclarationNode.qualifiers(), SyntaxKind.FINAL_KEYWORD);
                boolean isConfigurable = hasQualifier(variableDeclarationNode.qualifiers(),
                        SyntaxKind.CONFIGURABLE_KEYWORD);
                varExpressions.put(varName, new VariableBinding(initializer,
                        captureBindingPattern.variableName().location().lineRange(), isFinal && !isConfigurable));
            }
        }
        return varExpressions;
    }

    private static boolean hasQualifier(NodeList<Token> qualifiers, SyntaxKind qualifier) {
        return qualifiers.stream().anyMatch(token -> token.kind().equals(qualifier));
    }

    /**
     * Collects variable declarations and assignments from the given block node
     * up to the specified statement node.
     *
     * @param blockNode      the block node (FunctionBodyBlockNode or BlockStatementNode)
     * @param statementNode  the statement node to stop at
     * @param varExpressions the map to store variable names and their bindings
     */
    public static void collectVariableExpressionsUntilStatement(Node blockNode, StatementNode statementNode,
                                                                Map<String, VariableBinding> varExpressions) {
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
     * Check whether the given expression is a compile-time constant byte array: a non-empty list constructor of
     * numeric literals, a {@code base16}/{@code base64} byte array literal, or {@code toBytes()} called on a string
     * literal or constant. Variables are followed through the given resolver.
     *
     * @param expression the expression to check
     * @param context    the function context, used to look up symbols
     * @param resolver   resolves a variable reference to its known value, or returns it unchanged
     * @return true if the expression is a compile-time constant byte array
     */
    public static boolean isByteArrayLiteral(ExpressionNode expression, FunctionContext context,
                                             UnaryOperator<ExpressionNode> resolver) {
        ExpressionNode resolved = resolver.apply(unwrapBraces(expression));
        if (resolved.kind().equals(SyntaxKind.BYTE_ARRAY_LITERAL)) {
            return true;
        }
        if (resolved instanceof ListConstructorExpressionNode listExpression) {
            return !listExpression.expressions().isEmpty() && listExpression.expressions().stream()
                    .allMatch(expr -> expr.kind().equals(SyntaxKind.NUMERIC_LITERAL));
        }
        if (resolved instanceof MethodCallExpressionNode methodCallExpression
                && methodCallExpression.methodName() instanceof SimpleNameReferenceNode simpleNameRef
                && simpleNameRef.name().text().equals(TO_BYTES_METHOD)) {
            return isConstantString(methodCallExpression.expression(), context, resolver);
        }
        return false;
    }

    private static boolean isConstantString(ExpressionNode expression, FunctionContext context,
                                            UnaryOperator<ExpressionNode> resolver) {
        ExpressionNode unwrapped = unwrapBraces(expression);
        if (unwrapped.kind().equals(SyntaxKind.STRING_LITERAL) || isConstantReference(unwrapped, context)) {
            return true;
        }
        ExpressionNode resolved = resolver.apply(unwrapped);
        return resolved != unwrapped && isConstantString(resolved, context, resolver);
    }

    private static boolean isConstantReference(ExpressionNode expression, FunctionContext context) {
        if (!(expression instanceof NameReferenceNode)) {
            return false;
        }
        Optional<Symbol> symbol = context.semanticModel().symbol(expression);
        return symbol.isPresent() && symbol.get().kind().equals(SymbolKind.CONSTANT);
    }

    /**
     * Check whether the given expression is an integer literal or integer constant below the given threshold. An
     * integer literal may be written in decimal or, with a {@code 0x} prefix, in hexadecimal.
     *
     * @param valueExpr     the expression to check
     * @param threshold     the exclusive lower bound
     * @param semanticModel the semantic model
     * @return true only if the value is known and below the threshold
     */
    public static boolean hasLowerIntegerValue(ExpressionNode valueExpr, long threshold,
                                               SemanticModel semanticModel) {
        return getIntegerValue(unwrapBraces(valueExpr), semanticModel).filter(value -> value < threshold)
                .isPresent();
    }

    private static Optional<Long> getIntegerValue(ExpressionNode valueExpr, SemanticModel semanticModel) {
        if (valueExpr.kind().equals(SyntaxKind.NUMERIC_LITERAL)) {
            String literal = ((BasicLiteralNode) valueExpr).literalToken().text();
            try {
                if (literal.startsWith("0x") || literal.startsWith("0X")) {
                    return Optional.of(Long.parseLong(literal.substring(2), 16));
                }
                return Optional.of(Long.parseLong(literal));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        if (getConstantValue(valueExpr, semanticModel) instanceof Long longValue) {
            return Optional.of(longValue);
        }
        return Optional.empty();
    }

    /**
     * Retrieves the boolean value of a boolean literal or boolean constant.
     *
     * @param valueExpr     the expression
     * @param semanticModel the semantic model
     * @return the boolean value, if the expression is a literal or constant
     */
    public static Optional<Boolean> getBooleanValue(ExpressionNode valueExpr, SemanticModel semanticModel) {
        ExpressionNode unwrapped = unwrapBraces(valueExpr);
        if (unwrapped.kind().equals(SyntaxKind.BOOLEAN_LITERAL)) {
            return Optional.of(((BasicLiteralNode) unwrapped).literalToken().kind().equals(SyntaxKind.TRUE_KEYWORD));
        }
        if (getConstantValue(unwrapped, semanticModel) instanceof Boolean booleanValue) {
            return Optional.of(booleanValue);
        }
        return Optional.empty();
    }

    /**
     * Retrieves the string value of a parameter from the function context.
     *
     * @param key     the parameter name
     * @param context the function context
     * @return an Optional containing the string value if found, otherwise empty
     */
    public static Optional<String> getStringValue(String key, FunctionContext context) {
        return context.getParamExpression(key).flatMap(expr -> getStringValue(expr, context.semanticModel()));
    }

    /**
     * Retrieves the value of a string literal or string constant.
     *
     * @param valueExpr     the expression
     * @param semanticModel the semantic model
     * @return the string value, if the expression is a literal or constant
     */
    public static Optional<String> getStringValue(ExpressionNode valueExpr, SemanticModel semanticModel) {
        ExpressionNode unwrapped = unwrapBraces(valueExpr);
        if (unwrapped.kind().equals(SyntaxKind.STRING_LITERAL)) {
            String stringValue = ((BasicLiteralNode) unwrapped).literalToken().text();
            return Optional.of(stringValue.substring(1, stringValue.length() - 1));
        }
        if (getConstantValue(unwrapped, semanticModel) instanceof String constString) {
            return Optional.of(constString);
        }
        return Optional.empty();
    }

    private static Object getConstantValue(ExpressionNode valueExpr, SemanticModel semanticModel) {
        if (valueExpr instanceof NameReferenceNode refNode
                && semanticModel.symbol(refNode).orElse(null) instanceof ConstantSymbol constantRef
                && constantRef.constValue() instanceof ConstantValue constantValue) {
            return constantValue.value();
        }
        return null;
    }

    /**
     * Retrieves a field of an included record parameter, whether it is passed as a named argument or as a field of
     * a mapping constructor bound to the included record parameter itself. Both are resolved through variables with
     * {@link FunctionContext#resolveStable}.
     *
     * @param context        the function context
     * @param includedParam  the name of the included record parameter
     * @param fieldName      the field name
     * @return the field value expression, if it can be determined
     */
    public static Optional<ExpressionNode> getIncludedRecordField(FunctionContext context, String includedParam,
                                                                  String fieldName) {
        Optional<ExpressionNode> namedArgument = context.getStableParamExpression(fieldName);
        if (namedArgument.isPresent()) {
            return namedArgument;
        }
        Optional<ExpressionNode> record = context.getStableParamExpression(includedParam);
        if (record.isEmpty() || !(unwrapBraces(record.get()) instanceof MappingConstructorExpressionNode mapping)) {
            return Optional.empty();
        }
        for (MappingFieldNode field : mapping.fields()) {
            if (field instanceof SpecificFieldNode specificField
                    && fieldName.equals(unescapeIdentifier(specificField.fieldName().toSourceCode().trim()
                            .replace("\"", "")))) {
                return specificField.valueExpr().map(context::resolveStable);
            }
        }
        return Optional.empty();
    }

    private static ExpressionNode unwrapBraces(ExpressionNode expression) {
        ExpressionNode current = expression;
        while (current instanceof BracedExpressionNode braced) {
            current = braced.expression();
        }
        return current;
    }

    /**
     * Processes statements to collect variable declarations and assignments
     * up to the specified target statement.
     *
     * @param statements      the list of statements
     * @param targetStatement the target statement to stop at
     * @param varExpressions  the map to store variable names and their bindings
     */
    public static void processStatementsForVariableExpressions(NodeList<StatementNode> statements,
                                                               StatementNode targetStatement,
                                                               Map<String, VariableBinding> varExpressions) {
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

            if (statement instanceof AssignmentStatementNode assignmentNode) {
                processAssignmentStatement(assignmentNode, varExpressions);
            } else if (statement instanceof CompoundAssignmentStatementNode compoundAssignment) {
                getRootVariableName(compoundAssignment.lhsExpression()).ifPresent(varExpressions::remove);
            } else if (statement instanceof VariableDeclarationNode variableDeclarationNode) {
                processVariableDeclaration(variableDeclarationNode, varExpressions);
            }
        }
    }

    private static void processAssignmentStatement(AssignmentStatementNode assignmentNode,
                                                   Map<String, VariableBinding> varExpressions) {
        Node varRef = assignmentNode.varRef();
        if (varRef instanceof SimpleNameReferenceNode simpleNameRef) {
            String varName = unescapeIdentifier(simpleNameRef.name().text());
            VariableBinding previous = varExpressions.get(varName);
            LineRange declaration = previous == null ? null : previous.declaration();
            varExpressions.put(varName, new VariableBinding(assignmentNode.expression(), declaration, true));
            return;
        }
        // A member or field written in place changes the value the variable holds.
        getRootVariableName(varRef).ifPresent(varExpressions::remove);
    }

    private static Optional<String> getRootVariableName(Node node) {
        Node current = node;
        while (true) {
            switch (current) {
                case SimpleNameReferenceNode simpleNameRef -> {
                    return Optional.of(unescapeIdentifier(simpleNameRef.name().text()));
                }
                case IndexedExpressionNode indexed -> current = indexed.containerExpression();
                case FieldAccessExpressionNode fieldAccess -> current = fieldAccess.expression();
                default -> {
                    return Optional.empty();
                }
            }
        }
    }

    private static void processVariableDeclaration(VariableDeclarationNode variableDeclarationNode,
                                                   Map<String, VariableBinding> varExpressions) {
        BindingPatternNode bindingPatternNode = variableDeclarationNode.typedBindingPattern().bindingPattern();

        // Only supporting capture binding patterns for variable declarations
        if (!(bindingPatternNode instanceof CaptureBindingPatternNode captureBindingPattern)) {
            return;
        }

        String varName = unescapeIdentifier(captureBindingPattern.variableName().text());
        ExpressionNode initializer = variableDeclarationNode.initializer().orElse(null);
        varExpressions.put(varName, new VariableBinding(initializer,
                captureBindingPattern.variableName().location().lineRange(), true));
    }
}
