/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
package io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer;

import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.FunctionSymbol;
import io.ballerina.compiler.api.symbols.ParameterSymbol;
import io.ballerina.compiler.api.symbols.Qualifier;
import io.ballerina.compiler.api.symbols.Symbol;
import io.ballerina.compiler.api.symbols.SymbolKind;
import io.ballerina.compiler.api.symbols.VariableSymbol;
import io.ballerina.compiler.syntax.tree.AssignmentStatementNode;
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.ExpressionStatementNode;
import io.ballerina.compiler.syntax.tree.FunctionArgumentNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.SeparatedNodeList;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.compiler.syntax.tree.VariableDeclarationNode;
import io.ballerina.projects.Document;
import io.ballerina.scan.Reporter;
import io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.VariableBinding;
import io.ballerina.tools.diagnostics.Location;
import io.ballerina.tools.text.LineRange;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.collectVariableExpressionsUntilStatement;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getModuleLevelVarExpressions;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getModulePartNode;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getParamExpressions;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getParentBlockNode;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getStatementNode;
import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.unescapeIdentifier;

/**
 * Represents the context of a function being analyzed.
 *
 * @since 2.9.1
 */
public class FunctionContext {
    private static final Set<SyntaxKind> RESULT_PASS_THROUGH_KINDS = Set.of(SyntaxKind.CHECK_EXPRESSION,
            SyntaxKind.BRACED_EXPRESSION, SyntaxKind.TYPE_CAST_EXPRESSION, SyntaxKind.TRAP_EXPRESSION);
    private final SemanticModel semanticModel;
    private final Reporter reporter;
    private final Document document;
    private final String functionName;
    private final Location functionLocation;
    private final boolean resultDiscarded;
    private final Map<String, ExpressionNode> paramExpressions;
    private final Map<String, VariableBinding> varExpressions;

    /**
     * Creates a FunctionContext instance for the given function call and symbol.
     *
     * @param semanticModel The semantic model
     * @param reporter      The reporter for diagnostics
     * @param document      The document containing the function call
     * @param functionCall  The function call expression node
     * @param functionSymbol The function symbol
     * @return A FunctionContext instance
     */
    public static FunctionContext getInstance(SemanticModel semanticModel, Reporter reporter, Document document,
                                              FunctionCallExpressionNode functionCall,
                                              FunctionSymbol functionSymbol) {
        SeparatedNodeList<FunctionArgumentNode> arguments = functionCall.arguments();
        Optional<String> functionNameOpt = functionSymbol.getName();
        if (functionNameOpt.isEmpty()) {
            // This should not happen as function symbols always have name in this context
            throw new IllegalStateException("Function name is not available for the function symbol");
        }

        Optional<List<ParameterSymbol>> params = functionSymbol.typeDescriptor().params();
        Map<String, ExpressionNode> paramExpressions = params.isEmpty() || arguments.isEmpty()
                ? Map.of() : getParamExpressions(params.get(), arguments);
        return new FunctionContext(semanticModel, reporter, document, functionNameOpt.get(),
                functionCall.location(), isResultDiscarded(functionCall), paramExpressions,
                collectVariableBindings(functionCall));
    }

    /**
     * Collects the module-level variables of the enclosing file and the variables assigned in the enclosing block
     * before the statement containing the call. Later assignments with the same name override earlier ones.
     */
    private static Map<String, VariableBinding> collectVariableBindings(FunctionCallExpressionNode functionCall) {
        Map<String, VariableBinding> varExpressions = new HashMap<>();
        getModulePartNode(functionCall).ifPresent(modulePart ->
                varExpressions.putAll(getModuleLevelVarExpressions(modulePart)));
        Optional<StatementNode> statementNode = getStatementNode(functionCall);
        if (statementNode.isEmpty()) {
            return varExpressions;
        }
        Optional<Node> blockNode = getParentBlockNode(statementNode.get());
        if (blockNode.isEmpty()) {
            return Map.of();
        }
        collectVariableExpressionsUntilStatement(blockNode.get(), statementNode.get(), varExpressions);
        return varExpressions;
    }

    // Private constructor to enforce the use of the instance method
    private FunctionContext(SemanticModel semanticModel, Reporter reporter, Document document, String functionName,
                            Location functionLocation, boolean resultDiscarded,
                            Map<String, ExpressionNode> paramExpressions,
                            Map<String, VariableBinding> varExpressions) {
        this.semanticModel = semanticModel;
        this.reporter = reporter;
        this.document = document;
        this.functionName = functionName;
        this.functionLocation = functionLocation;
        this.resultDiscarded = resultDiscarded;
        this.paramExpressions = paramExpressions;
        this.varExpressions = varExpressions;
    }

    /**
     * Returns the semantic model.
     *
     * @return the semantic model
     */
    public SemanticModel semanticModel() {
        return semanticModel;
    }

    /**
     * Returns the reporter.
     *
     * @return the reporter
     */
    public Reporter reporter() {
        return reporter;
    }

    /**
     * Returns the document.
     *
     * @return the document
     */
    public Document document() {
        return document;
    }

    /**
     * Returns the function name.
     *
     * @return the function name
     */
    public String functionName() {
        return functionName;
    }

    /**
     * Returns the function location.
     *
     * @return the function location
     */
    public Location functionLocation() {
        return functionLocation;
    }

    /**
     * Returns whether the result of this call is thrown away: bound or assigned to the wildcard {@code _}, or
     * written as an expression statement, optionally through {@code check}, braces, a type cast or {@code trap}.
     *
     * @return true if the result is discarded
     */
    public boolean isResultDiscarded() {
        return resultDiscarded;
    }

    private static boolean isResultDiscarded(FunctionCallExpressionNode functionCall) {
        Node parent = functionCall.parent();
        while (parent != null && RESULT_PASS_THROUGH_KINDS.contains(parent.kind())) {
            parent = parent.parent();
        }
        if (parent instanceof VariableDeclarationNode variableDeclaration) {
            return variableDeclaration.typedBindingPattern().bindingPattern().kind()
                    .equals(SyntaxKind.WILDCARD_BINDING_PATTERN);
        }
        if (parent instanceof AssignmentStatementNode assignment) {
            return assignment.varRef().kind().equals(SyntaxKind.WILDCARD_BINDING_PATTERN);
        }
        return parent instanceof ExpressionStatementNode;
    }

    /**
     * Returns the argument expression written at the call site for the given parameter, without resolving
     * variables.
     *
     * @param paramName the parameter name
     * @return the argument expression as written, if the parameter was supplied
     */
    public Optional<ExpressionNode> getRawParamExpression(String paramName) {
        return Optional.ofNullable(paramExpressions.get(unescapeIdentifier(paramName)));
    }

    /**
     * Retrieves the argument expression for a given parameter. A variable reference is resolved to the value last
     * assigned to that variable, when it is known; otherwise the reference itself is returned.
     *
     * @param paramName The name of the parameter
     * @return An Optional containing the expression node if found, otherwise empty
     */
    public Optional<ExpressionNode> getParamExpression(String paramName) {
        return getRawParamExpression(paramName).map(expr -> resolve(expr, false));
    }

    /**
     * Same as {@link #getParamExpression(String)}, but a configurable or non-final module variable is left
     * unresolved, since its value can be changed outside the code being analysed.
     *
     * @param paramName The name of the parameter
     * @return An Optional containing the expression node if found, otherwise empty
     */
    public Optional<ExpressionNode> getStableParamExpression(String paramName) {
        return getRawParamExpression(paramName).map(this::resolveStable);
    }

    /**
     * Resolves a variable reference to the value last assigned to it, returning the expression unchanged when the
     * value is not known.
     *
     * @param expression the expression
     * @return the resolved expression
     */
    public ExpressionNode resolve(ExpressionNode expression) {
        return resolve(expression, false);
    }

    /**
     * Same as {@link #resolve(ExpressionNode)}, but a configurable or non-final module variable is left unresolved.
     *
     * @param expression the expression
     * @return the resolved expression
     */
    public ExpressionNode resolveStable(ExpressionNode expression) {
        return resolve(expression, true);
    }

    private ExpressionNode resolve(ExpressionNode expression, boolean stableOnly) {
        ExpressionNode current = expression;
        // Bounded so that a self-referencing chain of assignments cannot loop forever.
        for (int depth = 0; depth < varExpressions.size() + 1; depth++) {
            if (!(current instanceof SimpleNameReferenceNode nameRef)) {
                return current;
            }
            Optional<ExpressionNode> value = lookUpVariable(nameRef, stableOnly);
            if (value.isEmpty()) {
                return current;
            }
            current = value.get();
        }
        return current;
    }

    private Optional<ExpressionNode> lookUpVariable(SimpleNameReferenceNode nameRef, boolean stableOnly) {
        VariableBinding binding = varExpressions.get(unescapeIdentifier(nameRef.name().text()));
        if (binding == null || binding.value() == null || (stableOnly && !binding.stable())) {
            return Optional.empty();
        }
        Optional<Symbol> symbol = semanticModel.symbol(nameRef);
        if (symbol.isEmpty()) {
            return Optional.of(binding.value());
        }
        if (!(symbol.get() instanceof VariableSymbol variableSymbol)
                || variableSymbol.kind().equals(SymbolKind.PARAMETER)
                || (stableOnly && variableSymbol.qualifiers().contains(Qualifier.CONFIGURABLE))
                || !isDeclaredAt(variableSymbol, binding.declaration())) {
            return Optional.empty();
        }
        return Optional.of(binding.value());
    }

    private static boolean isDeclaredAt(VariableSymbol symbol, LineRange declaration) {
        // An assignment to a variable declared outside the scanned block records no declaration; the name then
        // cannot have been redeclared between that assignment and the call.
        if (declaration == null) {
            return true;
        }
        Optional<Location> location = symbol.getLocation();
        if (location.isEmpty()) {
            return false;
        }
        LineRange symbolRange = location.get().lineRange();
        return symbolRange.fileName().equals(declaration.fileName())
                && symbolRange.startLine().line() == declaration.startLine().line()
                && symbolRange.startLine().offset() == declaration.startLine().offset();
    }
}
