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
import io.ballerina.compiler.syntax.tree.ExpressionNode;
import io.ballerina.compiler.syntax.tree.FunctionArgumentNode;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.ModulePartNode;
import io.ballerina.compiler.syntax.tree.Node;
import io.ballerina.compiler.syntax.tree.SeparatedNodeList;
import io.ballerina.compiler.syntax.tree.SimpleNameReferenceNode;
import io.ballerina.compiler.syntax.tree.StatementNode;
import io.ballerina.projects.Document;
import io.ballerina.scan.Reporter;
import io.ballerina.tools.diagnostics.Location;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
    private final SemanticModel semanticModel;
    private final Reporter reporter;
    private final Document document;
    private final String functionName;
    private final Location functionLocation;
    private  Map<String, ExpressionNode> paramExpressions = Map.of();
    private Map<String, ExpressionNode> varExpressions = Map.of();

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
        Location location = functionCall.location();
        SeparatedNodeList<FunctionArgumentNode> arguments = functionCall.arguments();
        Optional<String> functionNameOpt = functionSymbol.getName();
        if (functionNameOpt.isEmpty()) {
            // This should not happen as function symbols always have name in this context
            throw new IllegalStateException("Function name is not available for the function symbol");
        }

        String functionName = functionNameOpt.get();
        Optional<List<ParameterSymbol>> params = functionSymbol.typeDescriptor().params();
        // Create a default FunctionContext in case of missing parameters or arguments
        FunctionContext defaultFunctionContext = new FunctionContext(semanticModel, reporter, document, functionName,
                location);
        if (params.isEmpty() || arguments.isEmpty()) {
            return defaultFunctionContext;
        }

        Map<String, ExpressionNode> paramExpressions = getParamExpressions(params.get(), arguments);

        Optional<StatementNode> statementNode = getStatementNode(functionCall);
        if (statementNode.isEmpty()) {
            return defaultFunctionContext;
        }

        // A map is used to hold variable expressions in global and function block scope.
        // The key is the variable name and the value is the expression node assigned to it.
        // Processing happens in an order using the NodeList. Hence, expressions will be overridden
        // if there are reassignments with the same variable name
        Map<String, ExpressionNode> varExpressions = new HashMap<>();

        // Collect module level variable expressions
        Optional<ModulePartNode> modulePartNode = getModulePartNode(statementNode.get());
        if (modulePartNode.isPresent()) {
            varExpressions = getModuleLevelVarExpressions(modulePartNode.get());
        }

        Optional<Node> functionBodyOpt = getParentBlockNode(statementNode.get());
        if (functionBodyOpt.isEmpty()) {
            return defaultFunctionContext;
        }

        // Add variable declarations up to the function call statement
        collectVariableExpressionsUntilStatement(functionBodyOpt.get(), statementNode.get(), varExpressions);
        return new FunctionContext(semanticModel, reporter, document, functionName, location, paramExpressions,
                varExpressions);
    }

    // Private constructor to enforce the use of the instance method
    private FunctionContext(SemanticModel semanticModel, Reporter reporter, Document document, String functionName,
                            Location functionLocation) {
        this.semanticModel = semanticModel;
        this.reporter = reporter;
        this.document = document;
        this.functionName = functionName;
        this.functionLocation = functionLocation;
    }

    // Private constructor to enforce the use of the instance method
    private FunctionContext(SemanticModel semanticModel, Reporter reporter, Document document, String functionName,
                            Location functionLocation, Map<String, ExpressionNode> paramExpressions,
                            Map<String, ExpressionNode> varExpressions) {
        this(semanticModel, reporter, document, functionName, functionLocation);
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
     * Retrieves the expression node for a given parameter name.
     * If the parameter expression is a simple name reference, it resolves
     * the reference to get the actual expression.
     *
     * @param paramName The name of the parameter
     * @return An Optional containing the expression node if found, otherwise empty
     */
    public Optional<ExpressionNode> getParamExpression(String paramName) {
        paramName = unescapeIdentifier(paramName);
        if (!paramExpressions.containsKey(paramName)) {
            return Optional.empty();
        }
        ExpressionNode paramExpr = paramExpressions.get(paramName);
        if (paramExpr instanceof SimpleNameReferenceNode simpleNameRef) {
            String varName = simpleNameRef.name().text();
            // Retrying to get the expression from variable expressions
            // collected with the block scope and global scope
            Optional<ExpressionNode> varExprOpt = getVarExpression(varName);
            return varExprOpt.isPresent() ? varExprOpt : Optional.of(paramExpr);
        }
        return Optional.of(paramExpr);
    }

    /**
     * Retrieves the expression node for a given variable name.
     * If the variable expression is a simple name reference, it resolves
     * the reference to get the actual expression.
     *
     * @param varName The name of the variable
     * @return An Optional containing the expression node if found, otherwise empty
     */
    public Optional<ExpressionNode> getVarExpression(String varName) {
        varName = unescapeIdentifier(varName);
        if (!varExpressions.containsKey(varName)) {
            return Optional.empty();
        }
        ExpressionNode varExpr = varExpressions.get(varName);
        if (varExpr instanceof SimpleNameReferenceNode simpleNameRef) {
            String innerVarName = simpleNameRef.name().text();
            return getVarExpression(innerVarName);
        }
        return Optional.of(varExpr);
    }
}
