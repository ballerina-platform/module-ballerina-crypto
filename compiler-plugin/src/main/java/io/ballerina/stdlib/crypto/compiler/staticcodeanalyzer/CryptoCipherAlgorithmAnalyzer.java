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

import io.ballerina.compiler.api.SemanticModel;
import io.ballerina.compiler.api.symbols.FunctionSymbol;
import io.ballerina.compiler.syntax.tree.FunctionCallExpressionNode;
import io.ballerina.compiler.syntax.tree.SyntaxKind;
import io.ballerina.projects.Document;
import io.ballerina.projects.plugins.AnalysisTask;
import io.ballerina.projects.plugins.SyntaxNodeAnalysisContext;
import io.ballerina.scan.Reporter;

import java.util.Optional;

import static io.ballerina.stdlib.crypto.compiler.staticcodeanalyzer.CryptoAnalyzerUtils.getCryptoFunctionSymbol;

/**
 * Analyzer to detect the usage of weak cipher algorithms and insecure practices in the Ballerina crypto module.
 */
public class CryptoCipherAlgorithmAnalyzer implements AnalysisTask<SyntaxNodeAnalysisContext> {

    private final Reporter reporter;
    private final CryptoFunctionRulesEngine rulesEngine;

    public CryptoCipherAlgorithmAnalyzer(Reporter reporter) {
        this.reporter = reporter;
        this.rulesEngine = new CryptoFunctionRulesEngine();
    }

    /**
     * Analyzes the syntax tree for function calls to crypto module functions.
     *
     * @param context the syntax node analysis context
     */
    @Override
    public void perform(SyntaxNodeAnalysisContext context) {
        FunctionCallExpressionNode functionCall = (FunctionCallExpressionNode) context.node();
        SemanticModel semanticModel = context.semanticModel();
        Document document = CryptoAnalyzerUtils.getDocument(context.currentPackage().module(context.moduleId()),
                context.documentId());
        if (!(functionCall.functionName().kind().equals(SyntaxKind.QUALIFIED_NAME_REFERENCE))) {
            return;
        }

        Optional<FunctionSymbol> functionSymbolOpt = getCryptoFunctionSymbol(functionCall, semanticModel);
        if (functionSymbolOpt.isEmpty()) {
            return;
        }

        FunctionContext functionContext = FunctionContext.getInstance(semanticModel, this.reporter, document,
                functionCall, functionSymbolOpt.get());
        rulesEngine.executeRules(functionContext);
    }
}
