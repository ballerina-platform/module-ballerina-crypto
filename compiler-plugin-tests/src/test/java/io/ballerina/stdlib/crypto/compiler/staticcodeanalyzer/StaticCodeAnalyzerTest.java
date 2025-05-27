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

import org.testng.Assert;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.Test;
import org.testng.internal.ExitCode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

/**
 * This class includes tests for Ballerina Http static code analyzer.
 *
 * @since 2.15.1
 */
public class StaticCodeAnalyzerTest {
    private static final Path RESOURCE_PACKAGES_DIRECTORY = Paths
            .get("src", "test", "resources", "static_code_analyzer", "ballerina_packages").toAbsolutePath();
    private static final Path EXPECTED_JSON_OUTPUT_DIRECTORY = Paths.
            get("src", "test", "resources", "static_code_analyzer", "expected_output").toAbsolutePath();
    private static final Path BALLERINA_PATH = getBalCommandPath();
    private static final Path JSON_RULES_FILE_PATH = Paths
            .get("../", "compiler-plugin", "src", "main", "resources", "rules.json").toAbsolutePath();
    private static final String SCAN_COMMAND = "scan";
    private static final List<Integer> RULE_IDS = getAllRuleIdsFromConstants();

    /**
     * Retrieves all rule IDs defined in the Rule enum.
     * This automatically includes any new rules added to the enum.
     *
     * @return List of rule ID integers
     */
    private static List<Integer> getAllRuleIdsFromConstants() {
        List<Integer> ruleIds = new ArrayList<>();
        try {
            for (CryptoRule rule : CryptoRule.values()) {
                ruleIds.add(rule.getId());
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract rule IDs from Constants enum", e);
        }
        return ruleIds;
    }

    /**
     * Returns the path to the Ballerina command based on the operating system.
     * This method constructs the path to the bal command in the target directory.
     *
     * @return Path to the bal command
     */
    private static Path getBalCommandPath() {
        String balCommand = isWindows() ? "bal.bat" : "bal";
        return Paths.get("../", "target", "ballerina-runtime", "bin", balCommand).toAbsolutePath();
    }

    /**
     * Pulls the scan tool before running the tests.
     * This ensures that the scan tool is available and up to date.
     *
     * @throws IOException if there's an error executing the pull command
     */
    @BeforeSuite
    public void pullScanTool() throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(BALLERINA_PATH.toString(), "tool", "pull", SCAN_COMMAND);
        ProcessOutputGobbler output = getOutput(processBuilder.start()).join();
        if (Pattern.compile("tool 'scan:.+\\..+\\..+' successfully set as the active version\\.")
                .matcher(output.getOutput()).find() || Pattern.compile("tool 'scan:.+\\..+\\..+' is already active\\.")
                .matcher(output.getOutput()).find()) {
            return;
        }
        Assert.assertFalse(ExitCode.hasFailure(output.getExitCode()));
    }

    /**
     * Validates the rules.json file against the expected rules defined in the Rule enum.
     * This test ensures that the rules.json file contains all the necessary rules with correct IDs,
     * kinds, and descriptions.
     *
     * @throws IOException if there's an error reading the rules.json file
     */
    @Test
    public void validateRulesJson() throws IOException {
        String actualRules = Files.readString(JSON_RULES_FILE_PATH);
        StringBuilder expectedRules = generateExpectedRulesJson();
        assertJsonEqual(normalizeJson(actualRules), normalizeJson(expectedRules.toString()));
    }

    /**
     * Generates the expected rules JSON based on rule IDs from the constant class.
     *
     * @return StringBuilder containing the expected rules JSON
     * @throws IOException if there's an error reading the rules.json file
     */
    private StringBuilder generateExpectedRulesJson() throws IOException {
        String actualRulesJson = Files.readString(JSON_RULES_FILE_PATH);
        java.util.Map<Integer, java.util.Map<String, String>> ruleDetails = new java.util.HashMap<>();
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "\\{\\s*\"id\"\\s*:\\s*(\\d+)\\s*,\\s*\"kind\"\\s*:\\s*\"([^\"]+)\"\\s*,"
                + "\\s*\"description\"\\s*:\\s*\"([^\"]+)\"\\s*}");
        java.util.regex.Matcher matcher = pattern.matcher(actualRulesJson);

        while (matcher.find()) {
            int ruleId = Integer.parseInt(matcher.group(1));
            String kind = matcher.group(2);
            String description = matcher.group(3);

            java.util.Map<String, String> details = new java.util.HashMap<>();
            details.put("kind", kind);
            details.put("description", description);
            ruleDetails.put(ruleId, details);
        }

        StringBuilder expectedRules = new StringBuilder("[");
        for (int i = 0; i < RULE_IDS.size(); i++) {
            if (i > 0) {
                expectedRules.append(",");
            }
            int ruleId = RULE_IDS.get(i);
            java.util.Map<String, String> details = ruleDetails.get(ruleId);

            expectedRules.append("{\"id\":").append(ruleId);

            if (details != null) {
                String kind = details.get("kind");
                String description = details.get("description");

                if (kind != null && !kind.isEmpty()) {
                    expectedRules.append(",\"kind\":\"").append(kind).append("\"");
                }

                if (description != null && !description.isEmpty()) {
                    expectedRules.append(",\"description\":\"").append(description).append("\"");
                }
            }

            expectedRules.append("}");
        }
        expectedRules.append("]");

        return expectedRules;
    }

    /**
     * Tests the static code analyzer for each rule defined in the CryptoRuleConstants class.
     * It executes the scan command for each target package
     * and compares the actual JSON report with the expected output.
     *
     * @throws IOException if there's an error executing the scan process or reading the expected output
     */
    @Test
    public void testStaticCodeRules() throws IOException {
        for (int ruleId : RULE_IDS) {
            String targetPackageName = "rule" + ruleId;
            String actualJsonReport = StaticCodeAnalyzerTest.executeScanProcess(targetPackageName);
            String expectedJsonReport = Files
                    .readString(EXPECTED_JSON_OUTPUT_DIRECTORY.resolve(targetPackageName + ".json"));
            assertJsonEqual(actualJsonReport, expectedJsonReport);
        }
    }

    /**
     * Executes the scan process for a given target package and returns the JSON report.
     *
     * @param targetPackage the name of the target package to scan
     * @return the JSON report as a string
     * @throws IOException if there's an error executing the scan process or reading the report
     */
    private static String executeScanProcess(String targetPackage) throws IOException {
        ProcessBuilder processBuilder = new ProcessBuilder(BALLERINA_PATH.toString(), SCAN_COMMAND);
        processBuilder.directory(RESOURCE_PACKAGES_DIRECTORY.resolve(targetPackage).toFile());
        ProcessOutputGobbler output = getOutput(processBuilder.start()).join();
        Assert.assertFalse(ExitCode.hasFailure(output.getExitCode()));
        return Files.readString(RESOURCE_PACKAGES_DIRECTORY.resolve(targetPackage)
                .resolve("target").resolve("report").resolve("scan_results.json"));
    }

    /**
     * Gets the output of a process and returns a CompletableFuture containing the ProcessOutputGobbler.
     * This method starts threads to read both the standard output and error streams of the process.
     *
     * @param process the process to get the output from
     * @return a CompletableFuture containing the ProcessOutputGobbler with the process output
     */
    private static CompletableFuture<ProcessOutputGobbler> getOutput(Process process) {
        ProcessOutputGobbler outputGobbler = new ProcessOutputGobbler(process.getInputStream());
        ProcessOutputGobbler errorGobbler = new ProcessOutputGobbler(process.getErrorStream());
        Thread outputThread = new Thread(outputGobbler);
        Thread errorThread = new Thread(errorGobbler);
        outputThread.start();
        errorThread.start();

        return CompletableFuture.supplyAsync(() -> {
            try {
                int exitCode = process.waitFor();
                outputGobbler.setExitCode(exitCode);
                errorGobbler.setExitCode(exitCode);
                outputThread.join();
                errorThread.join();
                return outputGobbler;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Asserts that two JSON strings are equal after normalizing them.
     * This method removes unnecessary whitespace and normalizes paths for comparison.
     *
     * @param actual   the actual JSON string
     * @param expected the expected JSON string
     */
    private void assertJsonEqual(String actual, String expected) {
        Assert.assertEquals(normalizeJson(actual), normalizeJson(expected));
    }

    /**
     * Normalizes a JSON string by removing unnecessary whitespace and ensuring consistent formatting.
     * This method is used to prepare JSON strings for comparison in tests.
     *
     * @param json the JSON string to normalize
     * @return the normalized JSON string
     */
    private static String normalizeJson(String json) {
        String normalizedJson = json.replaceAll("\\s*\"\\s*", "\"")
                .replaceAll("\\s*:\\s*", ":")
                .replaceAll("\\s*,\\s*", ",")
                .replaceAll("\\s*\\{\\s*", "{")
                .replaceAll("\\s*}\\s*", "}")
                .replaceAll("\\s*\\[\\s*", "[")
                .replaceAll("\\s*]\\s*", "]")
                .replaceAll("\n", "")
                .replaceAll(":\".*module-ballerina-jwt", ":\"module-ballerina-jwt");
        return isWindows() ? normalizedJson.replaceAll("/", "\\\\\\\\") : normalizedJson;
    }

    /**
     * Checks if the current operating system is Windows.
     * This method is used to determine the correct path format for file operations.
     *
     * @return true if the operating system is Windows, false otherwise
     */
    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ENGLISH).startsWith("windows");
    }
}
