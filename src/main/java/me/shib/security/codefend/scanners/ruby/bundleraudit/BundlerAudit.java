package me.shib.security.codefend.scanners.ruby.bundleraudit;

import me.shib.security.codefend.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class BundlerAudit extends Codefend {

    private static transient final String tool = "BundlerAudit";
    private static transient final File bundlerAuditOutput = new File("bundleraudit-result.txt");

    public BundlerAudit(CodefendConfig config) {
        super(config);
    }

    private static CodefendPriority getPriorityNumberForName(String priorityName) {
        switch (priorityName) {
            case "Urgent":
                return CodefendPriority.P0;
            case "Critical":
                return CodefendPriority.P0;
            case "High":
                return CodefendPriority.P1;
            case "Medium":
                return CodefendPriority.P2;
            case "Low":
                return CodefendPriority.P3;
            default:
                return CodefendPriority.P2;
        }
    }

    private String getDescription(String gemName, String gemVersion, String descriptionTitle, String url, String solution, String advisory) {
        StringBuilder description = new StringBuilder();
        description.append("A vulnerable gem (**").append(gemName)
                .append("-").append(gemVersion)
                .append("**) was found to be used in the repository ");
        description.append("**[").append(getConfig().getGitRepo()).append("](")
                .append(getConfig().getGitRepo().getGitRepoWebURL()).append(")**.\n");
        try {
            description.append("\n**[").append(advisory).append("](").append(getUrlForCVE(advisory)).append("):**");
        } catch (CodefendException e) {
            description.append("\n**[").append(advisory).append("](").append(url).append("):**");
        }
        if (descriptionTitle != null && !descriptionTitle.isEmpty()) {
            description.append("\n * **Description:** ").append(descriptionTitle);
        }
        if (url != null && !url.isEmpty()) {
            description.append("\n * **Reference:** [").append(url).append("]");
        }
        if (solution != null && !solution.isEmpty()) {
            description.append("\n * **Solution:** ").append(solution);
        }
        return description.toString();
    }

    private void addBugForContent(String gemVulnerabilityContent) throws CodefendException {
        String advisory = "";
        String url = "";
        String descriptionTitle = "";
        String solution = "";
        String gemName = "";
        String gemVersion = "";
        CodefendPriority priority = CodefendPriority.P3;
        String[] split = gemVulnerabilityContent.split("Solution: ");
        if (split.length == 2) {
            solution = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Title: ");
        if (split.length == 2) {
            descriptionTitle = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("URL: ");
        if (split.length == 2) {
            url = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Criticality: ");
        if (split.length == 2) {
            priority = getPriorityNumberForName(split[1].replace("\n", " ").trim());
        }
        split = split[0].split("Advisory: ");
        if (split.length == 2) {
            advisory = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Version: ");
        if (split.length == 2) {
            gemVersion = split[1].replace("\n", " ").trim();
        }
        split = split[0].split("Name: ");
        if (split.length == 2) {
            gemName = split[1].replace("\n", " ").trim();
        }
        String title = "Vulnerable Gem (" + advisory + ") - " + gemName;
        CodefendFinding finding = newVulnerability(title, priority);
        finding.setField("Description", descriptionTitle);
        finding.setField("Gem Name", gemName);
        finding.setField("Gem Version", gemVersion);
        if (advisory.startsWith("CVE-")) {
            finding.setCVE(advisory);
        } else {
            finding.setField("Advisory", advisory);
        }
        finding.setField("Solution", solution);
        finding.setField("Reference", url);
        if (gemName.isEmpty() || advisory.isEmpty()) {
            return;
        }
        finding.addKey(gemName);
        finding.addKey(advisory);
        finding.setDescription(getDescription(gemName, gemVersion, descriptionTitle, url, solution, advisory));
        finding.update();
    }

    private void parseOutputContentToResult(String content) throws CodefendException {
        String[] lines = content.split("\n");
        String lastLine = lines[lines.length - 1];
        if (lastLine.equalsIgnoreCase("Vulnerabilities found!")) {
            List<String> vulnGemLines = new ArrayList<>();
            for (String line : lines) {
                if (!line.startsWith("Insecure Source URI found")) {
                    vulnGemLines.add(line);
                }
            }
            StringBuilder vulnerabilityContent = new StringBuilder();
            int i = 0;
            while ((i < vulnGemLines.size()) && !vulnGemLines.get(i).equalsIgnoreCase("Vulnerabilities found!")) {
                if (!vulnGemLines.get(i).isEmpty()) {
                    vulnerabilityContent.append(vulnGemLines.get(i)).append("\n");
                } else {
                    addBugForContent(vulnerabilityContent.toString());
                    vulnerabilityContent = new StringBuilder();
                }
                i++;
            }
        } else if (!lastLine.equalsIgnoreCase("No vulnerabilities found")) {
            throw new CodefendException("Something went wrong with Bundler Audit");
        }
    }

    private String bundlerAuditExecutor(String command) throws CodefendException, IOException, InterruptedException {
        String response = runCommand(command);
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new CodefendException("Install npm before proceeding");
        }
        return response;
    }

    private void runBundlerAudit() throws CodefendException, IOException, InterruptedException {
        System.out.println("Running BundlerAudit...");
        String bundlerAuditResponse = bundlerAuditExecutor("bundle-audit");
        writeToFile(bundlerAuditResponse, bundlerAuditOutput);
    }

    private void updateBundlerAuditDatabase() throws CodefendException, IOException, InterruptedException {
        bundlerAuditExecutor("bundle-audit update");
    }

    private void parseBundlerAuditResult() throws CodefendException, IOException {
        String resultContent = readFromFile(bundlerAuditOutput);
        parseOutputContentToResult(resultContent);
    }

    @Override
    public Lang getLang() {
        return Lang.Ruby;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public Context getContext() {
        return Context.SCA;
    }

    @Override
    protected void scan() throws Exception {
        bundlerAuditOutput.delete();
        updateBundlerAuditDatabase();
        runBundlerAudit();
        parseBundlerAuditResult();
    }
}
