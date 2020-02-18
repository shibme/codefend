package me.shib.security.codefender.scanners.ruby.bundleraudit;

import me.shib.security.codefender.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class BundlerAudit extends Codefender {

    private static transient final String tool = "BundlerAudit";
    private static transient final File bundlerAuditOutput = new File("bundleraudit-result.txt");

    public BundlerAudit(CodefenderConfig config) {
        super(config);
    }

    private static int getPriorityNumberForName(String priorityName) {
        switch (priorityName) {
            case "High":
                return 1;
            case "Medium":
                return 2;
            case "Low":
                return 3;
            case "Urgent":
                return 0;
            case "Critical":
                return 0;
            default:
                return 2;
        }
    }

    private void addBugForContent(String gemVulnerabilityContent) throws CodefenderException {
        String advisory = "";
        String url = "";
        String descriptionTitle = "";
        String solution = "";
        String gemName = "";
        String gemVersion = "";
        int priority = 3;
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
        CodefenderVulnerability vulnerability = newVulnerability(title, priority);
        vulnerability.setField("Description", descriptionTitle);
        vulnerability.setField("Gem Name", gemName);
        vulnerability.setField("Gem Version", gemVersion);
        if (advisory.startsWith("CVE-")) {
            vulnerability.setCVE(advisory);
        } else {
            vulnerability.setField("Advisory", advisory);
        }
        vulnerability.setField("Solution", solution);
        vulnerability.setField("Reference", url);
        if (gemName.isEmpty() || advisory.isEmpty()) {
            return;
        }
        vulnerability.addKey(gemName);
        vulnerability.addKey(advisory);
        vulnerability.update();
    }

    private void parseOutputContentToResult(String content) throws CodefenderException {
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
            throw new CodefenderException("Something went wrong with Bundler Audit");
        }
    }

    private String bundlerAuditExecutor(String command) throws CodefenderException, IOException, InterruptedException {
        String response = runCommand(command);
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new CodefenderException("Install npm before proceeding");
        }
        return response;
    }

    private void runBundlerAudit() throws CodefenderException, IOException, InterruptedException {
        System.out.println("Running BundlerAudit...");
        String bundlerAuditResponse = bundlerAuditExecutor("bundle-audit");
        writeToFile(bundlerAuditResponse, bundlerAuditOutput);
    }

    private void updateBundlerAuditDatabase() throws CodefenderException, IOException, InterruptedException {
        bundlerAuditExecutor("bundle-audit update");
    }

    private void parseBundlerAuditResult() throws CodefenderException, IOException {
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
    public void scan() throws Exception {
        bundlerAuditOutput.delete();
        updateBundlerAuditDatabase();
        runBundlerAudit();
        parseBundlerAuditResult();
    }
}
