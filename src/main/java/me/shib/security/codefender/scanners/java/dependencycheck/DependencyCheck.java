package me.shib.security.codefender.scanners.java.dependencycheck;

import me.shib.security.codefender.*;
import me.shib.security.codefender.scanners.java.dependencycheck.models.Dependency;
import me.shib.security.codefender.scanners.java.dependencycheck.models.DependencyCheckResult;
import me.shib.security.codefender.scanners.java.dependencycheck.models.Reference;
import me.shib.security.codefender.scanners.java.dependencycheck.models.Vulnerability;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DependencyCheck extends Codefender {

    private static final transient String cweBaseURL = "https://cwe.mitre.org/data/definitions/";
    private static final transient String tool = "DependencyCheck";
    private static final transient File dependencyCheckReportFile = new File("bugaudit-dependency-check-result.json");
    private static final transient int cveRecheckHours = 24;

    private CodefenderConfig config;

    public DependencyCheck(CodefenderConfig config) {
        super(config);
        this.config = config;
    }

    @Override
    protected Lang getLang() {
        return Lang.Java;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public Context getContext() {
        return Context.SCA;
    }

    private int getPriorityForSeverity(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return 1;
            case "HIGH":
                return 2;
            case "MEDIUM":
                return 3;
            case "LOW":
                return 4;
            default:
                return 3;
        }
    }

    private String getUrlForCWE(String cwe) {
        if (cwe.toUpperCase().startsWith("CWE-")) {
            return cweBaseURL + cwe.toUpperCase().replace("CWE-", "") + ".html";
        }
        return null;
    }

    private void processDependencyCheckReport(DependencyCheckResult dependencyCheckResult) throws CodefenderException {
        class VulnDependencyPair {
            private Vulnerability vulnerability;
            private Dependency dependency;

            private VulnDependencyPair(Vulnerability vulnerability, Dependency dependency) {
                this.vulnerability = vulnerability;
                this.dependency = dependency;
            }
        }
        Map<String, List<VulnDependencyPair>> vulnDepsMap = new HashMap<>();
        List<Dependency> vulnerableDependencies = dependencyCheckResult.getVulnerableDependencies();
        for (Dependency dependency : vulnerableDependencies) {
            if (!dependency.getFileName().contains("(shaded: ") &&
                    dependency.getFileName().toLowerCase().endsWith(".jar")) {
                List<Vulnerability> vulnerabilities = dependency.getVulnerabilities();
                if (vulnerabilities != null) {
                    for (Vulnerability vulnerability : vulnerabilities) {
                        if (vulnerability.getName() != null &&
                                vulnerability.getName().toUpperCase().startsWith("CVE-")) {
                            String key = dependency.getName().toLowerCase() + "-" + vulnerability.getName();
                            List<VulnDependencyPair> vulnDependencyPairs = vulnDepsMap.get(key);
                            if (vulnDependencyPairs == null) {
                                vulnDependencyPairs = new ArrayList<>();
                            }
                            vulnDependencyPairs.add(new VulnDependencyPair(vulnerability, dependency));
                            vulnDepsMap.put(key, vulnDependencyPairs);
                        }
                    }
                }
            }
        }

        for (String key : vulnDepsMap.keySet()) {
            List<VulnDependencyPair> vulnDependencyPairs = vulnDepsMap.get(key);
            if (vulnDependencyPairs != null && vulnDependencyPairs.size() > 0) {
                Vulnerability vulnerability = vulnDependencyPairs.get(0).vulnerability;
                Dependency dependency = vulnDependencyPairs.get(0).dependency;
                String cve = vulnerability.getName();
                String title = "Vulnerability (" + cve + ") found in " + dependency.getName() +
                        " of " + config.getGitRepo();
                int priority = 10;
                for (VulnDependencyPair vulnDependencyPair : vulnDependencyPairs) {
                    int vulnPriority = getPriorityForSeverity(vulnDependencyPair.vulnerability.getSeverity());
                    if (vulnPriority < priority) {
                        priority = vulnPriority;
                    }
                }
                CodefenderVulnerability codefenderVuln = newVulnerability(title, priority);

                String message = "A known vulnerability was found in **" +
                        dependency.getFileName() + "** of " + "**[" +
                        config.getGitRepo() + "](" +
                        config.getGitRepo().getGitRepoWebURL() + ")**.";
                codefenderVuln.setField("Message", message);
                codefenderVuln.setCVE(vulnerability.getName());
                codefenderVuln.setField("Component", dependency.getFileName());
                String currentPath = System.getProperty("user.dir") + "/";
                if (dependency.getFilePath().startsWith(currentPath)) {
                    codefenderVuln.setField("Path", dependency.getFilePath().replaceFirst(currentPath, ""));
                }
                codefenderVuln.setField("Description", vulnerability.getDescription());
                if (vulnerability.getCvssv2() != null) {
                    codefenderVuln.setField("CVSS v2 Score", vulnerability.getCvssv2().getScore() + "");
                }
                if (vulnerability.getCvssv3() != null) {
                    codefenderVuln.setField("CVSS v3 Score", vulnerability.getCvssv3().getBaseScore() + "");
                }
                codefenderVuln.setField("Severity", vulnerability.getSeverity());

                StringBuilder cweField = new StringBuilder();
                for (String cwe : vulnerability.getCwes()) {
                    codefenderVuln.addTag(cwe);
                    String cweURL = getUrlForCWE(cwe);
                    if (cweURL != null) {
                        cweField.append("**[").append(cwe).append("](").append(cweURL).append(")** ");
                    } else {
                        cweField.append("**").append(cwe).append("** ");
                    }
                }
                codefenderVuln.setField("Applicable CWEs", cweField.toString().trim());

                if (vulnerability.getNotes() != null && !vulnerability.getNotes().isEmpty()) {
                    codefenderVuln.setField("Notes", vulnerability.getNotes());
                }

                if (vulnerability.getReferences() != null && vulnerability.getReferences().size() > 0) {
                    StringBuilder references = new StringBuilder();
                    for (Reference reference : vulnerability.getReferences()) {
                        if (reference.getName() != null && !reference.getName().isEmpty()) {
                            if (reference.getUrl() != null && !reference.getUrl().isEmpty()) {
                                references.append(" * [").append(reference.getName()).append("](")
                                        .append(reference.getUrl()).append(")\n");
                            } else {
                                references.append(" * ").append(reference.getName()).append("\n");
                            }
                        } else if (reference.getUrl() != null && !reference.getUrl().isEmpty()) {
                            references.append(" * [").append(reference.getUrl()).append("](")
                                    .append(reference.getUrl()).append(")\n");
                        }
                    }
                    codefenderVuln.setField("References", references.toString());
                }

                codefenderVuln.addKey(dependency.getName());
                codefenderVuln.addKey(cve);
                codefenderVuln.addTag(dependency.getFileName());
                codefenderVuln.update();
            }
        }
    }

    private void runDependecyCheck() throws IOException, InterruptedException {
        runCommand("dependency-check" +
                " --cveValidForHours " + cveRecheckHours +
                " --format JSON" +
                " --out " + dependencyCheckReportFile.getAbsolutePath() +
                " --scan .");
    }

    @Override
    public void scan() throws IOException, InterruptedException, CodefenderException {
        if (!isParserOnly()) {
            dependencyCheckReportFile.delete();
            runDependecyCheck();
        }
        DependencyCheckResult dependencyCheckResult = DependencyCheckResult.getResult(dependencyCheckReportFile);
        processDependencyCheckReport(dependencyCheckResult);
    }
}
