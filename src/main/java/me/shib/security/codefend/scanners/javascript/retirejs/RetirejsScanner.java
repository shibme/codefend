package me.shib.security.codefend.scanners.javascript.retirejs;

import me.shib.security.codefend.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class RetirejsScanner extends CodeFend {

    private static final transient String tool = "RetireJS";
    private static final transient File retireJsResultFile = new File("bugaudit-retirejs-result.json");

    public RetirejsScanner(CodeFendConfig config) throws CodeFendException {
        super(config);
    }

    private static CodeFendPriority getPriorityForSeverity(String severity) {
        switch (severity) {
            case "critical":
            case "urgent":
                return CodeFendPriority.P0;
            case "high":
                return CodeFendPriority.P1;
            case "low":
                return CodeFendPriority.P3;
            default:
                return CodeFendPriority.P2;
        }
    }

    private void retirejsExecutor(String command) throws CodeFendException, IOException, InterruptedException {
        String response = runCommand(command);
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new CodeFendException("Install npm before proceeding");
        }
    }

    private void npmProjectBuild() throws CodeFendException, IOException, InterruptedException {
        System.out.println("Building Project...");
        retirejsExecutor("npm install");
    }

    private void runRetireJS() throws CodeFendException, IOException, InterruptedException {
        System.out.println("Running RetireJS...");
        retirejsExecutor("retire -p --outputformat json --outputpath " + retireJsResultFile.getAbsolutePath());
    }

    private void parseResultData() throws IOException, CodeFendException {
        List<RetirejsResult.Data> dataList = RetirejsResult.getResult(RetirejsScanner.retireJsResultFile);
        if (dataList != null) {
            for (RetirejsResult.Data data : dataList) {
                if (data.getResults() != null) {
                    for (RetirejsResult.Data.Result result : data.getResults()) {
                        if (result.getVulnerabilities() != null) {
                            for (RetirejsResult.Data.Result.Vulnerability vulnerability : result.getVulnerabilities()) {
                                StringBuilder title = new StringBuilder();
                                if (vulnerability.getBelow() != null) {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" (Below ").append(vulnerability.getBelow()).append(") of ")
                                            .append(getConfig().getProject());
                                } else if (vulnerability.getAtOrAbove() != null) {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" (At/Above ").append(vulnerability.getAtOrAbove())
                                            .append(") of ").append(getConfig().getProject());
                                } else {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" of ").append(getConfig().getProject());
                                }
                                CodeFendFinding finding = newFinding(title.toString(),
                                        getPriorityForSeverity(vulnerability.getSeverity()));
                                StringBuilder description = new StringBuilder();
                                description.append("A known vulnerability in **")
                                        .append(result.getComponent()).append("** exists in ").append("**[")
                                        .append(getConfig().getGitRepo()).append("](")
                                        .append(getConfig().getGitRepo().getGitRepoWebURL()).append(")**.\n");
                                description.append(" * **Build File Path:** ").append(data.getFile()).append("\n");
                                finding.setField("Build File Path", data.getFile());
                                description.append(" * **Component:** ").append(result.getComponent()).append("\n");
                                finding.setField("Component", result.getComponent());
                                description.append(" * **Version:** ").append(result.getVersion()).append("\n");
                                finding.setField("Version:", result.getVersion());
                                if (vulnerability.getAtOrAbove() != null) {
                                    description.append(" * **Severity:** ").append(vulnerability.getSeverity()).append("\n");
                                    finding.setField("Severity", vulnerability.getSeverity());
                                }
                                if (vulnerability.getBelow() != null) {
                                    finding.addKey("Below-" + vulnerability.getBelow());
                                    description.append(" * **Below:** ").append(vulnerability.getBelow()).append("\n");
                                    finding.setField("Below", vulnerability.getBelow());
                                }
                                if (vulnerability.getAtOrAbove() != null) {
                                    finding.addKey("AtOrAbove-" + vulnerability.getAtOrAbove());
                                    description.append(" * **At (or) Above:** ").append(vulnerability.getAtOrAbove()).append("\n");
                                    finding.setField("At (or) Above", vulnerability.getAtOrAbove());
                                }
                                List<String> ignorableInfo = new ArrayList<>();
                                if (vulnerability.getIdentifiers() != null) {
                                    if (vulnerability.getIdentifiers().getIssue() != null) {
                                        finding.addKey("JS-Issue-" + vulnerability.getIdentifiers().getIssue());
                                        String issueURL = null;
                                        for (String info : vulnerability.getInfo()) {
                                            if (info.contains(vulnerability.getIdentifiers().getIssue()) &&
                                                    info.toLowerCase().startsWith("http")) {
                                                issueURL = info;
                                                ignorableInfo.add(issueURL);
                                            }
                                        }
                                        description.append(" * **Issue Reference:** ");
                                        if (null == issueURL) {
                                            description.append(vulnerability.getIdentifiers().getIssue());
                                            finding.setField("Issue Reference",
                                                    vulnerability.getIdentifiers().getIssue());
                                        } else {
                                            description.append("[").append(vulnerability.getIdentifiers().getIssue()).append("](")
                                                    .append(issueURL).append(")");
                                            finding.setField("Issue Reference", "[" +
                                                    vulnerability.getIdentifiers().getIssue() + "](" + issueURL + ")");
                                        }
                                    }
                                    description.append("\n");
                                    if (vulnerability.getIdentifiers().getBug() != null) {
                                        finding.addKey("JS-Bug-" + vulnerability.getIdentifiers().getBug());
                                        String bugURL = null;
                                        for (String info : vulnerability.getInfo()) {
                                            if (info.contains(vulnerability.getIdentifiers().getBug()) && info.toLowerCase().startsWith("http")) {
                                                bugURL = info;
                                                ignorableInfo.add(bugURL);
                                            }
                                        }
                                        description.append(" * **Bug Reference:** ");
                                        if (null == bugURL) {
                                            description.append(vulnerability.getIdentifiers().getBug());
                                            finding.setField("Bug Reference",
                                                    vulnerability.getIdentifiers().getBug());
                                        } else {
                                            description.append("[").append(vulnerability.getIdentifiers().getBug()).append("](")
                                                    .append(bugURL).append(")");
                                            finding.setField("Bug Reference", "[" +
                                                    vulnerability.getIdentifiers().getBug() + "](" + bugURL + ")");
                                        }
                                        description.append("\n");
                                    }
                                    if (vulnerability.getIdentifiers().getCVE() != null
                                            && vulnerability.getIdentifiers().getCVE().size() > 0) {
                                        description.append(" * **CVE:**");
                                        for (String cve : vulnerability.getIdentifiers().getCVE()) {
                                            finding.addKey(cve);
                                            try {
                                                description.append(" ").append("[").append(cve).append("](").append(getUrlForCVE(cve)).append(")");
                                            } catch (CodeFendException e) {
                                                description.append(" ").append(cve);
                                            }
                                        }
                                        description.append("\n");
                                        finding.setCVEs(vulnerability.getIdentifiers().getCVE());
                                    }
                                }
                                Set<String> filteredReferences = new HashSet<>(vulnerability.getInfo());
                                for (String ignoreableRef : ignorableInfo) {
                                    filteredReferences.remove(ignoreableRef);
                                }
                                if (filteredReferences.size() > 0) {
                                    StringBuilder referenceContent = new StringBuilder();
                                    for (String filteredRef : filteredReferences) {
                                        if (filteredRef.toLowerCase().startsWith("http")) {
                                            referenceContent.append(" * [").append(filteredRef).append("](").append(filteredRef).append(")\n");
                                        } else {
                                            referenceContent.append(" * ").append(filteredRef).append("\n");
                                        }
                                    }
                                    description.append("\n**More references:**\n").append(referenceContent);
                                    finding.setField("More references", referenceContent.toString().trim());
                                }
                                finding.setDescription(description.toString());
                                finding.addKey(data.getFile());
                                finding.addKey(result.getComponent());
                                finding.addKey(result.getComponent() + "-" + result.getVersion());
                                finding.update();
                            }
                        }
                    }
                }
            }
        }
    }

    @Override
    public Lang getLang() {
        return Lang.JavaScript;
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
    protected void scan() throws CodeFendException, IOException, InterruptedException {
        retireJsResultFile.delete();
        npmProjectBuild();
        runRetireJS();
        parseResultData();
    }
}
