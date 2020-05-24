package me.shib.security.codefend.scanners.javascript.retirejs;

import me.shib.security.codefend.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class RetirejsScanner extends Codefend {

    private static final transient String tool = "RetireJS";
    private static final transient File retireJsResultFile = new File("bugaudit-retirejs-result.json");

    public RetirejsScanner(CodefendConfig config) throws CodefendException {
        super(config);
    }

    private static int getPriorityForSeverity(String severity) {
        switch (severity) {
            case "critical":
            case "urgent":
            case "high":
                return 1;
            case "low":
                return 3;
            default:
                return 2;
        }
    }

    private void retirejsExecutor(String command) throws CodefendException, IOException, InterruptedException {
        String response = runCommand(command);
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new CodefendException("Install npm before proceeding");
        }
    }

    private void npmProjectBuild() throws CodefendException, IOException, InterruptedException {
        System.out.println("Building Project...");
        retirejsExecutor("npm install");
    }

    private void runRetireJS() throws CodefendException, IOException, InterruptedException {
        System.out.println("Running RetireJS...");
        retirejsExecutor("retire -p --outputformat json --outputpath " + retireJsResultFile.getAbsolutePath());
    }

    private void parseResultData(File file) throws IOException, CodefendException {
        List<RetirejsResult.Data> dataList = RetirejsResult.getResult(file);
        if (dataList != null) {
            for (RetirejsResult.Data data : dataList) {
                if (data.getResults() != null) {
                    for (RetirejsResult.Data.Result result : data.getResults()) {
                        if (result.getVulnerabilities() != null) {
                            for (RetirejsResult.Data.Result.Vulnerability retireVuln : result.getVulnerabilities()) {
                                StringBuilder title = new StringBuilder();
                                if (retireVuln.getBelow() != null) {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" (Below ").append(retireVuln.getBelow()).append(")");
                                } else if (retireVuln.getAtOrAbove() != null) {
                                    title.append("Vulnerability found in ").append(result.getComponent())
                                            .append(" (At/Above ").append(retireVuln.getAtOrAbove())
                                            .append(")");
                                } else {
                                    title.append("Vulnerability found in ").append(result.getComponent());
                                }
                                CodefendFinding vulnerability = newVulnerability(title.toString(),
                                        getPriorityForSeverity(retireVuln.getSeverity()));
                                vulnerability.setField("Build File Path", data.getFile());
                                vulnerability.setField("Component", result.getComponent());
                                vulnerability.setField("Version:", result.getVersion());
                                if (retireVuln.getAtOrAbove() != null) {
                                    vulnerability.setField("Severity", retireVuln.getSeverity());
                                }
                                if (retireVuln.getBelow() != null) {
                                    vulnerability.addKey("Below-" + retireVuln.getBelow());
                                    vulnerability.setField("Below", retireVuln.getBelow());
                                }
                                if (retireVuln.getAtOrAbove() != null) {
                                    vulnerability.addKey("AtOrAbove-" + retireVuln.getAtOrAbove());
                                    vulnerability.setField("At (or) Above", retireVuln.getAtOrAbove());
                                }
                                List<String> ignorableInfo = new ArrayList<>();
                                if (retireVuln.getIdentifiers() != null) {
                                    if (retireVuln.getIdentifiers().getIssue() != null) {
                                        vulnerability.addKey("JS-Issue-" + retireVuln.getIdentifiers().getIssue());
                                        String issueURL = null;
                                        for (String info : retireVuln.getInfo()) {
                                            if (info.contains(retireVuln.getIdentifiers().getIssue()) &&
                                                    info.toLowerCase().startsWith("http")) {
                                                issueURL = info;
                                                ignorableInfo.add(issueURL);
                                            }
                                        }
                                        if (null == issueURL) {
                                            vulnerability.setField("Issue Reference",
                                                    retireVuln.getIdentifiers().getIssue());
                                        } else {
                                            vulnerability.setField("Issue Reference", "[" +
                                                    retireVuln.getIdentifiers().getIssue() + "](" + issueURL + ")");
                                        }
                                    }
                                    if (retireVuln.getIdentifiers().getBug() != null) {
                                        vulnerability.addKey("JS-Bug-" + retireVuln.getIdentifiers().getBug());
                                        String bugURL = null;
                                        for (String info : retireVuln.getInfo()) {
                                            if (info.contains(retireVuln.getIdentifiers().getBug()) && info.toLowerCase().startsWith("http")) {
                                                bugURL = info;
                                                ignorableInfo.add(bugURL);
                                            }
                                        }
                                        if (null == bugURL) {
                                            vulnerability.setField("Bug Reference",
                                                    retireVuln.getIdentifiers().getBug());
                                        } else {
                                            vulnerability.setField("Bug Reference", "[" +
                                                    retireVuln.getIdentifiers().getBug() + "](" + bugURL + ")");
                                        }
                                    }
                                    if (retireVuln.getIdentifiers().getCVE() != null
                                            && retireVuln.getIdentifiers().getCVE().size() > 0) {
                                        for (String cve : retireVuln.getIdentifiers().getCVE()) {
                                            vulnerability.addKey(cve);
                                        }
                                        vulnerability.setCVEs(retireVuln.getIdentifiers().getCVE());
                                    }
                                }
                                Set<String> filteredReferences = new HashSet<>(retireVuln.getInfo());
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
                                    vulnerability.setField("More references", referenceContent.toString().trim());
                                }
                                vulnerability.addKey(data.getFile());
                                vulnerability.addKey(result.getComponent());
                                vulnerability.addKey(result.getComponent() + "-" + result.getVersion());
                                vulnerability.update();
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
    public void scan() throws CodefendException, IOException, InterruptedException {
        retireJsResultFile.delete();
        npmProjectBuild();
        runRetireJS();
        parseResultData(retireJsResultFile);
    }
}
