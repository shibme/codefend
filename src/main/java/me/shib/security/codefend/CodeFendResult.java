package me.shib.security.codefend;

import java.util.*;

final class CodeFendResult {

    private final Lang lang;
    private final CodeFend.Context context;
    private final String scanner;
    private final String scanDirPath;
    private final Map<String, CodeFendFinding> vulnerabilityMap;
    private String project;

    CodeFendResult(String project, Lang lang, CodeFend.Context context, String scanner, String scanDirPath) {
        this.project = project;
        this.lang = lang;
        this.context = context;
        this.scanner = scanner;
        this.scanDirPath = scanDirPath;
        this.vulnerabilityMap = new HashMap<>();
    }

    CodeFendFinding newVulnerability(String title, CodeFendPriority priority) {
        return new CodeFendFinding(this, title, priority);
    }

    void updateVulnerability(CodeFendFinding vulnerability) {
        vulnerability.addKey(project);
        vulnerability.addTag(project);
        vulnerability.addKey(lang.toString());
        vulnerability.addTag(lang.toString());
        vulnerability.addKey(context.toString());
        vulnerability.addTag(context.toString());
        vulnerability.addKey(scanner);
        vulnerability.addTag(scanner);
        StringBuilder key = new StringBuilder();
        List<String> keyList = new ArrayList<>(vulnerability.getKeys());
        Collections.sort(keyList);
        for (String k : keyList) {
            key.append(k).append(";");
        }
        vulnerabilityMap.put(key.toString(), vulnerability);
    }

    String getProject() {
        return project;
    }

    void setProject(String project) {
        this.project = project;
    }

    Lang getLang() {
        return lang;
    }

    CodeFend.Context getContext() {
        return context;
    }

    String getScanner() {
        return scanner;
    }

    String getScanDirPath() {
        return scanDirPath;
    }

    List<CodeFendFinding> getVulnerabilities() {
        return new ArrayList<>(vulnerabilityMap.values());
    }
}
