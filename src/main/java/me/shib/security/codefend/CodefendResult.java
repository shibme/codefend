package me.shib.security.codefend;

import java.util.*;

final class CodefendResult {

    private final Lang lang;
    private final Codefend.Context context;
    private final String scanner;
    private final String scanDirPath;
    private final Map<String, CodefendFinding> vulnerabilityMap;
    private String project;

    CodefendResult(String project, Lang lang, Codefend.Context context, String scanner, String scanDirPath) {
        this.project = project;
        this.lang = lang;
        this.context = context;
        this.scanner = scanner;
        this.scanDirPath = scanDirPath;
        this.vulnerabilityMap = new HashMap<>();
    }

    CodefendFinding newVulnerability(String title, int priority) {
        return new CodefendFinding(this, title, priority);
    }

    void updateVulnerability(CodefendFinding vulnerability) {
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

    Codefend.Context getContext() {
        return context;
    }

    String getScanner() {
        return scanner;
    }

    String getScanDirPath() {
        return scanDirPath;
    }

    List<CodefendFinding> getVulnerabilities() {
        return new ArrayList<>(vulnerabilityMap.values());
    }
}
