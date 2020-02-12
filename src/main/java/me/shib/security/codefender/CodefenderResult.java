package me.shib.security.codefender;

import java.util.*;

final class CodefenderResult {

    private String project;
    private Lang lang;
    private Codefender.Context context;
    private String scanner;
    private String scanDirPath;
    private Map<String, CodefenderFinding> vulnerabilityMap;

    CodefenderResult(String project, Lang lang, Codefender.Context context, String scanner, String scanDirPath) {
        this.project = project;
        this.lang = lang;
        this.context = context;
        this.scanner = scanner;
        this.scanDirPath = scanDirPath;
        this.vulnerabilityMap = new HashMap<>();
    }

    CodefenderFinding newVulnerability(String title, int priority) {
        return new CodefenderFinding(this, title, priority);
    }

    void updateVulnerability(CodefenderFinding vulnerability) {
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

    Codefender.Context getContext() {
        return context;
    }

    String getScanner() {
        return scanner;
    }

    String getScanDirPath() {
        return scanDirPath;
    }

    public List<CodefenderFinding> getVulnerabilities() {
        return new ArrayList<>(vulnerabilityMap.values());
    }
}
