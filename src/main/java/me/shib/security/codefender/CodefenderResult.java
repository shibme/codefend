package me.shib.security.codefender;

import java.util.*;

final class CodefenderResult {

    private String project;
    private Lang lang;
    private Codefender.Context context;
    private String scanner;
    private String scanDirPath;
    private Map<String, CodefenderVulnerability> vulnerabilityMap;

    CodefenderResult(String project, Lang lang, Codefender.Context context, String scanner, String scanDirPath) {
        this.project = project;
        this.lang = lang;
        this.context = context;
        this.scanner = scanner;
        this.scanDirPath = scanDirPath;
        this.vulnerabilityMap = new HashMap<>();
    }

    CodefenderVulnerability newVulnerability(String title, int priority) {
        return new CodefenderVulnerability(this, title, priority);
    }

    void updateVulnerability(CodefenderVulnerability vulnerability) {
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

    Codefender.Context getContext() {
        return context;
    }

    String getScanner() {
        return scanner;
    }

    String getScanDirPath() {
        return scanDirPath;
    }

    List<CodefenderVulnerability> getVulnerabilities() {
        return new ArrayList<>(vulnerabilityMap.values());
    }
}
