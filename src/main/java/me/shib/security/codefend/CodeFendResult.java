package me.shib.security.codefend;

import java.util.*;

final class CodeFendResult {

    private final Lang lang;
    private final CodeFend.Context context;
    private final String scanner;
    private final String scanDirPath;
    private final Map<String, CodeFendFinding> findingMap;
    private String project;

    CodeFendResult(String project, Lang lang, CodeFend.Context context, String scanner, String scanDirPath) {
        this.project = project;
        this.lang = lang;
        this.context = context;
        this.scanner = scanner;
        this.scanDirPath = scanDirPath;
        this.findingMap = new HashMap<>();
    }

    CodeFendFinding newFinding(String title, CodeFendPriority priority) {
        return new CodeFendFinding(this, title, priority);
    }

    void updateFinding(CodeFendFinding finding) {
        finding.addKey(project);
        finding.addTag(project);
        finding.addKey(lang.toString());
        finding.addTag(lang.toString());
        finding.addKey(context.getLabel());
        finding.addTag(context.getLabel());
        finding.addKey(scanner);
        finding.addTag(scanner);
        StringBuilder key = new StringBuilder();
        List<String> keyList = new ArrayList<>(finding.getKeys());
        Collections.sort(keyList);
        for (String k : keyList) {
            key.append(k).append(";");
        }
        findingMap.put(key.toString(), finding);
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

    List<CodeFendFinding> getFindings() {
        return new ArrayList<>(findingMap.values());
    }
}
