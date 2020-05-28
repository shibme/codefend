package me.shib.security.codeinspect;

import java.util.*;

final class CodeInspectResult {

    private final Lang lang;
    private final CodeInspect.Context context;
    private final String scanner;
    private final String scanDirPath;
    private final Map<String, CodeInspectFinding> findingMap;
    private String project;

    CodeInspectResult(String project, Lang lang, CodeInspect.Context context, String scanner, String scanDirPath) {
        this.project = project;
        this.lang = lang;
        this.context = context;
        this.scanner = scanner;
        this.scanDirPath = scanDirPath;
        this.findingMap = new HashMap<>();
    }

    CodeInspectFinding newFinding(String title, CodeInspectPriority priority) {
        return new CodeInspectFinding(this, title, priority);
    }

    void updateFinding(CodeInspectFinding finding) {
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

    CodeInspect.Context getContext() {
        return context;
    }

    String getScanner() {
        return scanner;
    }

    String getScanDirPath() {
        return scanDirPath;
    }

    List<CodeInspectFinding> getFindings() {
        return new ArrayList<>(findingMap.values());
    }
}
