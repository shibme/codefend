package me.shib.security.codefend;

import java.util.*;

public final class CodeFendFinding {

    private static final transient String cveBaseURL = "https://nvd.nist.gov/vuln/detail/";
    private final transient CodeFendResult result;

    private final String title;
    private final CodeFendPriority priority;
    private final Map<String, String> fields;
    private final Set<String> keys;
    private final Set<String> tags;
    private String description;

    CodeFendFinding(CodeFendResult result, String title, CodeFendPriority priority) {
        this.result = result;
        this.title = title;
        this.priority = priority;
        this.fields = new LinkedHashMap<>();
        this.keys = new HashSet<>();
        this.tags = new HashSet<>();
    }

    public void update() {
        result.updateVulnerability(this);
    }

    public void addKey(String key) throws CodeFendException {
        if (key == null || key.isEmpty()) {
            throw new CodeFendException("Null or Empty key cannot be processed");
        }
        this.keys.add(key);
    }

    public void addTag(String tag) {
        this.tags.add(tag);
    }

    public String getTitle() {
        return this.title;
    }

    public CodeFendPriority getPriority() {
        return priority;
    }

    public void setCVE(String cve) {
        if (cve != null && cve.toUpperCase().startsWith("CVE")) {
            setField("CVE", "[" + cve + "](" + cveBaseURL + cve + ")");
        }
    }

    public void setCVEs(List<String> cves) {
        Set<String> cveSet = new HashSet<>(cves);
        StringBuilder cveContent = new StringBuilder();
        for (String cve : cveSet) {
            if (cve != null && cve.toUpperCase().startsWith("CVE")) {
                cveContent.append("[").append(cve).append("](").append(cveBaseURL).append(cve).append(")").append(" ");
            }
        }
        if (!cveContent.toString().isEmpty()) {
            setField("CVEs", cveContent.toString().trim());
        }
    }

    public void setField(String label, String content) {
        this.fields.put(label, content);
    }

    public Map<String, String> getFields() {
        return fields;
    }

    public Set<String> getKeys() {
        return this.keys;
    }

    public Set<String> getTags() {
        return this.tags;
    }

    public String getDescription() {
        if (description == null) {
            StringBuilder content = new StringBuilder();
            for (String key : fields.keySet()) {
                content.append(" * **").append(key).append(":** ")
                        .append(fields.get(key)).append("\n");
            }
            return content.toString();
        }
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getProject() {
        return result.getProject();
    }

    public Lang getLang() {
        return result.getLang();
    }

    public CodeFend.Context getContext() {
        return result.getContext();
    }

    public String getScanner() {
        return result.getScanner();
    }

    public String getScanDirPath() {
        return result.getScanDirPath();
    }

    @Override
    public String toString() {
        StringBuilder content = new StringBuilder();
        content.append("Title:\t").append(title)
                .append("\nPriority:\t").append(priority);
        if (tags.size() > 0) {
            content.append("\nTags:");
            for (String tag : tags) {
                content.append(" ").append(tag);
            }
        }
        for (String label : fields.keySet()) {
            content.append("\n").append(label).append(":\t").append(fields.get(label));
        }
        content.append("\n");
        return content.toString();
    }
}
