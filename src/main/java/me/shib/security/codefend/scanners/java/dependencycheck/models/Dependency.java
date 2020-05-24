package me.shib.security.codefend.scanners.java.dependencycheck.models;

import java.util.List;

public final class Dependency {

    private boolean isVirtual;
    private String fileName;
    private transient String name;
    private String filePath;
    private String md5;
    private String sha1;
    private String sha256;
    private EvidenceCollected evidenceCollected;
    private List<VulnerabilityId> vulnerabilityIds;
    private List<Vulnerability> vulnerabilities;

    public boolean isVirtual() {
        return isVirtual;
    }

    public String getFileName() {
        return fileName;
    }

    public String getName() {
        if (null == name) {
            name = fileName.split("(^|-)([0-9])")[0];
        }
        return name;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getMd5() {
        return md5;
    }

    public String getSha1() {
        return sha1;
    }

    public String getSha256() {
        return sha256;
    }

    public EvidenceCollected getEvidenceCollected() {
        return evidenceCollected;
    }

    public List<VulnerabilityId> getVulnerabilityIds() {
        return vulnerabilityIds;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }
}
