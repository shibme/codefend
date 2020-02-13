package me.shib.security.codefender.scanners.java.dependencycheck.models;

import java.util.List;

public final class EvidenceCollected {

    private List<Evidence> vendorEvidence;
    private List<Evidence> productEvidence;
    private List<Evidence> versionEvidence;

    public List<Evidence> getVendorEvidence() {
        return vendorEvidence;
    }

    public List<Evidence> getProductEvidence() {
        return productEvidence;
    }

    public List<Evidence> getVersionEvidence() {
        return versionEvidence;
    }
}
