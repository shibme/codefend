package me.shib.security.codefend.scanners.java.dependencycheck.models;

public final class CVSSv2 {

    private float score;
    private String accessVector;
    private String accessComplexity;
    private String authenticationr;
    private String confidentialImpact;
    private String integrityImpact;
    private String availabilityImpact;
    private String severity;

    public float getScore() {
        return score;
    }

    public String getAccessVector() {
        return accessVector;
    }

    public String getAccessComplexity() {
        return accessComplexity;
    }

    public String getAuthenticationr() {
        return authenticationr;
    }

    public String getConfidentialImpact() {
        return confidentialImpact;
    }

    public String getIntegrityImpact() {
        return integrityImpact;
    }

    public String getAvailabilityImpact() {
        return availabilityImpact;
    }

    public String getSeverity() {
        return severity;
    }
}
