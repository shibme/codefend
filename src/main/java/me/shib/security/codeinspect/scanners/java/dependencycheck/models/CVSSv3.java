package me.shib.security.codeinspect.scanners.java.dependencycheck.models;

public final class CVSSv3 {

    private float baseScore;
    private String attackVector;
    private String attackComplexity;
    private String privilegesRequired;
    private String userInteraction;
    private String scope;
    private String confidentialityImpact;
    private String integrityImpact;
    private String availabilityImpact;
    private String baseSeverity;

    public float getBaseScore() {
        return baseScore;
    }

    public String getAttackVector() {
        return attackVector;
    }

    public String getAttackComplexity() {
        return attackComplexity;
    }

    public String getPrivilegesRequired() {
        return privilegesRequired;
    }

    public String getUserInteraction() {
        return userInteraction;
    }

    public String getScope() {
        return scope;
    }

    public String getConfidentialityImpact() {
        return confidentialityImpact;
    }

    public String getIntegrityImpact() {
        return integrityImpact;
    }

    public String getAvailabilityImpact() {
        return availabilityImpact;
    }

    public String getBaseSeverity() {
        return baseSeverity;
    }
}
