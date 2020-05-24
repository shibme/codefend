package me.shib.security.codefend.scanners.java.dependencycheck.models;

public final class Software {

    private String id;
    private String versionStartIncluding;
    private String versionEndExcluding;

    public String getId() {
        return id;
    }

    public String getVersionStartIncluding() {
        return versionStartIncluding;
    }

    public String getVersionEndExcluding() {
        return versionEndExcluding;
    }
}
