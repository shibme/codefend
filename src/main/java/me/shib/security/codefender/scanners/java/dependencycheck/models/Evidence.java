package me.shib.security.codefender.scanners.java.dependencycheck.models;

public final class Evidence {

    private String type;
    private String confidence;
    private String source;
    private String name;
    private String value;

    public String getType() {
        return type;
    }

    public String getConfidence() {
        return confidence;
    }

    public String getSource() {
        return source;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }
}
