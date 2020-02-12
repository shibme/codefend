package me.shib.security.codefender.scanners.ruby.brakeman;

public class BrakemanError {
    private String error;
    private String location;

    public String getError() {
        return error;
    }

    public String getLocation() {
        return location;
    }
}
