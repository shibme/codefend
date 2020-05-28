package me.shib.security.codeinspect.scanners.ruby.brakeman;

import java.util.Map;

public final class BrakemanWarning {

    private String warning_type;
    private int warning_code;
    private String fingerprint;
    private String check_name;
    private String message;
    private String file;
    private Integer line;
    private String link;
    private String code;
    private Object[] render_path;
    private Map<String, String> location;
    private String user_input;
    private String confidence;

    public String getWarning_type() {
        return warning_type;
    }

    public int getWarning_code() {
        return warning_code;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getCheck_name() {
        return check_name;
    }

    public String getMessage() {
        return message;
    }

    public String getFile() {
        return file;
    }

    public int getLine() {
        if (line == null) {
            return 0;
        }
        return line;
    }

    public String getLink() {
        return link;
    }

    public String getCode() {
        return code;
    }

    public Object[] getRender_path() {
        return render_path;
    }

    public Map<String, String> getLocation() {
        return location;
    }

    public String getUser_input() {
        return user_input;
    }

    public String getConfidence() {
        return confidence;
    }

}
