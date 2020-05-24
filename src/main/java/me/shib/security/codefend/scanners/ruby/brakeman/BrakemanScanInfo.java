package me.shib.security.codefend.scanners.ruby.brakeman;

import java.util.Date;

public class BrakemanScanInfo {
    private String app_path;
    private String rails_version;
    private int security_warnings;
    private Date start_time;
    private Date end_time;
    private float duration;
    private String[] checks_performed;
    private int number_of_controllers;
    private int number_of_models;
    private int number_of_templates;
    private String ruby_version;
    private String brakeman_version;

    public String getApp_path() {
        return app_path;
    }

    public String getRails_version() {
        return rails_version;
    }

    public int getSecurity_warnings() {
        return security_warnings;
    }

    public Date getStart_time() {
        return start_time;
    }

    public Date getEnd_time() {
        return end_time;
    }

    public float getDuration() {
        return duration;
    }

    public String[] getChecks_performed() {
        return checks_performed;
    }

    public int getNumber_of_controllers() {
        return number_of_controllers;
    }

    public int getNumber_of_models() {
        return number_of_models;
    }

    public int getNumber_of_templates() {
        return number_of_templates;
    }

    public String getRuby_version() {
        return ruby_version;
    }

    public String getBrakeman_version() {
        return brakeman_version;
    }
}
