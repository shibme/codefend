package me.shib.security.codeinspect.scanners.ruby.brakeman;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class BrakemanResult {

    private static final Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd HH:mm:ss Z").create();
    private BrakemanScanInfo scan_info;
    private BrakemanWarning[] warnings;
    private BrakemanWarning[] ignored_warnings;
    private BrakemanError[] errors;
    private String[] obsolete;

    static synchronized BrakemanResult getBrakemanResult(File jsonFile) throws IOException {
        StringBuilder jsonContent = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(jsonFile));
        String line;
        while ((line = br.readLine()) != null) {
            jsonContent.append(line).append("\n");
        }
        br.close();
        return gson.fromJson(jsonContent.toString(), BrakemanResult.class);
    }

    public BrakemanScanInfo getScan_info() {
        return scan_info;
    }

    public BrakemanWarning[] getWarnings() {
        return warnings;
    }

    public BrakemanWarning[] getIgnored_warnings() {
        return ignored_warnings;
    }

    public BrakemanError[] getErrors() {
        return errors;
    }

    public String[] getObsolete() {
        return obsolete;
    }
}
