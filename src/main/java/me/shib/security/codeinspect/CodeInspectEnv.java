package me.shib.security.codeinspect;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

enum CodeInspectEnv {

    CODEINSPECT_PROJECT("Project name of the scan"),
    CODEINSPECT_DIR("Specific directory inside the current directory to be scanned"),
    CODEINSPECT_CONTEXT("Type of scan [SAST or SCA - Does both by default]"),
    CODEINSPECT_LANG("Target language to be scanned [" + langAsList() + "]."),
    CODEINSPECT_BUILDSCRIPT("Any script that needs to be run before scan."),
    CODEINSPECT_TOOL("One of the available tool's name to be used specifically"),
    CODEINSPECT_GIT_REPO("Git repository URI if source is not available in current directory"),
    CODEINSPECT_GIT_BRANCH("The branch in the repository to be scanned"),
    CODEINSPECT_GIT_COMMIT("The commit hash to be checked out and scanned"),
    CODEINSPECT_GIT_USERNAME("The username of the git account to perform a HTTP based clone"),
    CODEINSPECT_GIT_TOKEN("The password or access token of the git account to perform a HTTP based clone"),
    CODEINSPECT_GIT_SSHKEY("The SSH private key file path to perform SSH based clone");

    private final String definition;

    CodeInspectEnv(String definition) {
        this.definition = definition;
    }

    private static String langAsList() {
        List<String> langs = new ArrayList<>();
        for (Lang lang : Lang.values()) {
            langs.add(lang.name());
        }
        return String.join(" | ", langs);
    }

    static String getVarDefinitions() {
        StringBuilder varDefinitions = new StringBuilder();
        for (CodeInspectEnv env : CodeInspectEnv.values()) {
            varDefinitions.append("\n").append(env).append("\n")
                    .append("\t- ").append(env.definition);
        }
        return varDefinitions.toString();
    }

    private String getValue() {
        String val = System.getenv(name());
        if (val != null && val.isEmpty()) {
            return null;
        }
        return val;
    }

    String getAsString() {
        return getValue();
    }

    List<String> getAsList() {
        try {
            return Arrays.asList(getValue().split(","));
        } catch (Exception e) {
            return null;
        }
    }

    boolean getAsBoolean() {
        try {
            return getValue().equalsIgnoreCase("TRUE");
        } catch (Exception e) {
            return false;
        }
    }

    Integer getAsInteger() {
        try {
            return Integer.parseInt(getValue());
        } catch (Exception e) {
            return null;
        }
    }
}
