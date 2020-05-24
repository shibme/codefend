package me.shib.security.codefend.scanners.ruby.brakeman;

import java.util.HashMap;
import java.util.Map;

final class BrakemanPriorityCalculator {

    private static final int[][] priorityConfidenceMatrix = new int[][]{
            {0, 1, 2},
            {1, 1, 2},
            {2, 2, 3},
            {3, 3, 3}
    };

    private static final Map<String, Integer> typeToNumberMap;
    private static final Map<String, Integer> confidenceToNumberMap;

    static {
        typeToNumberMap = new HashMap<>();
        typeToNumberMap.put("Attribute Restriction", 3);
        typeToNumberMap.put("Authentication", 1);
        typeToNumberMap.put("Basic Authentication", 1);
        typeToNumberMap.put("Command Injection", 1);
        typeToNumberMap.put("Cross-Site Request Forgery", 2);
        typeToNumberMap.put("Cross Site Scripting", 1);
        typeToNumberMap.put("Cross Site Scripting (Content Tag)", 1);
        typeToNumberMap.put("Cross Site Scripting (JSON)", 2);
        typeToNumberMap.put("Dangerous Evaluation", 1);
        typeToNumberMap.put("Dangerous Send", 2);
        typeToNumberMap.put("Default Routes", 3);
        typeToNumberMap.put("Denial of Service", 1);
        typeToNumberMap.put("Dynamic Render Paths", 3);
        typeToNumberMap.put("File Access", 2);
        typeToNumberMap.put("Format Validation", 3);
        typeToNumberMap.put("Information Disclosure", 3);
        typeToNumberMap.put("Mail Link", 1);
        typeToNumberMap.put("Mass Assignment", 2);
        typeToNumberMap.put("Remote Code Execution", 1);
        typeToNumberMap.put("Remote Execution in YAML.load", 1);
        typeToNumberMap.put("Session Manipulation", 2);
        typeToNumberMap.put("Session Settings", 2);
        typeToNumberMap.put("SQL Injection", 1);
        typeToNumberMap.put("SSL Verification Bypass", 2);
        typeToNumberMap.put("Unsafe Deserialization", 1);
        typeToNumberMap.put("Unscoped Find", 2);
        typeToNumberMap.put("Unsafe Redirects", 2);

        confidenceToNumberMap = new HashMap<>();
        confidenceToNumberMap.put("High", 1);
        confidenceToNumberMap.put("Medium", 2);
        confidenceToNumberMap.put("Weak", 3);
    }

    static int getCodefendPriority(String type, String confidence) {
        Integer typeNumber = null;
        Integer confidenceNumber = null;
        if (type != null) {
            typeNumber = typeToNumberMap.get(type);
        }
        if (typeNumber == null) {
            typeNumber = 2;
        }
        if (confidence != null) {
            confidenceNumber = confidenceToNumberMap.get(type);
        }
        if (confidenceNumber == null) {
            confidenceNumber = 2;
        }
        return priorityConfidenceMatrix[typeNumber][confidenceNumber];
    }

}
