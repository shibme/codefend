package me.shib.security.codefender.scanners.java.dependencycheck.models;

import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public final class DependencyCheckResult {

    private static transient final Gson gson = new Gson();

    private String reportSchema;
    private List<Dependency> dependencies;
    private transient List<Dependency> vulnerableDependencies;

    private static String readFromFile(File file) throws IOException {
        if (!file.exists() || file.isDirectory()) {
            return "";
        }
        StringBuilder contentBuilder = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            contentBuilder.append(line).append("\n");
        }
        br.close();
        return contentBuilder.toString();
    }

    public static DependencyCheckResult getResult(File dependencyCheckJSON) throws IOException {
        String json = readFromFile(dependencyCheckJSON);
        DependencyCheckResult result = gson.fromJson(json, DependencyCheckResult.class);
        result.collectVulnerableDependencies();
        return result;
    }

    public String getReportSchema() {
        return reportSchema;
    }

    public List<Dependency> getDependencies() {
        return dependencies;
    }

    public List<Dependency> getVulnerableDependencies() {
        return vulnerableDependencies;
    }

    private void collectVulnerableDependencies() {
        this.vulnerableDependencies = new ArrayList<>();
        for (Dependency dependency : dependencies) {
            if (dependency.getVulnerabilities() != null) {
                for (Vulnerability vulnerability : dependency.getVulnerabilities()) {
                    if (vulnerability.getName().toUpperCase().startsWith("CVE-") &&
                            vulnerability.getSource() != Vulnerability.Source.RETIREJS) {
                        vulnerableDependencies.add(dependency);
                        break;
                    }
                }
            }
        }
    }

}
