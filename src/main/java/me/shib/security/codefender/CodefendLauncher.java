package me.shib.security.codefender;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.shib.security.codefender.scanners.java.dependencycheck.DependencyCheck;
import me.shib.security.codefender.scanners.javascript.retirejs.RetirejsScanner;
import me.shib.security.codefender.scanners.ruby.brakeman.BrakemanScanner;
import me.shib.security.codefender.scanners.ruby.bundleraudit.BundlerAudit;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;

public final class CodefendLauncher {

    private static final transient Gson gson = new GsonBuilder().setPrettyPrinting()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss").create();

    private static boolean processResults(List<CodefenderResult> results) {
        boolean vulnerable = false;
        for (CodefenderResult result : results) {
            List<CodefenderVulnerability> vulnerabilities = result.getVulnerabilities();
            vulnerable |= vulnerabilities.size() > 0;
            StringBuilder content = new StringBuilder();
            content.append("Project:\t").append(result.getProject()).append("\n");
            content.append("Context:\t").append(result.getContext()).append("\n");
            content.append("Language:\t").append(result.getLang()).append("\n");
            content.append("Scanner:\t").append(result.getScanner()).append("\n");
            content.append("Count:\t").append(vulnerabilities.size()).append("\n");
            content.append("Vulnerabilities:").append("\n");
            for (CodefenderVulnerability vulnerability : vulnerabilities) {
                content.append("\n").append(vulnerability);
            }
            System.out.println(content);
        }
        try {
            Codefender.writeToFile(gson.toJson(results), new File("codefender-results.json"));
        } catch (FileNotFoundException e) {
            throw new CodefenderException(e);
        }
        return vulnerable;
    }

    public static void main(String[] args) {
        System.out.println("Codefender: Starting independent run");
        CodefenderConfig config = CodefenderConfig.getInstance();
        Codefender.addScanner(new BrakemanScanner(config));
        Codefender.addScanner(new BundlerAudit(config));
        Codefender.addScanner(new RetirejsScanner(config));
        Codefender.addScanner(new DependencyCheck(config));
        List<CodefenderResult> results = Codefender.execute(config);
        if (processResults(results)) {
            System.exit(1);
        }
    }
}
