package me.shib.security.codefender;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.shib.security.codefender.scanners.javascript.retirejs.RetirejsScanner;
import me.shib.security.codefender.scanners.ruby.brakeman.BrakemanScanner;
import me.shib.security.codefender.scanners.ruby.bundleraudit.BundlerAudit;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;

public final class CodefendLauncher {

    private static final transient Gson gson = new GsonBuilder().setPrettyPrinting()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss").create();

    private static void processResults(List<CodefenderResult> results) {
        for (CodefenderResult result : results) {
            List<CodefenderFinding> vulnerabilities = result.getVulnerabilities();
            StringBuilder content = new StringBuilder();
            content.append("Project:\t").append(result.getProject()).append("\n");
            content.append("Context:\t").append(result.getContext()).append("\n");
            content.append("Language:\t").append(result.getLang()).append("\n");
            content.append("Scanner:\t").append(result.getScanner()).append("\n");
            content.append("Count:\t").append(vulnerabilities.size()).append("\n");
            content.append("Vulnerabilities:").append("\n");
            for (CodefenderFinding vulnerability : vulnerabilities) {
                content.append("\n").append(vulnerability);
            }
            System.out.println(content);
        }
        try {
            Codefender.writeToFile(gson.toJson(results), new File("codefender-results.json"));
        } catch (FileNotFoundException e) {
            throw new CodefenderException(e);
        }
    }

    public static void main(String[] args) {
        System.out.println("Codefender: Starting independent run");
        CodefenderConfig config = CodefenderConfig.getInstance();
        Codefender.addScanner(new BrakemanScanner(config));
        Codefender.addScanner(new BundlerAudit(config));
        Codefender.addScanner(new RetirejsScanner(config));
        List<CodefenderResult> results = Codefender.execute(config);
        processResults(results);
    }
}
