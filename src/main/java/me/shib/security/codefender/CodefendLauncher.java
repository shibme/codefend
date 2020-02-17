package me.shib.security.codefender;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.List;

public final class CodefendLauncher {

    private static final transient Gson gson = new GsonBuilder().setPrettyPrinting()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss").create();

    private static boolean processResults(List<Codefender> scanners) {
        boolean vulnerable = false;
        for (Codefender scanner : scanners) {
            List<CodefenderVulnerability> vulnerabilities = scanner.getVulnerabilities();
            vulnerable |= vulnerabilities.size() > 0;
            StringBuilder content = new StringBuilder();
            content.append("Project:\t").append(scanner.getProject()).append("\n");
            content.append("Context:\t").append(scanner.getContext()).append("\n");
            content.append("Language:\t").append(scanner.getLang()).append("\n");
            content.append("Scanner:\t").append(scanner.getScanner()).append("\n");
            content.append("Count:\t").append(vulnerabilities.size()).append("\n");
            content.append("Vulnerabilities:").append("\n");
            for (CodefenderVulnerability vulnerability : vulnerabilities) {
                content.append("\n").append(vulnerability);
            }
            System.out.println(content);
        }
        try {
            //TODO
            //Codefender.writeToFile(gson.toJson(results), new File("codefender-results.json"));
        } catch (Exception e) {
            throw new CodefenderException(e);
        }
        return vulnerable;
    }

    public static void main(String[] args) {
        CodefenderConfig config = CodefenderConfig.getInstance();
        List<Codefender> scanners = Codefender.getScanners(config);
        for (Codefender codefender : scanners) {
            System.out.println("Now running scanner: " + codefender.getTool());
            try {
                codefender.scan();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (processResults(scanners)) {
            System.exit(1);
        }
    }
}
