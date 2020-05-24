package me.shib.security.codefend;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.List;

public final class CodefendLauncher {

    private static final transient Gson gson = new GsonBuilder().setPrettyPrinting()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss").create();

    private static boolean processResults(List<Codefend> scanners) {
        boolean vulnerable = false;
        for (Codefend scanner : scanners) {
            List<CodefendFinding> vulnerabilities = scanner.getVulnerabilities();
            vulnerable |= vulnerabilities.size() > 0;
            StringBuilder content = new StringBuilder();
            content.append("Project:\t").append(scanner.getProject()).append("\n");
            content.append("Context:\t").append(scanner.getContext()).append("\n");
            content.append("Language:\t").append(scanner.getLang()).append("\n");
            content.append("Scanner:\t").append(scanner.getScanner()).append("\n");
            content.append("Count:\t").append(vulnerabilities.size()).append("\n");
            content.append("Vulnerabilities:").append("\n");
            for (CodefendFinding vulnerability : vulnerabilities) {
                content.append("\n").append(vulnerability);
            }
            System.out.println(content);
        }
        try {
            //TODO
            //Codefend.writeToFile(gson.toJson(results), new File("codefend-results.json"));
        } catch (Exception e) {
            throw new CodefendException(e);
        }
        return vulnerable;
    }

    public static void main(String[] args) {
        CodefendConfig config = CodefendConfig.getInstance();
        List<Codefend> scanners = Codefend.getScanners(config);
        for (Codefend codefend : scanners) {
            System.out.println("Now running scanner: " + codefend.getTool());
            try {
                codefend.scan();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (processResults(scanners)) {
            System.exit(1);
        }
    }
}
