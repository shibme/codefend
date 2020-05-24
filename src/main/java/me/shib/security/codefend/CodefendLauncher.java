package me.shib.security.codefend;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.shib.steward.Steward;
import me.shib.steward.StewardConfig;
import me.shib.steward.StewardData;

import java.util.ArrayList;
import java.util.List;

final class CodefendLauncher {

    private static final transient Gson gson = new GsonBuilder().setPrettyPrinting()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss").create();

    private static void processResults(CodefendConfig config, List<Codefend> codefends) {
        try {
            List<CodefendFinding> findings = new ArrayList<>();
            for (Codefend codefend : codefends) {
                findings.addAll(codefend.getFindings());
            }
            StewardData data = StewardAdapter.toStewardData(config, findings);
            Steward.process(data, StewardConfig.getConfig());
        } catch (Exception e) {
            throw new CodefendException(e);
        }
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
        processResults(config, scanners);
    }
}
