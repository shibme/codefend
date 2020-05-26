package me.shib.security.codefend;

import me.shib.steward.Steward;
import me.shib.steward.StewardConfig;
import me.shib.steward.StewardData;

import java.util.ArrayList;
import java.util.List;

final class CodeFendLauncher {

    private static void processResults(CodeFendConfig config, List<CodeFend> codeFends) {
        try {
            List<CodeFendFinding> findings = new ArrayList<>();
            for (CodeFend codefend : codeFends) {
                findings.addAll(codefend.getFindings());
            }
            StewardData data = StewardAdapter.toStewardData(config, findings);
            Steward.process(data, StewardConfig.getConfig());
        } catch (Exception e) {
            throw new CodeFendException(e);
        }
    }

    public static void main(String[] args) {
        CodeFendConfig config = CodeFendConfig.getInstance();
        List<CodeFend> scanners = CodeFend.getScanners(config);
        for (CodeFend codefend : scanners) {
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
