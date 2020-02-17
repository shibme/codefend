package me.shib.security.codefender.scanners.ruby.brakeman;

import me.shib.security.codefender.*;

import java.io.File;
import java.io.IOException;

public final class BrakemanScanner extends Codefender {

    private static final String tool = "Brakeman";
    private static final File brakemanOutput = new File("brakeman-result.json");
    private static final String[] excludedPaths = {"Gemfile.lock"};

    public BrakemanScanner(CodefenderConfig config) throws CodefenderException {
        super(config);
    }

    private static boolean isExcludedPath(String path) {
        for (String p : excludedPaths) {
            if (p.equalsIgnoreCase(path)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Lang getLang() {
        return Lang.Ruby;
    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public Context getContext() {
        return Context.SAST;
    }

    @Override
    public void scan() throws CodefenderException, IOException, InterruptedException {
        if (!isParserOnly()) {
            brakemanOutput.delete();
            runBrakeman();
        }
        processBrakemanResult();
    }

    private void runBrakeman() throws CodefenderException, IOException, InterruptedException {
        StringBuilder brakemanCommandBuilder = new StringBuilder();
        brakemanCommandBuilder.append("brakeman -o ").append(brakemanOutput.getAbsolutePath());
        String response = runCommand(brakemanCommandBuilder.toString());
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new CodefenderException("Install brakeman before proceeding");
        }
    }

    private void warningToVulnerability(BrakemanWarning warning) throws CodefenderException {
        String title = "Brakeman warning (" + warning.getWarning_type() + ") found in " + warning.getFile();
        int priority = BrakemanPriorityCalculator.getCodefendPriority(warning.getWarning_type(), warning.getConfidence());
        CodefenderVulnerability vulnerability = newVulnerability(title, priority);
        if (warning.getLink() != null) {
            vulnerability.setField("Type", "[" + warning.getWarning_type() + "](" + warning.getLink() + ")");
        } else {
            vulnerability.setField("Type", warning.getWarning_type());
        }
        vulnerability.setField("File", warning.getFile());
        vulnerability.setField("Line", warning.getLine() + "");
        vulnerability.setField("Message", warning.getMessage());
        vulnerability.setField("Confidence", warning.getConfidence());
        if (warning.getCode() != null) {
            vulnerability.setField("Code", "```\n" + warning.getCode() + "\n```");
        }
        vulnerability.addKey(warning.getFile());
        vulnerability.addKey("Brakeman-" + warning.getFingerprint());
        vulnerability.update();
    }

    private void processBrakemanResult() throws IOException, CodefenderException {
        BrakemanResult brakemanResult = BrakemanResult.getBrakemanResult(brakemanOutput);
        for (BrakemanWarning warning : brakemanResult.getWarnings()) {
            if (!isExcludedPath(warning.getFile())) {
                warningToVulnerability(warning);
            }
        }
    }

}
