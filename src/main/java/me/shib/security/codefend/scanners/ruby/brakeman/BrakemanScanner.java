package me.shib.security.codefend.scanners.ruby.brakeman;

import me.shib.security.codefend.*;

import java.io.File;
import java.io.IOException;

public final class BrakemanScanner extends CodeFend {

    private static final String tool = "Brakeman";
    private static final File brakemanOutput = new File("brakeman-result.json");
    private static final String[] excludedPaths = {"Gemfile.lock"};

    public BrakemanScanner(CodeFendConfig config) throws CodeFendException {
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
    protected void scan() throws CodeFendException, IOException, InterruptedException {
        brakemanOutput.delete();
        runBrakeman();
        processBrakemanResult();
    }

    private void runBrakeman() throws CodeFendException, IOException, InterruptedException {
        String response = runCommand("brakeman -o " + brakemanOutput.getAbsolutePath());
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new CodeFendException("Install brakeman before proceeding");
        }
    }

    private String getDescription(BrakemanWarning warning) {
        StringBuilder description = new StringBuilder();
        description.append("The following insecure code warnings were found in ").append("**[")
                .append(warning.getFile()).append("](").append(getConfig().getGitRepo().getGitRepoWebURL()).append("/tree/")
                .append(getConfig().getGitRepo().getGitRepoCommitHash()).append("/").append(warning.getFile()).append("):**\n");
        description.append(" * **Line:** ").append(warning.getLine()).append("\n");
        description.append(" * **Type:** ");
        if (warning.getLink() != null) {
            description.append("[").append(warning.getWarning_type()).append("](").append(warning.getLink()).append(")");
        } else {
            description.append(warning.getWarning_type());
        }
        description.append("\n");
        description.append(" * **Message:** ").append(warning.getMessage()).append("\n");
        description.append(" * **Confidence:** ").append(warning.getConfidence());
        if (warning.getCode() != null) {
            description.append("\n * **Code:**\n");
            description.append("```\n");
            description.append(warning.getCode());
            description.append("\n```");
        }
        return description.toString();
    }

    private void warningToFinding(BrakemanWarning warning) throws CodeFendException {
        String title = "SAST warning (" + warning.getWarning_type() + ") found in " + warning.getFile() + " of " + getConfig().getProject();
        CodeFendPriority priority = BrakemanPriorityCalculator.getCodeFendPriority(warning.getWarning_type(), warning.getConfidence());
        CodeFendFinding finding = newFinding(title, priority);
        if (warning.getLink() != null) {
            finding.setField("Type", "[" + warning.getWarning_type() + "](" + warning.getLink() + ")");
        } else {
            finding.setField("Type", warning.getWarning_type());
        }
        finding.setField("File", warning.getFile());
        finding.setField("Line", warning.getLine() + "");
        finding.setField("Message", warning.getMessage());
        finding.setField("Confidence", warning.getConfidence());
        if (warning.getCode() != null) {
            finding.setField("Code", "```\n" + warning.getCode() + "\n```");
        }
        finding.addKey(warning.getFile());
        finding.addKey("Brakeman-" + warning.getFingerprint());
        finding.setDescription(getDescription(warning));
        finding.update();
    }

    private void processBrakemanResult() throws IOException, CodeFendException {
        BrakemanResult brakemanResult = BrakemanResult.getBrakemanResult(brakemanOutput);
        for (BrakemanWarning warning : brakemanResult.getWarnings()) {
            if (!isExcludedPath(warning.getFile())) {
                warningToFinding(warning);
            }
        }
    }

}
