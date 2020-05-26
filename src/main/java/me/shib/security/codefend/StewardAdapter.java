package me.shib.security.codefend;

import me.shib.lib.trakr.TrakrPriority;
import me.shib.steward.StewardData;
import me.shib.steward.StewardFinding;

import java.util.List;

final class StewardAdapter {

    private static final transient String toolName = "CodeFend";

    private static TrakrPriority toStewardPriority(CodeFendPriority priority) {
        switch (priority) {
            case P0:
                return TrakrPriority.P0;
            case P1:
                return TrakrPriority.P1;
            case P2:
                return TrakrPriority.P2;
            case P3:
                return TrakrPriority.P3;
            case P4:
                return TrakrPriority.P4;
            default:
                return null;
        }
    }

    private static StewardFinding toStewardFinding(CodeFendFinding finding) {
        StewardFinding sf = new StewardFinding(finding.getTitle(), toStewardPriority(finding.getPriority()));
        sf.addContext(finding.getProject());
        sf.addContext(finding.getLang().name());
        sf.addContext(finding.getContext().getLabel());
        sf.addContexts(finding.getKeys());
        sf.addTags(finding.getTags());
        sf.setDescription(finding.getDescription());
        return sf;
    }

    static StewardData toStewardData(CodeFendConfig config, List<CodeFendFinding> findings) {
        StewardData data = new StewardData(config.getProject(), toolName);
        data.addContext(config.getLang().name());
        if (config.getGitRepo() != null) {
            data.addContext(config.getGitRepo().getGitRepoSlug());
        }
        if (config.getScanDirPath() != null && !config.getScanDirPath().isEmpty()) {
            String scanDirContext = "ScanDir-" + config.getScanDirPath();
            data.addContext(scanDirContext);
        }
        for (CodeFendFinding finding : findings) {
            data.addFinding(toStewardFinding(finding));
        }
        return data;
    }

}
