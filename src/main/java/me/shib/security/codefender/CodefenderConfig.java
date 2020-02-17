package me.shib.security.codefender;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class CodefenderConfig {

    private static final transient String CODEFENDER_PROJECT = "CODEFENDER_PROJECT";
    private static final transient String CODEFENDER_DIR = "CODEFENDER_DIR";
    private static final transient String CODEFENDER_CONTEXT = "CODEFENDER_CONTEXT";
    private static final transient String CODEFENDER_LANG = "CODEFENDER_LANG";
    private static final transient String CODEFENDER_TOOL = "CODEFENDER_TOOL";
    private static final transient String CODEFENDER_BUILDSCRIPT = "CODEFENDER_BUILDSCRIPT";
    private static final transient String CODEFENDER_PARSEONLY = "CODEFENDER_PARSEONLY";
    private static final transient String CODEFENDER_GIT_REPO = "CODEFENDER_GIT_REPO";
    private static final transient String CODEFENDER_GIT_BRANCH = "CODEFENDER_GIT_BRANCH";
    private static final transient String CODEFENDER_GIT_COMMIT = "CODEFENDER_GIT_COMMIT";
    private static final transient String CODEFENDER_GIT_USERNAME = "CODEFENDER_GIT_USERNAME";
    private static final transient String CODEFENDER_GIT_TOKEN = "CODEFENDER_GIT_TOKEN";
    private static final transient String CODEFENDER_GIT_SSHKEY = "CODEFENDER_GIT_SSHKEY";

    private static transient CodefenderConfig config;

    private transient File scanDir;
    private transient GitRepo gitRepo;

    private String project;
    private String scanDirPath;
    private String buildScript;
    private Lang lang;
    private Codefender.Context context;
    private String tool;
    private GitCredential gitCredential;
    private Boolean parseOnly;

    public CodefenderConfig(String project, String scanDirPath, String buildScript, Lang lang,
                            Codefender.Context context, String tool, GitRepo gitRepo, GitCredential gitCredential, Boolean parseOnly) {
        this.project = project;
        this.scanDirPath = scanDirPath;
        this.buildScript = buildScript;
        this.lang = lang;
        this.context = context;
        this.tool = tool;
        this.gitRepo = gitRepo;
        this.gitCredential = gitCredential;
        this.parseOnly = parseOnly;
        init();
    }

    private CodefenderConfig() {
        init();
    }

    static synchronized CodefenderConfig getInstance() {
        if (config == null) {
            config = new CodefenderConfig();
        }
        return config;
    }

    private synchronized GitRepo buildGitRepoFromEnv() {
        String gitUri = envValue(CODEFENDER_GIT_REPO);
        if (gitUri == null || gitUri.isEmpty()) {
            return null;
        }
        String gitBranch = envValue(CODEFENDER_GIT_BRANCH);
        String gitCommit = envValue(CODEFENDER_GIT_COMMIT);
        return new GitRepo(gitUri, gitBranch, gitCommit);
    }

    private String envValue(String var) {
        String value = System.getenv(var);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return null;
    }

    private Codefender.Context buildContextFromEnv() {
        try {
            return Codefender.Context.valueOf(envValue(CODEFENDER_CONTEXT));
        } catch (Exception e) {
            return null;
        }
    }

    private Lang buildLangFromEnvOrContent(File scanDir) {
        try {
            return Lang.valueOf(envValue(CODEFENDER_LANG));
        } catch (Exception e) {
            return Lang.getLangFromDir(scanDir);
        }
    }

    private boolean buildParseOnlyFromEnv() {
        String parseOnlyStr = envValue(CODEFENDER_PARSEONLY);
        return parseOnlyStr != null && parseOnlyStr.equalsIgnoreCase("TRUE");
    }

    public String getScanDirPath() {
        return scanDirPath;
    }

    public File getScanDir() {
        return scanDir;
    }

    public String getBuildScript() {
        return buildScript;
    }

    public Lang getLang() {
        return lang;
    }

    public Codefender.Context getContext() {
        return context;
    }

    public String getTool() {
        return tool;
    }

    public GitCredential getGitCredential() {
        return gitCredential;
    }

    public void setGitCredential(GitCredential gitCredential) {
        this.gitCredential = gitCredential;
    }

    public Boolean isParseOnly() {
        return parseOnly;
    }

    public GitRepo getGitRepo() {
        return gitRepo;
    }

    public void setGitRepo(GitRepo gitRepo) {
        this.gitRepo = gitRepo;
    }

    void init() {
        if (gitCredential == null) {
            gitCredential = buildGitCredentialFromEnv();
        }
        if (gitRepo == null) {
            gitRepo = buildGitRepoFromEnv();
        }
        if (project == null) {
            project = envValue(CODEFENDER_PROJECT);
            if (project == null || project.isEmpty()) {
                project = "Codefend_" + new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss_SSS").format(new Date().getTime());
            }
        }
        if (scanDirPath == null) {
            scanDirPath = buildScanDirPathFromEnvOrCurrentDir();
        }
        if (scanDirPath != null) {
            scanDir = new File(scanDirPath);
        } else {
            scanDir = new File(System.getProperty("user.dir"));
        }
        if (lang == null) {
            lang = buildLangFromEnvOrContent(scanDir);
        }
        if (context == null) {
            context = buildContextFromEnv();
        }
        if (tool == null) {
            tool = envValue(CODEFENDER_TOOL);
        }
        if (buildScript == null) {
            buildScript = envValue(CODEFENDER_BUILDSCRIPT);
        }
        if (parseOnly == null) {
            parseOnly = buildParseOnlyFromEnv();
        }
    }

    String getProject() {
        return project;
    }

    private String buildScanDirPathFromEnvOrCurrentDir() {
        String scanDirPath = envValue(CODEFENDER_DIR);
        String currentPath = System.getProperty("user.dir");
        if (scanDirPath != null && !scanDirPath.startsWith("/")) {
            File scanDir = new File(scanDirPath);
            if (scanDir.exists() && scanDir.isDirectory() && scanDir.getAbsolutePath().startsWith(currentPath)) {
                return scanDirPath;
            }
        }
        return null;
    }

    private synchronized GitCredential buildGitCredentialFromEnv() {
        if (gitCredential == null) {
            String gitUsername = envValue(CODEFENDER_GIT_USERNAME);
            String gitAccessToken = envValue(CODEFENDER_GIT_TOKEN);
            String sshPrivateKeyFilePath = envValue(CODEFENDER_GIT_SSHKEY);
            if (sshPrivateKeyFilePath != null) {
                File sshPrivateKeyFile = new File(sshPrivateKeyFilePath);
                if (sshPrivateKeyFile.exists()) {
                    gitCredential = new GitCredential(sshPrivateKeyFile);
                }
            }
            if (gitCredential == null && gitAccessToken != null) {
                gitCredential = new GitCredential(gitUsername, gitAccessToken);
            }
        }
        return gitCredential;
    }
}
