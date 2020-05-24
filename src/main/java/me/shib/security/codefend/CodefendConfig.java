package me.shib.security.codefend;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class CodefendConfig {

    private static final transient String CODEFEND_PROJECT = "CODEFEND_PROJECT";
    private static final transient String CODEFEND_DIR = "CODEFEND_DIR";
    private static final transient String CODEFEND_CONTEXT = "CODEFEND_CONTEXT";
    private static final transient String CODEFEND_LANG = "CODEFEND_LANG";
    private static final transient String CODEFEND_TOOL = "CODEFEND_TOOL";
    private static final transient String CODEFEND_BUILDSCRIPT = "CODEFEND_BUILDSCRIPT";
    private static final transient String CODEFEND_GIT_REPO = "CODEFEND_GIT_REPO";
    private static final transient String CODEFEND_GIT_BRANCH = "CODEFEND_GIT_BRANCH";
    private static final transient String CODEFEND_GIT_COMMIT = "CODEFEND_GIT_COMMIT";
    private static final transient String CODEFEND_GIT_USERNAME = "CODEFEND_GIT_USERNAME";
    private static final transient String CODEFEND_GIT_TOKEN = "CODEFEND_GIT_TOKEN";
    private static final transient String CODEFEND_GIT_SSHKEY = "CODEFEND_GIT_SSHKEY";

    private static transient CodefendConfig config;

    private transient File scanDir;
    private transient GitRepo gitRepo;

    private String project;
    private String scanDirPath;
    private String buildScript;
    private Lang lang;
    private Codefend.Context context;
    private String tool;
    private GitCredential gitCredential;

    public CodefendConfig(String project, String scanDirPath, String buildScript, Lang lang,
                          Codefend.Context context, String tool, GitRepo gitRepo, GitCredential gitCredential) {
        this.project = project;
        this.scanDirPath = scanDirPath;
        this.buildScript = buildScript;
        this.lang = lang;
        this.context = context;
        this.tool = tool;
        this.gitRepo = gitRepo;
        this.gitCredential = gitCredential;
        init();
    }

    private CodefendConfig() {
        init();
    }

    static synchronized CodefendConfig getInstance() {
        if (config == null) {
            config = new CodefendConfig();
        }
        return config;
    }

    private synchronized GitRepo buildGitRepoFromEnv() {
        String gitUri = envValue(CODEFEND_GIT_REPO);
        if (gitUri == null || gitUri.isEmpty()) {
            return null;
        }
        String gitBranch = envValue(CODEFEND_GIT_BRANCH);
        String gitCommit = envValue(CODEFEND_GIT_COMMIT);
        return new GitRepo(gitUri, gitBranch, gitCommit);
    }

    private String envValue(String var) {
        String value = System.getenv(var);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return null;
    }

    private Codefend.Context buildContextFromEnv() {
        try {
            return Codefend.Context.valueOf(envValue(CODEFEND_CONTEXT));
        } catch (Exception e) {
            return null;
        }
    }

    private Lang buildLangFromEnvOrContent(File scanDir) {
        try {
            return Lang.valueOf(envValue(CODEFEND_LANG));
        } catch (Exception e) {
            return Lang.getLangFromDir(scanDir);
        }
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

    public Codefend.Context getContext() {
        return context;
    }

    public String getTool() {
        return tool;
    }

    public GitCredential getGitCredential() {
        return gitCredential;
    }

    public GitRepo getGitRepo() {
        return gitRepo;
    }

    void init() {
        if (gitCredential == null) {
            gitCredential = buildGitCredentialFromEnv();
        }
        if (gitRepo == null) {
            gitRepo = buildGitRepoFromEnv();
        }
        if (gitRepo != null) {
            gitRepo.cloneRepo(gitCredential);
        } else {
            gitRepo = new GitRepo();
        }
        if (project == null) {
            project = envValue(CODEFEND_PROJECT);
            if (project == null || project.isEmpty()) {
                if (gitRepo != null) {
                    project = gitRepo.getGitRepoSlug();
                } else {
                    project = "Codefend_" + new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss_SSS").format(new Date().getTime());
                }
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
            tool = envValue(CODEFEND_TOOL);
        }
        if (buildScript == null) {
            buildScript = envValue(CODEFEND_BUILDSCRIPT);
        }
    }

    String getProject() {
        return project;
    }

    private String buildScanDirPathFromEnvOrCurrentDir() {
        String scanDirPath = envValue(CODEFEND_DIR);
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
        String gitUsername = envValue(CODEFEND_GIT_USERNAME);
        String gitAccessToken = envValue(CODEFEND_GIT_TOKEN);
        String sshPrivateKeyFilePath = envValue(CODEFEND_GIT_SSHKEY);
        if (sshPrivateKeyFilePath != null) {
            File sshPrivateKeyFile = new File(sshPrivateKeyFilePath);
            if (sshPrivateKeyFile.exists()) {
                return new GitCredential(sshPrivateKeyFile);
            }
        }
        if (gitAccessToken != null) {
            return new GitCredential(gitUsername, gitAccessToken);
        }
        return null;
    }
}
