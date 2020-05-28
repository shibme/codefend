package me.shib.security.codeinspect;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class CodeInspectConfig {

    private static final transient String CODEINSPECT_PROJECT = "CODEINSPECT_PROJECT";
    private static final transient String CODEINSPECT_DIR = "CODEINSPECT_DIR";
    private static final transient String CODEINSPECT_CONTEXT = "CODEINSPECT_CONTEXT";
    private static final transient String CODEINSPECT_LANG = "CODEINSPECT_LANG";
    private static final transient String CODEINSPECT_TOOL = "CODEINSPECT_TOOL";
    private static final transient String CODEINSPECT_BUILDSCRIPT = "CODEINSPECT_BUILDSCRIPT";
    private static final transient String CODEINSPECT_GIT_REPO = "CODEINSPECT_GIT_REPO";
    private static final transient String CODEINSPECT_GIT_BRANCH = "CODEINSPECT_GIT_BRANCH";
    private static final transient String CODEINSPECT_GIT_COMMIT = "CODEINSPECT_GIT_COMMIT";
    private static final transient String CODEINSPECT_GIT_USERNAME = "CODEINSPECT_GIT_USERNAME";
    private static final transient String CODEINSPECT_GIT_TOKEN = "CODEINSPECT_GIT_TOKEN";
    private static final transient String CODEINSPECT_GIT_SSHKEY = "CODEINSPECT_GIT_SSHKEY";

    private static transient CodeInspectConfig config;

    private transient File scanDir;
    private transient GitRepo gitRepo;

    private String project;
    private String scanDirPath;
    private String buildScript;
    private Lang lang;
    private CodeInspect.Context context;
    private String tool;
    private GitCredential gitCredential;

    public CodeInspectConfig(String project, String scanDirPath, String buildScript, Lang lang,
                             CodeInspect.Context context, String tool, GitRepo gitRepo, GitCredential gitCredential) {
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

    private CodeInspectConfig() {
        init();
    }

    static synchronized CodeInspectConfig getInstance() {
        if (config == null) {
            config = new CodeInspectConfig();
        }
        return config;
    }

    private synchronized GitRepo buildGitRepoFromEnv() {
        String gitUri = envValue(CODEINSPECT_GIT_REPO);
        if (gitUri == null || gitUri.isEmpty()) {
            return null;
        }
        String gitBranch = envValue(CODEINSPECT_GIT_BRANCH);
        String gitCommit = envValue(CODEINSPECT_GIT_COMMIT);
        return new GitRepo(gitUri, gitBranch, gitCommit);
    }

    private String envValue(String var) {
        String value = System.getenv(var);
        if (value != null && !value.isEmpty()) {
            return value;
        }
        return null;
    }

    private CodeInspect.Context buildContextFromEnv() {
        try {
            return CodeInspect.Context.valueOf(envValue(CODEINSPECT_CONTEXT));
        } catch (Exception e) {
            return null;
        }
    }

    private Lang buildLangFromEnvOrContent(File scanDir) {
        try {
            return Lang.valueOf(envValue(CODEINSPECT_LANG));
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

    public CodeInspect.Context getContext() {
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
            project = envValue(CODEINSPECT_PROJECT);
            if (project == null || project.isEmpty()) {
                if (gitRepo != null) {
                    project = gitRepo.getGitRepoSlug();
                } else {
                    project = "CodeInspect_" + new SimpleDateFormat("yyyy_MM_dd_HH_mm_ss_SSS").format(new Date().getTime());
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
            tool = envValue(CODEINSPECT_TOOL);
        }
        if (buildScript == null) {
            buildScript = envValue(CODEINSPECT_BUILDSCRIPT);
        }
    }

    public String getProject() {
        return project;
    }

    private String buildScanDirPathFromEnvOrCurrentDir() {
        String scanDirPath = envValue(CODEINSPECT_DIR);
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
        String gitUsername = envValue(CODEINSPECT_GIT_USERNAME);
        String gitAccessToken = envValue(CODEINSPECT_GIT_TOKEN);
        String sshPrivateKeyFilePath = envValue(CODEINSPECT_GIT_SSHKEY);
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
