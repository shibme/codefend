package me.shib.security.codeinspect;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class CodeInspectConfig {

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
        String gitUri = CodeInspectEnv.CODEINSPECT_GIT_REPO.getAsString();
        if (gitUri == null) {
            return null;
        }
        return new GitRepo(gitUri, CodeInspectEnv.CODEINSPECT_GIT_BRANCH.getAsString(),
                CodeInspectEnv.CODEINSPECT_GIT_COMMIT.getAsString());
    }

    private CodeInspect.Context buildContextFromEnv() {
        try {
            return CodeInspect.Context.valueOf(CodeInspectEnv.CODEINSPECT_CONTEXT.getAsString());
        } catch (Exception e) {
            return null;
        }
    }

    private Lang buildLangFromEnvOrContent(File scanDir) {
        try {
            return Lang.valueOf(CodeInspectEnv.CODEINSPECT_LANG.getAsString());
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
            project = CodeInspectEnv.CODEINSPECT_PROJECT.getAsString();
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
            tool = CodeInspectEnv.CODEINSPECT_TOOL.getAsString();
        }
        if (buildScript == null) {
            buildScript = CodeInspectEnv.CODEINSPECT_BUILDSCRIPT.getAsString();
        }
    }

    public String getProject() {
        return project;
    }

    private String buildScanDirPathFromEnvOrCurrentDir() {
        String scanDirPath = CodeInspectEnv.CODEINSPECT_DIR.getAsString();
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
        String gitUsername = CodeInspectEnv.CODEINSPECT_GIT_USERNAME.getAsString();
        String gitAccessToken = CodeInspectEnv.CODEINSPECT_GIT_TOKEN.getAsString();
        String sshPrivateKeyFilePath = CodeInspectEnv.CODEINSPECT_GIT_SSHKEY.getAsString();
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
