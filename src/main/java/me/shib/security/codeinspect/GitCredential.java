package me.shib.security.codeinspect;

import java.io.File;

public class GitCredential {

    private String gitUsername;
    private String gitAccessToken;
    private File sshPrivateKeyFile;

    public GitCredential(String gitUsername, String gitAccessToken) {
        this.gitUsername = gitUsername;
        if (this.gitUsername == null || this.gitUsername.isEmpty()) {
            this.gitUsername = "git";
        }
        this.gitAccessToken = gitAccessToken;
    }

    public GitCredential(File sshPrivateKeyFile) {
        this.sshPrivateKeyFile = sshPrivateKeyFile;
    }

    String getGitUsername() {
        return gitUsername;
    }

    String getGitAccessToken() {
        return gitAccessToken;
    }

    File getSshPrivateKeyFile() {
        return sshPrivateKeyFile;
    }
}
