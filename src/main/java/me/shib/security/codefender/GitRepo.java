package me.shib.security.codefender;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Objects;

public class GitRepo {

    private transient String repoSlug;
    private transient String gitRepoWebURL;
    private String gitRepoHttpUri;
    private String gitRepoSshUri;
    private String gitRepoBranch;
    private String gitRepoCommitHash;

    GitRepo(String gitUri, String gitRepoBranch, String gitRepoCommitHash) {
        init(gitUri, gitRepoBranch, gitRepoCommitHash);
    }

    GitRepo() throws CodefenderException {
        File gitDir = new File(".git");
        if (!gitDir.exists() || !gitDir.isDirectory()) {
            throw new CodefenderException("Not a Git Repository");
        }
        String gitUri = getGitUrlFromLocalRepo();
        if (gitUri == null) {
            throw new CodefenderException("Not a Git Repository");
        }
        String gitBranch = getGitBranchFromLocalRepo();
        String gitCommit = getGitCommitFromLocalRepo();
        init(gitUri, gitBranch, gitCommit);
    }

    private static String runGitCommand(String gitCommand) throws CodefenderException {
        CommandRunner runner = new CommandRunner(gitCommand, "Git");
        runner.suppressConsoleLog();
        try {
            runner.execute();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return null;
        }
        String response = runner.getResult();
        if (response.contains("command not found") || response.contains("is currently not installed")) {
            throw new CodefenderException("Git was not found in local environment before proceeding");
        }
        return response;
    }

    private static String getGitUrlFromLocalRepo() throws CodefenderException {
        String response = runGitCommand("git config --get remote.origin.url");
        if (response != null) {
            return response.trim();
        }
        return null;
    }

    private static String getGitBranchFromLocalRepo() throws CodefenderException {
        String response = runGitCommand("git branch");
        try {
            if (response != null) {
                return response.split("\\s+")[1];
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String getGitCommitFromLocalRepo() throws CodefenderException {
        String commit = runGitCommand("git show --format=%H --no-patch");
        if (commit == null || commit.isEmpty()) {
            return null;
        }
        return commit.trim();
    }

    private static GitRepo getFromLocal() {
        try {
            return new GitRepo();
        } catch (CodefenderException e) {
            return null;
        }
    }

    private void init(String gitUri, String gitRepoBranch, String gitRepoCommitHash) {
        String url = cleanRepoUrl(gitUri);
        String[] urlSplit = url.split("/");
        String host = urlSplit[0];
        String repoName = urlSplit[urlSplit.length - 1];
        String owner = url.replaceFirst(host + "/", "");
        owner = removeEndingSequence(owner, "/" + repoName);
        this.gitRepoWebURL = getWebURL(host, owner, repoName);
        this.gitRepoHttpUri = getHttpUri(host, owner, repoName);
        this.gitRepoSshUri = getSSHUri(host, owner, repoName);
        this.gitRepoBranch = gitRepoBranch;
        this.gitRepoCommitHash = gitRepoCommitHash;
    }

    private String getWebURL(String host, String owner, String repoName) {
        return "https://" + host + "/" + owner + "/" + repoName;
    }

    private String getHttpUri(String host, String owner, String repoName) {
        return "https://" + host + "/" + owner + "/" + repoName + ".git";
    }

    private String getSSHUri(String host, String owner, String repoName) {
        return "git@" + host + ":" + owner + "/" + repoName + ".git";
    }

    private String removeEndingSequence(String source, String seq) {
        if (source.endsWith(seq)) {
            int start = source.lastIndexOf(seq);
            return source.substring(0, start) +
                    source.substring(start + seq.length());
        }
        return source;
    }

    private String cleanRepoUrl(String url) {
        if (url.contains("//")) {
            String[] split = url.split("//");
            url = split[split.length - 1];
        }
        if (url.contains("@")) {
            String[] split = url.split("@");
            url = split[split.length - 1];
        }
        url = removeEndingSequence(url, ".git");
        url = removeEndingSequence(url, "/");
        return url.replaceFirst(":", "/");
    }

    public String getRepoSlug() {
        if (repoSlug != null) {
            String url;
            if (gitRepoSshUri != null) {
                url = gitRepoSshUri;
            } else {
                url = gitRepoHttpUri;
            }
            String[] urlSplit = url.split("/");
            String host = urlSplit[0];
            String repoName = urlSplit[urlSplit.length - 1];
            String owner = url.replaceFirst(host + "/", "");
            owner = removeEndingSequence(owner, "/" + repoName);
            repoSlug = owner + "/" + repoName;
        }
        return repoSlug;
    }

    public synchronized void cloneRepo(GitCredential credential) throws CodefenderException {
        File currentDir = new File(System.getProperty("user.dir"));
        if (currentDir.list() != null) {
            if (Objects.requireNonNull(currentDir.list()).length > 0) {
                throw new CodefenderException("Not an empty directory");
            }
        }
        if (getFromLocal() != null) {
            throw new CodefenderException("A repository already exists");
        }
        StringBuilder cloneCommand = new StringBuilder();
        cloneCommand.append("git clone ");
        if (this.gitRepoBranch != null && !this.gitRepoBranch.isEmpty()) {
            cloneCommand.append("--branch ").append(this.gitRepoBranch).append(" ");
        }
        cloneCommand.append("--depth 1 ");
        if (this.gitRepoSshUri != null || this.gitRepoHttpUri != null) {
            String cloneUri;
            if (credential.getSshPrivateKeyFile() != null) {
                cloneUri = this.gitRepoSshUri;
                File sshPrivateKeyFile = new File(System.getProperty("user.home") + File.separator +
                        ".ssh" + File.separator + "id_rsa");
                try {
                    Files.copy(sshPrivateKeyFile.toPath(), sshPrivateKeyFile.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    throw new CodefenderException(e);
                }
                cloneCommand.append(this.gitRepoSshUri);
            } else {
                cloneUri = this.gitRepoHttpUri;
                if (credential.getGitUsername() != null && credential.getGitAccessToken() != null) {
                    String[] splitUrl = this.gitRepoHttpUri.split("//");
                    cloneCommand.append(splitUrl[0]).append("//").append(credential.getGitUsername())
                            .append(":").append(credential.getGitAccessToken()).append("@").append(splitUrl[1]);
                } else {
                    cloneCommand.append(this.gitRepoHttpUri);
                }
            }
            cloneCommand.append(" .");
            System.out.println("Pulling Repository: " + cloneUri);
            runGitCommand(cloneCommand.toString());
        } else {
            throw new CodefenderException("No git repository was specified");
        }
        GitRepo localRepo = getFromLocal();
        if (localRepo == null) {
            throw new CodefenderException("Failed to clone the repo");
        }
        if (this.gitRepoBranch != null && !this.gitRepoBranch.isEmpty()) {
            GitRepo local = GitRepo.getFromLocal();
            if (local == null || !local.gitRepoBranch.equalsIgnoreCase(this.gitRepoBranch)) {
                throw new CodefenderException("Something went wrong. Please validate the branch name");
            }
        }
        if (this.gitRepoCommitHash != null && !this.gitRepoCommitHash.isEmpty()) {
            System.out.println("Checking out commit: " + gitRepoCommitHash);
            runGitCommand("git checkout " + this.gitRepoCommitHash);
            GitRepo local = GitRepo.getFromLocal();
            if (local == null || !local.gitRepoCommitHash.equalsIgnoreCase(this.gitRepoCommitHash)) {
                throw new CodefenderException("Something went wrong. Please validate the branch name");
            }
        }
    }

    public String getGitRepoWebURL() {
        return gitRepoWebURL;
    }

    public String getGitRepoHttpUri() {
        return gitRepoHttpUri;
    }

    public String getGitRepoSshUri() {
        return gitRepoSshUri;
    }

    public String getGitRepoBranch() {
        return gitRepoBranch;
    }

    public String getGitRepoCommitHash() {
        return gitRepoCommitHash;
    }

    @Override
    public String toString() {
        return getRepoSlug();
    }
}
