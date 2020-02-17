package me.shib.security.codefender;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.shib.security.codefender.scanners.java.dependencycheck.DependencyCheck;
import me.shib.security.codefender.scanners.javascript.retirejs.RetirejsScanner;
import me.shib.security.codefender.scanners.ruby.brakeman.BrakemanScanner;
import me.shib.security.codefender.scanners.ruby.bundleraudit.BundlerAudit;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public abstract class Codefender {

    private static final transient Gson gson = new GsonBuilder().setPrettyPrinting()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss").create();
    private static final transient Set<Codefender> codefenders = new HashSet<>();

    private transient CodefenderConfig config;
    private transient CodefenderResult result;

    public Codefender(CodefenderConfig config) {
        this.config = config;
        this.result = new CodefenderResult(config.getProject(), getLang(),
                getContext(), getTool(), config.getScanDirPath());
    }

    static synchronized void addScanner(Codefender codefender) {
        codefenders.add(codefender);
    }

    private static synchronized List<Codefender> getCodefenders(CodefenderConfig config) {
        List<Codefender> qualifiedClasses = new ArrayList<>();
        System.out.println("Attempting to run for Language: " + config.getLang());
        if (config.getLang() != null) {
            for (Codefender codefender : codefenders) {
                try {
                    if (codefender.getLang() != null && codefender.getLang() == config.getLang()) {
                        if (config.getTool() == null || config.getTool().isEmpty() ||
                                config.getTool().equalsIgnoreCase(codefender.getTool())) {
                            qualifiedClasses.add(codefender);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return qualifiedClasses;
    }

    private static synchronized void prepareScan(CodefenderConfig config) {
        Codefender.addScanner(new BrakemanScanner(config));
        Codefender.addScanner(new BundlerAudit(config));
        Codefender.addScanner(new RetirejsScanner(config));
        Codefender.addScanner(new DependencyCheck(config));
        GitRepo gitRepo = config.getGitRepo();
        if (gitRepo != null) {
            gitRepo.cloneRepo(config.getGitCredential());
        } else {
            config.setGitRepo(new GitRepo());
        }
    }

    public static synchronized List<Codefender> getScanners(CodefenderConfig config) throws CodefenderException {
        if (config == null) {
            config = CodefenderConfig.getInstance();
        }
        prepareScan(config);
        List<Codefender> scanners = Codefender.getCodefenders(config);
        if (scanners.size() > 0) {
            try {
                buildProject(config.getBuildScript(), config.getScanDir());
                for (Codefender codefender : scanners) {
                    codefender.result.setProject(config.getProject());
                }
            } catch (IOException | InterruptedException e) {
                throw new CodefenderException(e);
            }
        } else {
            System.out.println("No scanners available to scan this code.");
        }
        return scanners;
    }

    private static synchronized void buildProject(String buildScript, File scanDir) throws IOException, InterruptedException, CodefenderException {
        if (buildScript != null) {
            System.out.println("Running: " + buildScript);
            CommandRunner commandRunner = new CommandRunner(buildScript, scanDir, "Building Project");
            if (commandRunner.execute() != 0) {
                throw new CodefenderException("Build Failed!");
            }
        }
    }

    protected static void writeToFile(String content, File file) throws FileNotFoundException {
        PrintWriter pw = new PrintWriter(file);
        pw.append(content);
        pw.close();
    }

    protected String getHash(File file, int lineNo, String type, String[] args) throws IOException {
        return getHash(file, lineNo, lineNo, type, args);
    }

    protected String getHash(File file, int lineNo, String type) throws IOException {
        return getHash(file, lineNo, lineNo, type, null);
    }

    protected String getHash(File file, int startLineNo, int endLineNo, String type) throws IOException {
        return getHash(file, startLineNo, endLineNo, type, null);
    }

    protected String getHash(File file, int startLineNo, int endLineNo, String type, String[] args) throws IOException {
        class HashableContent {
            private String filePath;
            private String snippet;
            private String type;
            private String[] args;
        }
        List<String> lines = readLinesFromFile(file);
        if (startLineNo <= endLineNo && endLineNo <= lines.size() && startLineNo > 0) {
            StringBuilder snippet = new StringBuilder();
            snippet.append(lines.get(startLineNo - 1));
            for (int i = startLineNo; i < endLineNo; i++) {
                snippet.append("\n").append(lines.get(i));
            }
            HashableContent hashableContent = new HashableContent();
            hashableContent.type = type;
            hashableContent.filePath = file.getAbsolutePath().replaceFirst(config.getScanDir().getAbsolutePath(), "");
            hashableContent.snippet = snippet.toString();
            hashableContent.args = args;
            return DigestUtils.sha1Hex(gson.toJson(hashableContent));
        }
        return null;
    }

    protected CodefenderVulnerability newVulnerability(String title, int priority) {
        return result.newVulnerability(title, priority);
    }

    protected String runCommand(String command) throws IOException, InterruptedException {
        CommandRunner commandRunner = new CommandRunner(command, config.getScanDir(), getTool());
        commandRunner.execute();
        return commandRunner.getResult();
    }

    private List<String> readLinesFromFile(File file) throws IOException {
        List<String> lines = new ArrayList<>();
        if (file.exists() && !file.isDirectory()) {
            BufferedReader br = new BufferedReader(new FileReader(file));
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
            br.close();
        }
        return lines;
    }

    protected String readFromFile(File file) throws IOException {
        StringBuilder content = new StringBuilder();
        for (String line : readLinesFromFile(file)) {
            content.append(line).append("\n");
        }
        return content.toString();
    }

    public String getProject() {
        return result.getProject();
    }

    public String getScanner() {
        return result.getScanner();
    }

    public String getScanDirPath() {
        return result.getScanDirPath();
    }

    public List<CodefenderVulnerability> getVulnerabilities() {
        return result.getVulnerabilities();
    }

    protected boolean isParserOnly() {
        return config.isParseOnly();
    }

    public abstract Lang getLang();

    public abstract String getTool();

    public abstract Context getContext();

    public abstract void scan() throws Exception;

    public enum Context {
        SAST, SCA
    }

}
