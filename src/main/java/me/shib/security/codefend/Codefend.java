package me.shib.security.codefend;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.shib.security.codefend.scanners.java.dependencycheck.DependencyCheck;
import me.shib.security.codefend.scanners.javascript.retirejs.RetirejsScanner;
import me.shib.security.codefend.scanners.ruby.brakeman.BrakemanScanner;
import me.shib.security.codefend.scanners.ruby.bundleraudit.BundlerAudit;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public abstract class Codefend {

    private static final transient Gson gson = new GsonBuilder().setPrettyPrinting()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss").create();
    private static final transient Set<Codefend> codefends = new HashSet<>();

    private final transient CodefendConfig config;
    private final transient CodefendResult result;

    public Codefend(CodefendConfig config) {
        this.config = config;
        this.result = new CodefendResult(config.getProject(), getLang(),
                getContext(), getTool(), config.getScanDirPath());
    }

    static synchronized void addScanner(Codefend codefend) {
        codefends.add(codefend);
    }

    private static synchronized List<Codefend> getCodefends(CodefendConfig config) {
        List<Codefend> qualifiedClasses = new ArrayList<>();
        System.out.println("Attempting to run for Language: " + config.getLang());
        if (config.getLang() != null) {
            for (Codefend codefend : codefends) {
                try {
                    if (codefend.getLang() != null && codefend.getLang() == config.getLang()) {
                        if (config.getTool() == null || config.getTool().isEmpty() ||
                                config.getTool().equalsIgnoreCase(codefend.getTool())) {
                            qualifiedClasses.add(codefend);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return qualifiedClasses;
    }

    private static synchronized void prepareScanners(CodefendConfig config) {
        Codefend.addScanner(new BrakemanScanner(config));
        Codefend.addScanner(new BundlerAudit(config));
        Codefend.addScanner(new RetirejsScanner(config));
        Codefend.addScanner(new DependencyCheck(config));
    }

    public static synchronized List<Codefend> getScanners(CodefendConfig config) throws CodefendException {
        prepareScanners(config);
        List<Codefend> scanners = Codefend.getCodefends(config);
        if (scanners.size() > 0) {
            try {
                buildProject(config.getBuildScript(), config.getScanDir());
                for (Codefend codefend : scanners) {
                    codefend.result.setProject(config.getProject());
                }
            } catch (IOException | InterruptedException e) {
                throw new CodefendException(e);
            }
        } else {
            System.out.println("No scanners available to scan this code.");
        }
        return scanners;
    }

    private static synchronized void buildProject(String buildScript, File scanDir) throws IOException, InterruptedException, CodefendException {
        if (buildScript != null) {
            System.out.println("Running: " + buildScript);
            CommandRunner commandRunner = new CommandRunner(buildScript, scanDir, "Building Project");
            if (commandRunner.execute() != 0) {
                throw new CodefendException("Build Failed!");
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

    protected CodefendFinding newVulnerability(String title, CodefendPriority priority) {
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

    public List<CodefendFinding> getFindings() {
        return result.getVulnerabilities();
    }

    public abstract Lang getLang();

    public abstract String getTool();

    public abstract Context getContext();

    protected abstract void scan() throws Exception;

    public enum Context {
        SAST("Codefend-SAST"),
        SCA("Codefend-SCA");

        private final String label;

        Context(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }
    }

}
