package me.shib.security.codefender;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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

    public static void addScanner(Codefender codefender) {
        codefenders.add(codefender);
    }

    private static synchronized List<Codefender> getCodefends(CodefenderConfig config) {
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

    static synchronized List<CodefenderResult> execute(CodefenderConfig config) throws CodefenderException {
        if (config == null) {
            config = CodefenderConfig.getInstance();
        }
        List<Codefender> codefenders = Codefender.getCodefends(config);
        List<CodefenderResult> results = new ArrayList<>();
        if (codefenders.size() > 0) {
            try {
                buildProject(config.getBuildScript(), config.getScanDir());
                for (Codefender codefender : codefenders) {
                    try {
                        codefender.getResult().setProject(config.getProject());
                        System.out.println("Now running scanner: " + codefender.getTool());
                        codefender.scan();
                        results.add(codefender.getResult());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            } catch (IOException | InterruptedException e) {
                throw new CodefenderException(e);
            }
        } else {
            System.out.println("No scanners available to scan this code.");
        }
        return results;
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

    private CodefenderResult getResult() {
        return result;
    }

    protected boolean isParserOnly() {
        return config.isParseOnly();
    }

    protected abstract Lang getLang();

    public abstract String getTool();

    public abstract Context getContext();

    public abstract void scan() throws Exception;

    public enum Context {
        SAST, SCA
    }

}
