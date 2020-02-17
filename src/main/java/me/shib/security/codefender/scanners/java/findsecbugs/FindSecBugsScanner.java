package me.shib.security.codefender.scanners.java.findsecbugs;

import me.shib.security.codefender.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FindSecBugsScanner extends Codefender {

    private static transient final Lang scannerLang = Lang.Java;
    private static transient final String tool = "FindSecBugs";
    private static transient final String thresholdLevel = "FINDSECBUGS_CONFIDENCE_LEVEL";
    private static transient final int java_Maven = 1;
    private static transient final int java_Gradle = 2;
    private List<String> modulePaths = new ArrayList<>();

    private CodefenderConfig config;

    public FindSecBugsScanner(CodefenderConfig config) {
        super(config);
    }

    protected String readFromFile(File file) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while ((line = br.readLine()) != null) {
            contentBuilder.append(line).append("\n");
        }
        br.close();
        return contentBuilder.toString();
    }

    @Override
    public Lang getLang() {
        return scannerLang;
    }

    private void modifyXMLsForEnvironment(File directory, int buildType) throws IOException, SAXException, ParserConfigurationException {
        String fileName = "";
        if (buildType == java_Maven) {
            fileName = "pom.xml";
            List<String> modules = getModulePaths(directory);
            if (!modules.isEmpty()) {
                for (String module : modules) {
                    modifyXMLsForEnvironment(new File(module), java_Maven);
                }
            }
        } else
            fileName = "build.gradle";

        //Used to append spotbugs maven plugin to pom.xml file
        File buildFile = new File(directory + File.separator + fileName);

        System.out.println(buildFile.getAbsolutePath());
        if (buildFile.exists()) {
            this.modulePaths.add(directory.getAbsolutePath());
            //The corresponding two files is used to tell spotbugs to report only security bugs and not others!
            File excludeFile = new File(directory + File.separator + "spotbugs-security-exclude.xml");
            String excludeFileContents = "<FindBugsFilter>\n" +
                    "</FindBugsFilter>";

            if (!excludeFile.exists())
                writeToFile(excludeFileContents, excludeFile);
            else
                System.out.println("Exclude file already present!");

            File includeFile = new File(directory + File.separator + "spotbugs-security-include.xml");
            System.out.println(includeFile.getAbsolutePath());
            String includeFileContents = "<FindBugsFilter>\n" +
                    "    <Match>\n" +
                    "        <Bug category=\"SECURITY\"/>\n" +
                    "    </Match>\n" +
                    "</FindBugsFilter>";

            if (!includeFile.exists())
                writeToFile(includeFileContents, includeFile);
            else
                System.out.println("Include file already present!");

            List<String> lines = Files.readAllLines(buildFile.toPath(), StandardCharsets.UTF_8);

            String confidenceLevel = System.getenv(thresholdLevel);
            if (confidenceLevel == null || confidenceLevel.equals(""))
                confidenceLevel = "Low";
            else
                confidenceLevel = confidenceLevel.substring(0, 1).toUpperCase() + confidenceLevel.substring(1).toLowerCase();

            if (fileName == "pom.xml") {

                String pluginStr = "<plugin>\n" +
                        "            <groupId>com.github.spotbugs</groupId>\n" +
                        "            <artifactId>spotbugs-maven-plugin</artifactId>\n" +
                        "            <version>3.1.12</version>\n" +
                        "            <configuration>\n" +
                        "                <effort>Max</effort>\n" +
                        "                <threshold>" + confidenceLevel + "</threshold>\n" +
                        "                <failOnError>true</failOnError>\n" +
                        "                <maxHeap>2048</maxHeap>\n" +
                        "                <includeFilterFile>spotbugs-security-include.xml</includeFilterFile>\n" +
                        "                <excludeFilterFile>spotbugs-security-exclude.xml</excludeFilterFile>\n" +
                        "                <plugins>\n" +
                        "                    <plugin>\n" +
                        "                        <groupId>com.h3xstream.findsecbugs</groupId>\n" +
                        "                        <artifactId>findsecbugs-plugin</artifactId>\n" +
                        "                        <version>LATEST</version> <!-- Auto-update to the latest stable -->\n" +
                        "                    </plugin>\n" +
                        "                </plugins>\n" +
                        "            </configuration>\n" +
                        "        </plugin>";

                boolean buildNode = false, pluginsNode = false;
                DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

                Document doc = dBuilder.parse(buildFile);
                doc.getDocumentElement().normalize();

                Element nElement = doc.getDocumentElement();
                Node childNode = nElement.getFirstChild();

                while (childNode.getNextSibling() != null) {
                    childNode = childNode.getNextSibling();
                    if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element childElement = (Element) childNode;
                        if (childElement.getNodeName().equals("build")) {
                            buildNode = true;
                            Node nChildNode = childNode.getFirstChild();
                            while (nChildNode.getNextSibling() != null) {
                                nChildNode = nChildNode.getNextSibling();
                                if (nChildNode.getNodeType() == Node.ELEMENT_NODE) {
                                    if (nChildNode.getNodeName().equals("plugins"))
                                        pluginsNode = true;
                                }
                            }

                        }
                    }
                }

                if (buildNode && pluginsNode) {
                    for (ListIterator<String> it = lines.listIterator(); it.hasNext(); ) {
                        String str = it.next();
                        if (str.trim().contains("<plugins>")) {
                            it.add(pluginStr);
                        }
                    }
                } else if (buildNode && !pluginsNode) {
                    String tempStr = pluginStr;
                    pluginStr = "<plugins>\n" +
                            tempStr +
                            "   </plugins>\n";

                    for (ListIterator<String> it = lines.listIterator(); it.hasNext(); ) {
                        String str = it.next();
                        if (str.trim().contains("<build>")) {
                            it.add(pluginStr);
                        }
                    }

                } else {
                    String tempStr = pluginStr;
                    pluginStr = "<build>\n" +
                            "   <plugins>\n" +
                            tempStr +
                            "   </plugins>\n" +
                            "</build>";

                    int position = 0;
                    for (String str : lines) {
                        if (str.trim().contains("</project>")) {
                            position = lines.indexOf(str);
                            break;
                        }
                    }
                    lines.add(position, pluginStr);
                }

                Files.write(Paths.get(directory + File.separator + "pom.xml"), lines, StandardCharsets.UTF_8);
            } else {
                int position = 0;

                String pluginStr = "\n\nallprojects {\n" +
                        "    \tapply plugin: 'findbugs'\n" +
                        "    dependencies {\n" +
                        "    \n" +
                        "    \tfindbugs 'com.google.code.findbugs:findbugs:3.0.1'\n" +
                        "    \tfindbugs configurations.findbugsPlugins.dependencies\n" +
                        "    \tfindbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.9.0'\n" +
                        "    }\n" +
                        "    \n" +
                        "    task findbugs(type: FindBugs) {\n" +
                        "\n" +
                        "      classes = fileTree(project.rootDir.absolutePath).include(\"**/*.class\");\n" +
                        "      source = fileTree(project.rootDir.absolutePath).include(\"**/*.java\");\n" +
                        "      classpath = files()\n" +
                        "      pluginClasspath = project.configurations.findbugsPlugins\n" +
                        "\n" +
                        "      findbugs {\n" +
                        "       toolVersion = \"3.1.12\"\n" +
                        "       sourceSets = [sourceSets.main]\n" +
                        "       maxHeapSize = '2048m'  \n" +
                        "       ignoreFailures = true\n" +
                        "       reportsDir = file(\"$project.buildDir\")\n" +
                        "       effort = \"max\"\n" +
                        "       reportLevel = \"" + confidenceLevel.toLowerCase() + "\"\n" +
                        "       includeFilter = file(\"$rootProject.projectDir/spotbugs-security-include.xml\")\n" +
                        "       excludeFilter = file(\"$rootProject.projectDir/spotbugs-security-exclude.xml\")\n" +
                        "      }\n" +
                        "\n" +
                        "      tasks.withType(FindBugs) {\n" +
                        "            reports {\n" +
                        "                    xml.enabled = true\n" +
                        "                    html.enabled = false\n" +
                        "            }\n" +
                        "        }\n" +
                        "    }\n" +
                        "  }";

                Files.write(Paths.get(config.getScanDirPath() + File.separator + fileName), pluginStr.getBytes(), StandardOpenOption.APPEND);
            }
        } else
            throw new FileNotFoundException(fileName + "not found!");
    }

    private List<String> getModulePaths(File directory) throws IOException {
        List<String> modulePaths = new ArrayList<>();
        File file = new File(directory + File.separator + "pom.xml");
        String contents = readFromFile(file);
        Pattern pattern = Pattern.compile("<module>(.*)</module>");
        Matcher matcher = pattern.matcher(contents);

        while (matcher.find()) {
            String module = matcher.group(1);
            String path = directory + File.separator + module;

            modulePaths.add(path);
        }

        return modulePaths;
    }

    private Integer getSeverity(int priority, int rank) {
        Integer[][] severityMatrix = {
                {1, 2, 2},
                {2, 2, 3},
                {3, 3, 4},
                {3, 4, 4}
        };

        int index1 = 0;
        if (rank >= 5 && rank <= 9)
            index1 = 1;
        else if (rank >= 10 && rank <= 14)
            index1 = 2;
        else if (rank >= 15 && rank <= 20)
            index1 = 3;
        int index2 = priority - 1;
        return severityMatrix[index1][index2];
    }

    private List<FindSecBugsWarning> getXMLValuesForBug(String modulePath) throws ParserConfigurationException, IOException, SAXException {
        File bugXML = new File(modulePath);
        List<FindSecBugsWarning> bugsList = new ArrayList<FindSecBugsWarning>();

        if (!bugXML.exists())
            return bugsList;

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

        Document doc = dBuilder.parse(bugXML);
        doc.getDocumentElement().normalize();

        NodeList nList = doc.getElementsByTagName("Project");

        Node nNode = nList.item(0);
        Element nElement = (Element) nNode;

        List<String> srcDirList = new ArrayList<String>();
        nList = nElement.getElementsByTagName("SrcDir");
        for (int temp = 0; temp < nList.getLength(); temp++)
            srcDirList.add(nList.item(temp).getTextContent());

        nList = doc.getElementsByTagName("BugInstance");
        for (int temp = 0; temp < nList.getLength(); temp++) {
            nNode = nList.item(temp);

            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) nNode;

                FindSecBugsWarning findBugs = new FindSecBugsWarning();

                if (nElement.hasAttribute("projectName"))
                    findBugs.setModuleName(nElement.getAttribute("projectName"));

                if (eElement.hasAttribute("type"))
                    findBugs.setBugType(eElement.getAttribute("type"));

                if (eElement.hasAttribute("instanceHash"))
                    findBugs.setInstanceHash(eElement.getAttribute("instanceHash"));
                else
                    findBugs.setInstanceHash("");

                if (eElement.hasAttribute("LongMessage"))
                    findBugs.setMessage(eElement.getElementsByTagName("LongMessage").item(0).getTextContent());

                NodeList nList1 = eElement.getElementsByTagName("SourceLine");
                Node nNode1 = nList1.item(2);
                Element eElement1 = (Element) nNode1;

                if (eElement1 == null)
                    continue;

                if (eElement1.hasAttribute("classname"))
                    findBugs.setClassName(eElement1.getAttribute("classname"));

                if (eElement1.hasAttribute("sourcepath")) {
                    if (!srcDirList.isEmpty() && srcDirList.size() != 1) {
                        String sourcePath = eElement1.getAttribute("sourcepath");
                        String[] srcDirArr = new String[srcDirList.size()];
                        srcDirList.toArray(srcDirArr);

                        for (int i = 0; i < srcDirArr.length; i++) {
                            if (srcDirArr[i].contains(sourcePath))
                                findBugs.setFilePath(srcDirArr[i]);
                        }
                    } else
                        findBugs.setFilePath(eElement1.getAttribute("sourcepath"));

                    if (findBugs.getFilePath() == null)
                        continue;
                }

                String lineStart = "", lineEnd = "";
                if (eElement1.hasAttribute("start"))
                    lineStart = eElement1.getAttribute("start");

                if (eElement1.hasAttribute("end"))
                    lineEnd = eElement1.getAttribute("end");

                findBugs.setLineNumber(lineStart + "-" + lineEnd);
                findBugs.setPriority(eElement.getAttribute("priority"));

                int priority = Integer.parseInt(findBugs.getPriority());
                int rank = Integer.parseInt(eElement.getAttribute("rank"));
                findBugs.setSeverity(getSeverity(priority, rank));

                if (findBugs.getInstanceHash().isEmpty()) {
                    File bugFile = new File(findBugs.getFilePath());
                    String instanceHash = getHash(bugFile, Integer.parseInt(lineStart), Integer.parseInt(lineEnd), findBugs.getBugType(), null);
                    findBugs.setInstanceHash(instanceHash);
                }
                bugsList.add(findBugs);
            }
        }
        return bugsList;
    }

    private void addKeys(CodefenderVulnerability vulnerability, FindSecBugsWarning warning) {
        vulnerability.addKey(warning.getFilePath());
        vulnerability.addKey(config.getGitRepo() + "-" + warning.getInstanceHash());
        vulnerability.addKey(warning.getBugType().replace(" ", "-"));
    }

    private void warningsToVulns(List<FindSecBugsWarning> warnings) {
        for (FindSecBugsWarning warning : warnings) {
            String title = "FindSecBugs (" + warning.getBugType() + ") found in " + warning.getFilePath() + config.getGitRepo();
            CodefenderVulnerability vulnerability = newVulnerability(title, warning.getSeverity());
            String message = "The following insecure code was found **[was found](" +
                    config.getGitRepo().getGitRepoWebURL() +
                    "/tree/" + config.getGitRepo().getGitRepoCommitHash() + ")";
            vulnerability.setField("Message", message);
            vulnerability.setField("Line", warning.getLineNumber());
            vulnerability.setField("Type", warning.getBugType());
            vulnerability.setField("Message", warning.getMessage());
            vulnerability.setField("Confidence", warning.getPriority());
            addKeys(vulnerability, warning);
            vulnerability.update();
        }
    }

    private void processFindSecBugsResult(int buildType) throws IOException, SAXException, ParserConfigurationException, InterruptedException {
        if (buildType == java_Maven) {
            for (String module : modulePaths) {
                module += File.separator + "target" + File.separator + "spotbugsXml.xml";
                warningsToVulns(getXMLValuesForBug(module));
            }
        } else if (buildType == java_Gradle) {
            String buildDirString = runCommand("gradle properties");
            Pattern pattern = Pattern.compile("buildDir: *(.*)");
            Matcher matcher = pattern.matcher(buildDirString);
            String buildDir = "";
            if (matcher.find())
                buildDir = matcher.group(1);
            warningsToVulns(getXMLValuesForBug(buildDir + "/findbugs.xml"));
        }
    }

    private void runFindSecBugs(int buildType) throws InterruptedException, SAXException, ParserConfigurationException, IOException {
        System.out.println("Running FindSecBugs!\n");

        if (buildType == java_Maven) {
            modifyXMLsForEnvironment(config.getScanDir(), java_Maven);
            String buildScript = config.getBuildScript();
            String command, extraArgument;
            if (buildScript == null)
                extraArgument = "";
            else {
                Pattern pattern = Pattern.compile("mvn clean install(.*)");
                Matcher matcher = pattern.matcher(buildScript);

                if (matcher.find()) {
                    extraArgument = matcher.group(1);
                } else {
                    extraArgument = "";
                }
            }
            command = "mvn spotbugs:spotbugs" + extraArgument;
            String spotBugsResponse = runCommand(command);
            if (!spotBugsResponse.contains("BUILD SUCCESS"))
                throw new CodefenderException("FindSecBugs failed!");
        } else if (buildType == java_Gradle) {
            modifyXMLsForEnvironment(config.getScanDir(), java_Gradle);

            String command = "gradle findbugs";
            String findBugsResponse = runCommand(command);

            if (!findBugsResponse.contains("BUILD SUCCESSFUL"))
                throw new CodefenderException("FindSecBugs failed!");

        }

    }

    @Override
    public String getTool() {
        return tool;
    }

    @Override
    public Context getContext() {
        return Context.SAST;
    }

    @Override
    public void scan() throws Exception {

        int buildType;
        if (new File(config.getScanDirPath() + File.separator + "pom.xml").exists())
            buildType = java_Maven;
        else
            buildType = java_Gradle;

        if (!isParserOnly()) {
            runFindSecBugs(buildType);
        }
        processFindSecBugsResult(buildType);
    }
}
