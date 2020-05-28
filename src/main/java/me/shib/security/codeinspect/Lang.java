package me.shib.security.codeinspect;

import java.io.File;
import java.util.*;

public enum Lang {

    Go(new String[]{"go"}), Java(new String[]{"java"}), JavaScript(new String[]{"js"}),
    Python(new String[]{"py"}), Ruby(new String[]{"rb"}), PHP(new String[]{"php", "php4", "php3", "php3"}),
    Scala(new String[]{"scala"}), Groovy(new String[]{"groovy"}), Dart(new String[]{"dart"}),
    Swift(new String[]{"swift"}), Objectiv_C(new String[]{"h", "m"}), Kotlin(new String[]{"kt"}),
    Lua(new String[]{"lua"}), TypeScript(new String[]{"ts"}), Erlang(new String[]{"erl"}),
    CoffeeScript(new String[]{"coffee"});

    private final transient String[] extensions;

    Lang(String[] extensions) {
        this.extensions = extensions;
    }


    private static int indexOfLastSeparator(final String filename) {
        if (filename == null) {
            return -1;
        }
        final int lastUnixPos = filename.lastIndexOf('/');
        final int lastWindowsPos = filename.lastIndexOf('\\');
        return Math.max(lastUnixPos, lastWindowsPos);
    }

    private static int indexOfExtension(final String filename) {
        if (filename == null) {
            return -1;
        }
        final int extensionPos = filename.lastIndexOf('.');
        final int lastSeparator = indexOfLastSeparator(filename);
        return lastSeparator > extensionPos ? -1 : extensionPos;
    }

    private static String getExtension(final String filename) {
        if (filename == null) {
            return null;
        }
        final int index = indexOfExtension(filename);
        if (index == -1) {
            return "";
        } else {
            return filename.substring(index + 1);
        }
    }

    private static void traverseAndUpdateExtensionCount(Map<String, Integer> extensionCountMap, File file) {
        if (!file.isHidden()) {
            if (file.isDirectory()) {
                File[] files = file.listFiles();
                if (files != null) {
                    for (File f : files) {
                        traverseAndUpdateExtensionCount(extensionCountMap, f);
                    }
                }
            } else {
                String extension = getExtension(file.getAbsolutePath());
                Integer count = extensionCountMap.get(extension);
                if (count != null) {
                    count++;
                } else {
                    count = 1;
                }
                extensionCountMap.put(extension, count);
            }
        }
    }

    private static Map<Lang, Integer> getLangFilesCount(File dir) {
        Map<Lang, Integer> langFilesCountMap = new HashMap<>();
        Map<String, Integer> extensionCountMap = new HashMap<>();
        if (dir != null) {
            traverseAndUpdateExtensionCount(extensionCountMap, dir);
        }
        for (Lang lang : Lang.values()) {
            int count = 0;
            for (String extension : lang.extensions) {
                Integer extCount = extensionCountMap.get(extension);
                if (extCount != null) {
                    count += extCount;
                }
            }
            if (count > 0) {
                langFilesCountMap.put(lang, count);
            }
        }
        return langFilesCountMap;
    }

    private static List<Lang> getLangListByUsage(File dir) {
        Map<Lang, Integer> langFilesCountMap = getLangFilesCount(dir);
        Map<Integer, List<Lang>> countToLang = new HashMap<>();
        for (Map.Entry<Lang, Integer> entry : langFilesCountMap.entrySet()) {
            List<Lang> langList = countToLang.get(entry.getValue());
            if (langList == null) {
                langList = new ArrayList<>();
            }
            langList.add(entry.getKey());
            countToLang.put(entry.getValue(), langList);
        }
        List<Integer> counts = new ArrayList<>(countToLang.keySet());
        Collections.sort(counts);
        Collections.reverse(counts);
        List<Lang> langListByUsage = new ArrayList<>();
        for (Integer count : counts) {
            if (count != null && count > 0) {
                langListByUsage.addAll(countToLang.get(count));
            }
        }
        return langListByUsage;
    }

    static Lang getLangFromDir(File dir) {
        List<Lang> langList = getLangListByUsage(dir);
        if (langList.size() > 0) {
            return langList.get(0);
        } else {
            return null;
        }
    }

}
