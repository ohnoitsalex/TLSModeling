package application.information_handler;

import application.config.Config;
import ch.qos.logback.core.testUtil.TeeOutputStream;
import org.yaml.snakeyaml.Yaml;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AbstractInformationComparator {

    public static boolean compareAbstractYaml(
            Map<String, Object> yaml1, Map<String, Object> yaml2, String path) {
        boolean differencesFound = false;
        try {
            // Set up a PrintStream to write to both console and file
            PrintStream fileOut = new PrintStream(new FileOutputStream(Config.DIFFERENCES, true));
            PrintStream consoleOut = System.out;

            // Wrap both streams
            PrintStream multiOut = new PrintStream(new TeeOutputStream(consoleOut));
            System.setOut(multiOut);

            // Perform the comparison
            Set<String> keys = new HashSet<>(yaml1.keySet());
            keys.addAll(yaml2.keySet()); // Ensure all keys are checked

            for (String key : keys) {
                String currentPath = path.isEmpty() ? key : path + "." + key;

                if (!yaml1.containsKey(key)) {
                    System.out.println("Missing in first file: " + currentPath);
                } else if (!yaml2.containsKey(key)) {
                    System.out.println("Missing in second file: " + currentPath);
                } else {
                    Object val1 = yaml1.get(key);
                    Object val2 = yaml2.get(key);

                    if (val1 instanceof Map && val2 instanceof Map) {
                        compareAbstractYaml((Map<String, Object>) val1, (Map<String, Object>) val2, currentPath);
                    } else if (!val1.equals(val2)) {
                        System.out.println("Difference at " + currentPath + " -> " + val1 + " vs " + val2);
                        differencesFound = true;
                    }
                }

            }

            // Close file stream after writing
            fileOut.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return differencesFound;
    }

    public static void main(String[] args) {
        Yaml yaml = new Yaml();

        try (InputStream input1 = AbstractInformationComparator.class.getClassLoader().getResourceAsStream(Config.RESSOURCESMODELCLIENTHELLO);
             InputStream input2 = AbstractInformationComparator.class.getClassLoader().getResourceAsStream(Config.RESSOURCESSUTCLIENTHELLO)) {

            if (input1 == null || input2 == null) {
                System.out.println("Error: One or both YAML files not found!");
                return;
            }

            Map<String, Object> yamlMap1 = yaml.load(input1);
            Map<String, Object> yamlMap2 = yaml.load(input2);

            compareAbstractYaml(yamlMap1, yamlMap2, "");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
