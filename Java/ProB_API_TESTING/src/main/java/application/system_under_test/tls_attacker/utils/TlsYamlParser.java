package application.system_under_test.tls_attacker.utils;

import java.util.Map;
import java.io.File;
import org.yaml.snakeyaml.Yaml;
import java.io.FileWriter;
import java.io.FileReader;

public class TlsYamlParser {
    public static Map<String, String> readYaml(String filename) {
        try {
            Yaml yaml = new Yaml();
            return yaml.load(new FileReader(filename));
        } catch (Exception e) {
            throw new RuntimeException("Failed to read YAML file: " + filename, e);
        }
    }

    public static void writeYaml(Map<String, String> data, String filename) {
        try {
            Yaml yaml = new Yaml();
            yaml.dump(data, new FileWriter(filename));
        } catch (Exception e) {
            throw new RuntimeException("Failed to write YAML file: " + filename, e);
        }
    }
}
