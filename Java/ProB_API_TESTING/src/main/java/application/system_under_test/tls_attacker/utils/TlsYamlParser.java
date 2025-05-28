package application.system_under_test.tls_attacker.utils;

import org.yaml.snakeyaml.Yaml;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;

/**
 * Utility class for reading and writing TLS message data in YAML format.
 */
public class TlsYamlParser {
    
    /**
     * Reads a YAML file and returns its contents as a Map.
     * @param filename The path to the YAML file
     * @return Map containing the YAML data
     */
    public static Map<String, String> readYaml(String filename) {
        try (FileReader reader = new FileReader(filename)) {
            Yaml yaml = new Yaml();
            return yaml.load(reader);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read YAML file: " + filename, e);
        }
    }

    /**
     * Writes data to a YAML file.
     * @param data The data to write
     * @param filename The path where to write the YAML file
     */
    public static void writeYaml(Map<String, String> data, String filename) {
        try (FileWriter writer = new FileWriter(filename)) {
            Yaml yaml = new Yaml();
            yaml.dump(data, writer);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write YAML file: " + filename, e);
        }
    }
}
