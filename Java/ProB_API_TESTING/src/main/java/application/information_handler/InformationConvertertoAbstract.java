package application.information_handler;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.representer.Representer;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.stream.Collectors;

public class InformationConvertertoAbstract {

    // Configuration YAML initialisée une seule fois
    private static final DumperOptions options;
    private static final Yaml yaml;

    static {
        options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setExplicitStart(false);
        yaml = new Yaml(new Representer(options), options);
    }

    public static void removeGlobalTagsYaml(String filePath) {
        try {
            Path path = Paths.get(filePath).toAbsolutePath();
            if (!Files.exists(path)) {
                System.err.println("File not found: " + path);
                return;
            }

            String updatedContent = Files.lines(path)
                    .skip(1)
                    .collect(Collectors.joining(System.lineSeparator()));

            Files.write(path, updatedContent.getBytes());
            System.out.println("First line removed successfully from " + filePath);
        } catch (IOException e) {
            System.err.println("Error processing file " + filePath);
            e.printStackTrace();
        }
    }

    public static void serializeToYAML(Object obj, String filePath) {
        try {
            Path path = Paths.get(filePath).toAbsolutePath();
            Files.createDirectories(path.getParent());
            
            try (FileWriter writer = new FileWriter(filePath)) {
                yaml.dump(obj, writer);
                System.out.println("YAML file created: " + path);
            }
        } catch (IOException e) {
            System.err.println("Failed to write YAML to " + filePath);
            e.printStackTrace();
        }
    }

    public static void configureYAML() {
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        options.setExplicitStart(false);
    }

    public static Map<String, Object> retreiveYamlInformation(String yamlFilePath) {
        try {
            Path path = Paths.get(yamlFilePath).toAbsolutePath();
            if (!Files.exists(path)) {
                System.err.println("YAML file not found: " + path);
                return null;
            }

            try (InputStream input = Files.newInputStream(path)) {
                Map<String, Object> result = yaml.load(input);
                if (result == null) {
                    System.err.println("Loaded YAML is null from: " + path);
                }
                return result;
            }
        } catch (Exception e) {
            System.err.println("Error loading YAML from " + yamlFilePath);
            e.printStackTrace();
            return null;
        }
    }
}