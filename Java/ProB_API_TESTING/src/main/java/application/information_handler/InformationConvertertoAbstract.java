package application.information_handler;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.representer.Representer;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.stream.Collectors;

public class InformationConvertertoAbstract {

    // Configure YAML options
    private static DumperOptions options;

    //Yaml Instance
    private static Yaml yaml;

    public static void removeGlobalTagsYaml(String filePath){
        try {
            // Step 1: Read the file and skip the first line
            Path path = Paths.get(filePath);
            String updatedContent = Files.lines(path)
                    .skip(1) // Skip the first line
                    .collect(Collectors.joining(System.lineSeparator()));

            // Step 2: Write the updated content back to the same file
            Files.write(path, updatedContent.getBytes());

            System.out.println("First line removed successfully from " + filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void configureYAML(){
        options = new DumperOptions();
        //Configure DumperOptions to suppress global tags
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK); // Use block style (readable)
        options.setPrettyFlow(true); // Make it pretty
        options.setExplicitStart(false); // Avoid "---" at the start

        yaml = new Yaml(new Representer(options), options);
    }

    public static void serializeToYAML(Object obj, String name) {
        // Serialize to YAML string
        String yamlString = yaml.dump(obj);

        // Optionally, write to a file
        try (FileWriter writer = new FileWriter(name+".yaml")) {
            writer.write(yamlString);
            System.out.println( name +".yaml file created successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static Map<String, Object> retreiveYamlInformation(String yamlFilePath){
        InputStream inputStream = InformationConvertertoAbstract.class.getClassLoader().getResourceAsStream(yamlFilePath);
        if (inputStream != null)
            return yaml.load(inputStream);
        return null;
    }
}
