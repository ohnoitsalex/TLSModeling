package application.information_converter;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.representer.Representer;

import java.io.FileWriter;
import java.io.IOException;

public class InformationConvertertoAbstract {

    // Configure YAML options
    private static DumperOptions options;

    //Yaml Instance
    private static Yaml yaml;

    public static void configureYAML(){
        options = new DumperOptions();
        options.setPrettyFlow(true); // Make YAML more readable
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK); // Use block-style formatting

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
}
