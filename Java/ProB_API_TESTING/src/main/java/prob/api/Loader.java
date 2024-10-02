package prob.api;

import de.prob.Main;
import de.prob.scripting.Api;
import de.prob.statespace.StateSpace;

public class Loader {

    private Api api;
    private StateSpace model;

    public Loader(){
    }
    public void loadAndExecuteAPI(String proBModelPath){
        try {
            api = Main.getInjector().getInstance(Api.class);
            model = api.b_load(proBModelPath);
            model.execute();
            model.performExtendedStaticChecks();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void printMachineInformation(){
        System.out.println("--------------");
        System.out.println("Machine Constants: " + model.getLoadedMachine().getConstantNames());
        System.out.println("--------------");
        System.out.println("Machine Variables: " + model.getLoadedMachine().getVariableNames());
        System.out.println("--------------");
        System.out.println("Machine Operations: " + model.getLoadedMachine().getOperationNames());
        System.out.println("--------------");
    }
}
