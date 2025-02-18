package application.config;

import com.google.inject.AbstractModule;
import de.prob.MainModule;

public class Config extends AbstractModule {

    public static final String TLSMODELFILEPATH = "src/main/resources/models/TLS_specification.mch";
    public static final String TLSMODELFORTESTINGFILEPATH = "src/main/resources/models/TLS_specificationTesting.mch";
    public static final String LIBRARYMODELFILEPATH = "src/main/resources/models/Library_Example.mch";
    public static final String CLIENTCLASSNAME = "application.system_under_test.tls_system_under_test.Client";
    public static final String SERVERCLASSNAME = "application.system_under_test.tls_system_under_test.Server";
    public static final String CLASSPATH = "target/classes";

    @Override
    protected void configure() {
        install(new MainModule()); // Install ProB 2.0 Injection bindings
    }

}