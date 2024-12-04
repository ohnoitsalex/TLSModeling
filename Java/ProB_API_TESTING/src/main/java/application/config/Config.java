package application.config;

import com.google.inject.AbstractModule;
import de.prob.MainModule;

public class Config extends AbstractModule {

    public static final String TLSMODELFILEPATH = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/TLS_specification.mch";
    public static final String LIBRARYMODELFILEPATH = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/Library_Example.mch";
    public static final String CLIENTCLASSNAME = "application.system_under_test.tls_system_under_test.Client";
    public static final String SERVERCLASSNAME = "application.system_under_test.tls_system_under_test.Server";
    public static final String CLASSPATH = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/target/classes";
    @Override
    protected void configure() {
        install(new MainModule()); // Install ProB 2.0 Injection bindings
    }

}