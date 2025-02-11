package application.config;

import com.google.inject.AbstractModule;
import de.prob.MainModule;

public class Config extends AbstractModule {

    public static final String TLSMODELFILEPATH = "src/main/resources/models/TLS_specification.mch";
    public static final String TLSMODELFORTESTINGFILEPATH = "src/main/resources/models/TLS_specificationTesting.mch";
    public static final String CLIENTCLASSNAME = "application.system_under_test.tls_system_under_test.Client";
    public static final String SERVERCLASSNAME = "application.system_under_test.tls_system_under_test.Server";
    public static final String MODELCLIENTHELLOYAML = "src/main/resources/data/ModelClientHello.yaml";
    public static final String MODELCLIENTHELLO = "src/main/resources/data/ModelClientHello";
    public static final String MODELSERVERHELLOYAML = "src/main/resources/data/ModelServerHello.yaml";
    public static final String MODELSERVERHELLO = "src/main/resources/data/ModelServerHello";
    public static final String SUTCLIENTHELLOYAML = "src/main/resources/data/SUTClientHello.yaml";
    public static final String SUTCLIENTHELLO = "src/main/resources/data/SUTClientHello";
    public static final String SUTSERVERHELLOYAML = "src/main/resources/data/SUTServerHello.yaml";
    public static final String SUTSERVERHELLO = "src/main/resources/data/SUTServerHello";
    public static final String CLASSPATH = "target/classes";
    public static final String WRITERFILEPATH = "src/main/resources/data/tls_handshake_data.txt";
    public static final String DIFFERENCES = "src/main/resources/data/differences.txt";

    public static final String RESSOURCESSUTCLIENTHELLO = "data/SUTClientHello.yaml";

    public static final String RESSOURCESMODELCLIENTHELLO = "data/ModelClientHello.yaml";



    @Override
    protected void configure() {
        install(new MainModule()); // Install ProB 2.0 Injection bindings
    }

}