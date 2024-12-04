package application;

import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_system_under_test.TLSSystemUnderTest;
import application.test_examiner.TestExaminer;

public class Main {
    private static SystemUnderTest tlsSystemUnderTest = new TLSSystemUnderTest();
    private static TestExaminer tlsTestExaminer = new TestExaminer("tls");

    public static void main(String[] args) {

        tlsTestExaminer.loadModel();
        tlsTestExaminer.executeModelOperation();
        //tlsTestExaminer.createSUT();
    }
}