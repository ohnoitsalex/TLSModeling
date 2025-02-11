package application;

import application.test_examiner.TestExaminer;

public class Main {
    private static final TestExaminer tlsTestExaminer = new TestExaminer("tls");

    public static void main(String[] args) {

        tlsTestExaminer.loadModel();
        tlsTestExaminer.testServerHello();
        tlsTestExaminer.createSUT();
    }

    public void testServerHello(){
        tlsTestExaminer.loadModel();
        tlsTestExaminer.testServerHello();
    }
}
