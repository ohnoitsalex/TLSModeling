package application;

import application.test_examiner.TestExaminer;

public class Main {
    public static void main(String[] args) {
        // Exemple : on teste un serveur réel avec un client TLS-Attacker
        String type = "tls";       // Choix du modèle
        String mode = "server";    // Ce que tu veux tester (client ou serveur)

        TestExaminer examiner = new TestExaminer(type, mode);
        examiner.runTest();
    }
}
