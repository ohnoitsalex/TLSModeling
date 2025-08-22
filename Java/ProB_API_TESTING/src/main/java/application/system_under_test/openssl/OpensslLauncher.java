package application.system_under_test.openssl;

import java.io.*;
import java.util.*;

public class OpensslLauncher {

    public static Process startOpenSslServer(String certPath, String keyPath, int port) throws IOException {
        List<String> command = Arrays.asList(
            "openssl", "s_server",
            "-accept", String.valueOf(port),
            "-cert", certPath,
            "-key", keyPath,
            "-tls1_3"
        );

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();

        // Optionnel : lire la sortie du process
        new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[OpenSSL] " + line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        return process;
    }
}
