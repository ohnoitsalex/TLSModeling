package application.system_under_test.tls_system_under_test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.*;
import org.bouncycastle.tls.*;



import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class BCServer {

    public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, NoSuchProviderException, IOException, KeyStoreException, UnrecoverableKeyException {
        Security.setProperty("crypto.policy", "unlimited");
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);

        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory= CertificateFactory
                .getInstance("X.509", "BC");

        X509Certificate certificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("Baeldung.cer"));

        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("Baeldung.p12"), keystorePassword);
        PrivateKey key = (PrivateKey) keystore.getKey("baeldung", keyPassword);


    }
}
