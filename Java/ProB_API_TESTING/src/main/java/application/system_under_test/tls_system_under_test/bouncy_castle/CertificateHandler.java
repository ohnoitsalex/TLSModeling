package application.system_under_test.tls_system_under_test.bouncy_castle;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateHandler {

    public static KeyPair keyPair;
    public static X509Certificate certificate;
    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, SignatureException, InvalidKeyException {
            Provider[] providers = Security.getProviders();
//            for (Provider provider : providers) {
//                System.out.println("Name: " + provider.getName() + ", Version: " + provider.getVersion());
//            }

            // build a certificate generator
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            X500Principal dnName = new X500Principal("cn=example");

            // add some options
            certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            certGen.setSubjectDN(new X509Name("dc=name"));
            certGen.setIssuerDN(dnName); // use the same
            // yesterday
            certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
            // in 2 years
            certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
            certGen.setPublicKey(keyPair.getPublic());
            certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
            certGen.addExtension(X509Extensions.ExtendedKeyUsage, true,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

            // finally, sign the certificate with the private key of the same KeyPair
            X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
            return cert;
    }

    public static void generate() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        // Generate a key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, new SecureRandom());
        keyPair = keyPairGenerator.generateKeyPair();

        // Generate the self-signed certificate
        certificate = generateSelfSignedCertificate(keyPair);

        // Output the certificate
        System.out.println("Generated Self-Signed Certificate:");
        System.out.println(certificate);
    }
}
