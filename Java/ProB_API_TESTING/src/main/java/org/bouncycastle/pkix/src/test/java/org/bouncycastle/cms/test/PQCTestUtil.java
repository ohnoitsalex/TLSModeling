package org.bouncycastle.cms.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.interfaces.FalconKey;
import org.bouncycastle.pqc.jcajce.interfaces.LMSKey;
import org.bouncycastle.pqc.jcajce.interfaces.PicnicKey;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

public class PQCTestUtil
{
    public static KeyPair makeKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SPHINCS256", "BCPQC");

        kpGen.initialize(new SPHINCS256KeyGenParameterSpec(), new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static KeyPair makeSphincsPlusKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SPHINCSPlus", "BCPQC");

        kpGen.initialize(SPHINCSPlusParameterSpec.sha2_128f_robust, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static KeyPair makeLmsKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BCPQC");

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1), new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static KeyPair makeFalconKeyPair()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Falcon", "BCPQC");

        kpGen.initialize(FalconParameterSpec.falcon_512, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static KeyPair makePicnicKeyPair()
            throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("Picnic", "BCPQC");
        //TODO: divide into two with cases with digest and with parametersets
        kpGen.initialize(PicnicParameterSpec.picnicl1full, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static KeyPair makeMlDsaKeyPair()
            throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
        //TODO: divide into two with cases with digest and with parametersets
        kpGen.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static KeyPair makeSlhDsaKeyPair()
            throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("SLH-DSA", "BC");
        //TODO: divide into two with cases with digest and with parametersets
        kpGen.initialize(SLHDSAParameterSpec.slh_dsa_sha2_128f, new SecureRandom());

        return kpGen.generateKeyPair();
    }

    public static X509Certificate makeCertificate(KeyPair subKP, String subDN, KeyPair issKP, String issDN)
        throws Exception
    {
        //
        // create base certificate - version 3
        //
        ContentSigner sigGen;
        PrivateKey    issPriv = issKP.getPrivate();
        if (issPriv instanceof FalconKey)
        {
            sigGen = new JcaContentSignerBuilder(((FalconKey)issPriv).getParameterSpec().getName()).setProvider("BCPQC").build(issPriv);
        }
        else if (issPriv instanceof PicnicKey)
        {
//            sigGen = new JcaContentSignerBuilder(((PicnicKey)issPriv).getParameterSpec().getName()).setProvider("BCPQC").build(issPriv);
            sigGen = new JcaContentSignerBuilder("PICNIC").setProvider("BCPQC").build(issPriv);
        }
        else if (issPriv instanceof MLDSAKey)
        {
            sigGen = new JcaContentSignerBuilder("ML-DSA").setProvider("BC").build(issPriv);
        }
        else if (issPriv instanceof SLHDSAKey)
        {
            sigGen = new JcaContentSignerBuilder("SLH-DSA").setProvider("BC").build(issPriv);
        }
        else if (issPriv instanceof LMSKey)
        {
            sigGen = new JcaContentSignerBuilder("LMS").setProvider("BC").build(issPriv);
        }
        else
        {
            sigGen = new JcaContentSignerBuilder("SHA512withSPHINCS256").setProvider("BCPQC").build(issPriv);
        }

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(new X500Name(issDN), BigInteger.valueOf(1), new Date(System.currentTimeMillis() - 50000), new Date(System.currentTimeMillis() + 50000), new X500Name(subDN), subKP.getPublic())
            .addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.digitalSignature))
            .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                new DERSequence(KeyPurposeId.anyExtendedKeyUsage));

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
    }
}
