package org.bouncycastle.cms.jcajce;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class JcaSignerInfoVerifierBuilder {
    private Helper helper = new Helper();
    private DigestCalculatorProvider digestProvider;
    private CMSSignatureAlgorithmNameGenerator sigAlgNameGen = new DefaultCMSSignatureAlgorithmNameGenerator();
    private SignatureAlgorithmIdentifierFinder sigAlgIDFinder = new DefaultSignatureAlgorithmIdentifierFinder();

    public JcaSignerInfoVerifierBuilder(DigestCalculatorProvider digestProvider) {
        this.digestProvider = digestProvider;
    }

    public JcaSignerInfoVerifierBuilder setProvider(Provider provider) {
        this.helper = new ProviderHelper(provider);

        return this;
    }

    public JcaSignerInfoVerifierBuilder setProvider(String providerName) {
        this.helper = new NamedHelper(providerName);

        return this;
    }

    /**
     * Override the default signature algorithm name generator.
     *
     * @param sigAlgNameGen the algorithm name generator to use.
     * @return the current builder.
     */
    public JcaSignerInfoVerifierBuilder setSignatureAlgorithmNameGenerator(CMSSignatureAlgorithmNameGenerator sigAlgNameGen) {
        this.sigAlgNameGen = sigAlgNameGen;

        return this;
    }

    public JcaSignerInfoVerifierBuilder setSignatureAlgorithmFinder(SignatureAlgorithmIdentifierFinder sigAlgIDFinder) {
        this.sigAlgIDFinder = sigAlgIDFinder;

        return this;
    }

    public SignerInformationVerifier build(X509CertificateHolder certHolder)
            throws OperatorCreationException, CertificateException {
        return new SignerInformationVerifier(sigAlgNameGen, sigAlgIDFinder, helper.createContentVerifierProvider(certHolder), digestProvider);
    }

    public SignerInformationVerifier build(X509Certificate certificate)
            throws OperatorCreationException {
        return new SignerInformationVerifier(sigAlgNameGen, sigAlgIDFinder, helper.createContentVerifierProvider(certificate), digestProvider);
    }

    public SignerInformationVerifier build(PublicKey pubKey)
            throws OperatorCreationException {
        return new SignerInformationVerifier(sigAlgNameGen, sigAlgIDFinder, helper.createContentVerifierProvider(pubKey), digestProvider);
    }

    private static class Helper {
        ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
                throws OperatorCreationException {
            return new JcaContentVerifierProviderBuilder().build(publicKey);
        }

        ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
                throws OperatorCreationException {
            return new JcaContentVerifierProviderBuilder().build(certificate);
        }

        ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
                throws OperatorCreationException, CertificateException {
            return new JcaContentVerifierProviderBuilder().build(certHolder);
        }

        DigestCalculatorProvider createDigestCalculatorProvider()
                throws OperatorCreationException {
            return new JcaDigestCalculatorProviderBuilder().build();
        }
    }

    private static class NamedHelper
            extends Helper {
        private final String providerName;

        public NamedHelper(String providerName) {
            this.providerName = providerName;
        }

        ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
                throws OperatorCreationException {
            return new JcaContentVerifierProviderBuilder().setProvider(providerName).build(publicKey);
        }

        ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
                throws OperatorCreationException {
            return new JcaContentVerifierProviderBuilder().setProvider(providerName).build(certificate);
        }

        DigestCalculatorProvider createDigestCalculatorProvider()
                throws OperatorCreationException {
            return new JcaDigestCalculatorProviderBuilder().setProvider(providerName).build();
        }

        ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
                throws OperatorCreationException, CertificateException {
            return new JcaContentVerifierProviderBuilder().setProvider(providerName).build(certHolder);
        }
    }

    private static class ProviderHelper
            extends Helper {
        private final Provider provider;

        public ProviderHelper(Provider provider) {
            this.provider = provider;
        }

        ContentVerifierProvider createContentVerifierProvider(PublicKey publicKey)
                throws OperatorCreationException {
            return new JcaContentVerifierProviderBuilder().setProvider(provider).build(publicKey);
        }

        ContentVerifierProvider createContentVerifierProvider(X509Certificate certificate)
                throws OperatorCreationException {
            return new JcaContentVerifierProviderBuilder().setProvider(provider).build(certificate);
        }

        DigestCalculatorProvider createDigestCalculatorProvider()
                throws OperatorCreationException {
            return new JcaDigestCalculatorProviderBuilder().setProvider(provider).build();
        }

        ContentVerifierProvider createContentVerifierProvider(X509CertificateHolder certHolder)
                throws OperatorCreationException, CertificateException {
            return new JcaContentVerifierProviderBuilder().setProvider(provider).build(certHolder);
        }
    }
}
