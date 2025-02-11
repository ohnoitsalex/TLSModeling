package org.bouncycastle.cms;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.*;

public class SignerInformationVerifier {
    private final ContentVerifierProvider verifierProvider;
    private final DigestCalculatorProvider digestProvider;
    private final SignatureAlgorithmIdentifierFinder sigAlgorithmFinder;
    private final CMSSignatureAlgorithmNameGenerator sigNameGenerator;

    public SignerInformationVerifier(CMSSignatureAlgorithmNameGenerator sigNameGenerator, SignatureAlgorithmIdentifierFinder sigAlgorithmFinder, ContentVerifierProvider verifierProvider, DigestCalculatorProvider digestProvider) {
        this.sigNameGenerator = sigNameGenerator;
        this.sigAlgorithmFinder = sigAlgorithmFinder;
        this.verifierProvider = verifierProvider;
        this.digestProvider = digestProvider;
    }

    public boolean hasAssociatedCertificate() {
        return verifierProvider.hasAssociatedCertificate();
    }

    public X509CertificateHolder getAssociatedCertificate() {
        return verifierProvider.getAssociatedCertificate();
    }

    public ContentVerifier getContentVerifier(AlgorithmIdentifier signingAlgorithm, AlgorithmIdentifier digestAlgorithm)
            throws OperatorCreationException {
        String signatureName = sigNameGenerator.getSignatureName(digestAlgorithm, signingAlgorithm);
        AlgorithmIdentifier baseAlgID = sigAlgorithmFinder.find(signatureName);

        return verifierProvider.get(new AlgorithmIdentifier(baseAlgID.getAlgorithm(), signingAlgorithm.getParameters()));
    }

    public DigestCalculator getDigestCalculator(AlgorithmIdentifier algorithmIdentifier)
            throws OperatorCreationException {
        return digestProvider.get(algorithmIdentifier);
    }
}
