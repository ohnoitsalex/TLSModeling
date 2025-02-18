package org.bouncycastle.mail.smime.handlers;

import javax.activation.ActivationDataFlavor;
import javax.mail.internet.MimeBodyPart;
import java.awt.datatransfer.DataFlavor;

public class pkcs7_mime 
    extends PKCS7ContentHandler
{
    private static final ActivationDataFlavor ADF = new ActivationDataFlavor(MimeBodyPart.class, "application/pkcs7-mime", "Encrypted Data");
    private static final DataFlavor[]         DFS = new DataFlavor[] { ADF };
    
    public pkcs7_mime()
    {
        super(ADF, DFS);
    }
}
