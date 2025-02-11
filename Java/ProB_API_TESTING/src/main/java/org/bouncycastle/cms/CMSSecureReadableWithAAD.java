package org.bouncycastle.cms;

import java.io.OutputStream;

interface CMSSecureReadableWithAAD
        extends CMSSecureReadable {
    OutputStream getAADStream();

    void setAADStream(OutputStream stream);

    byte[] getMAC();
}
