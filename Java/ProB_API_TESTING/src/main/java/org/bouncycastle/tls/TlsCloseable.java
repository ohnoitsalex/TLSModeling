package org.bouncycastle.tls;

import java.io.IOException;

public interface TlsCloseable
{
    void close() throws IOException;
}
