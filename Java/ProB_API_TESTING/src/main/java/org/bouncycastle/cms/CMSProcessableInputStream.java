package org.bouncycastle.cms;

import org.bouncycastle.util.io.Streams;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class CMSProcessableInputStream implements CMSProcessable, CMSReadable {
    private final InputStream input;
    private boolean used = false;

    public CMSProcessableInputStream(
            InputStream input) {
        this.input = input;
    }

    public InputStream getInputStream() {
        checkSingleUsage();

        return input;
    }

    public void write(OutputStream zOut)
            throws IOException, CMSException {
        checkSingleUsage();

        Streams.pipeAll(input, zOut);
        input.close();
    }

    public Object getContent() {
        return getInputStream();
    }

    private synchronized void checkSingleUsage() {
        if (used) {
            throw new IllegalStateException("CMSProcessableInputStream can only be used once");
        }

        used = true;
    }
}
