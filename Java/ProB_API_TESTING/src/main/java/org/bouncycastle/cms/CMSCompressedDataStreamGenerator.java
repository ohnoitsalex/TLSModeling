package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.BERSequenceGenerator;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.operator.OutputCompressor;

import java.io.IOException;
import java.io.OutputStream;

/**
 * General class for generating a compressed CMS message stream.
 * <p>
 * A simple example of usage.
 * </p>
 * <pre>
 *      CMSCompressedDataStreamGenerator gen = new CMSCompressedDataStreamGenerator();
 *
 *      OutputStream cOut = gen.open(outputStream, new ZlibCompressor());
 *
 *      cOut.write(data);
 *
 *      cOut.close();
 * </pre>
 */
public class CMSCompressedDataStreamGenerator {
    public static final String ZLIB = CMSObjectIdentifiers.zlibCompress.getId();

    private int _bufferSize;

    /**
     * base constructor
     */
    public CMSCompressedDataStreamGenerator() {
    }

    /**
     * Set the underlying string size for encapsulated data
     *
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
            int bufferSize) {
        _bufferSize = bufferSize;
    }

    /**
     * Open a compressing output stream with the PKCS#7 content type OID of "data".
     *
     * @param out        the stream to encode to.
     * @param compressor the type of compressor to use.
     * @return an output stream to write the data be compressed to.
     * @throws IOException
     */
    public OutputStream open(
            OutputStream out,
            OutputCompressor compressor)
            throws IOException {
        return open(CMSObjectIdentifiers.data, out, compressor);
    }

    /**
     * Open a compressing output stream.
     *
     * @param contentOID the content type OID.
     * @param out        the stream to encode to.
     * @param compressor the type of compressor to use.
     * @return an output stream to write the data be compressed to.
     * @throws IOException
     */
    public OutputStream open(
            ASN1ObjectIdentifier contentOID,
            OutputStream out,
            OutputCompressor compressor)
            throws IOException {
        BERSequenceGenerator sGen = new BERSequenceGenerator(out);

        sGen.addObject(CMSObjectIdentifiers.compressedData);

        //
        // Compressed Data
        //
        BERSequenceGenerator cGen = new BERSequenceGenerator(sGen.getRawOutputStream(), 0, true);

        cGen.addObject(new ASN1Integer(0));

        //
        // AlgorithmIdentifier
        //
        cGen.addObject(compressor.getAlgorithmIdentifier());

        //
        // Encapsulated ContentInfo
        //
        BERSequenceGenerator eiGen = new BERSequenceGenerator(cGen.getRawOutputStream());

        eiGen.addObject(contentOID);

        OutputStream octetStream = CMSUtils.createBEROctetOutputStream(
                eiGen.getRawOutputStream(), 0, true, _bufferSize);

        return new CmsCompressedOutputStream(
                compressor.getOutputStream(octetStream), sGen, cGen, eiGen);
    }

    private static class CmsCompressedOutputStream
            extends OutputStream {
        private final OutputStream _out;
        private final BERSequenceGenerator _sGen;
        private final BERSequenceGenerator _cGen;
        private final BERSequenceGenerator _eiGen;

        CmsCompressedOutputStream(
                OutputStream out,
                BERSequenceGenerator sGen,
                BERSequenceGenerator cGen,
                BERSequenceGenerator eiGen) {
            _out = out;
            _sGen = sGen;
            _cGen = cGen;
            _eiGen = eiGen;
        }

        public void write(
                int b)
                throws IOException {
            _out.write(b);
        }


        public void write(
                byte[] bytes,
                int off,
                int len)
                throws IOException {
            _out.write(bytes, off, len);
        }

        public void write(
                byte[] bytes)
                throws IOException {
            _out.write(bytes);
        }

        public void close()
                throws IOException {
            _out.close();
            _eiGen.close();
            _cGen.close();
            _sGen.close();
        }
    }
}
