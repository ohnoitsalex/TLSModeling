package org.bouncycastle.mail.smime.handlers;

import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.util.Strings;

import javax.activation.ActivationDataFlavor;
import javax.activation.DataContentHandler;
import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import java.awt.datatransfer.DataFlavor;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;

public class multipart_signed
    implements DataContentHandler
{
    private static final ActivationDataFlavor ADF = new ActivationDataFlavor(MimeMultipart.class, "multipart/signed", "Multipart Signed");
    private static final DataFlavor[] DFS = new DataFlavor[]{ADF};

    public Object getContent(DataSource ds)
        throws IOException
    {
        try
        {
            return new MimeMultipart(ds);
        }
        catch (MessagingException ex)
        {
            return null;
        }
    }

    public Object getTransferData(DataFlavor df, DataSource ds)
        throws IOException
    {
        return HandlerUtil.getTransferData(this, ADF, df, ds);
    }

    public DataFlavor[] getTransferDataFlavors()
    {
        return DFS;
    }

    public void writeTo(Object obj, String _mimeType, OutputStream os)
        throws IOException
    {

        if (obj instanceof MimeMultipart)
        {
            try
            {
                outputBodyPart(os, obj);
            }
            catch (MessagingException ex)
            {
                throw new IOException(ex.getMessage());
            }
        }
        else
        {
            HandlerUtil.writeFromBarrInputStreamSMIMESTreamProcessor(obj, os);
        }
    }

    /*
     * Output the mulitpart as a collection of leaves to make sure preamble text is not included.
     */
    private void outputBodyPart(
        OutputStream out,
        Object bodyPart)
        throws MessagingException, IOException
    {
        if (bodyPart instanceof Multipart)
        {
            Multipart mp = (Multipart)bodyPart;
            ContentType contentType = new ContentType(mp.getContentType());
            String boundary = "--" + contentType.getParameter("boundary");

            LineOutputStream lOut = new LineOutputStream(out);

            for (int i = 0; i < mp.getCount(); i++)
            {
                lOut.writeln(boundary);
                outputBodyPart(out, mp.getBodyPart(i));
                lOut.writeln();       // CRLF terminator
            }

            lOut.writeln(boundary + "--");
            return;
        }

        MimeBodyPart mimePart = (MimeBodyPart)bodyPart;

        if (SMIMEUtil.isMultipartContent(mimePart))
        {
            Object content = mimePart.getContent();

            if (content instanceof Multipart)
            {
                Multipart mp = (Multipart)content;
                ContentType contentType = new ContentType(mp.getContentType());
                String boundary = "--" + contentType.getParameter("boundary");

                LineOutputStream lOut = new LineOutputStream(out);

                Enumeration headers = mimePart.getAllHeaderLines();
                while (headers.hasMoreElements())
                {
                    lOut.writeln((String)headers.nextElement());
                }

                lOut.writeln();      // CRLF separator

                outputPreamble(lOut, mimePart, boundary);

                outputBodyPart(out, mp);
                return;
            }
        }

        mimePart.writeTo(out);
    }

    /**
     * internal preamble is generally included in signatures, while this is technically wrong,
     * if we find internal preamble we include it by default.
     */
    static void outputPreamble(LineOutputStream lOut, MimeBodyPart part, String boundary)
        throws MessagingException, IOException
    {
        InputStream in;

        try
        {
            in = part.getRawInputStream();
        }
        catch (MessagingException e)
        {
            return;            // no underlying content, rely on default generation
        }

        String line;

        while ((line = readLine(in)) != null)
        {
            if (line.equals(boundary))
            {
                break;
            }

            lOut.writeln(line);
        }

        in.close();

        if (line == null)
        {
            throw new MessagingException("no boundary found");
        }
    }

    /*
     * read a line of input stripping of the tailing \r\n
     */
    private static String readLine(InputStream in)
        throws IOException
    {
        StringBuffer b = new StringBuffer();

        int ch;
        while ((ch = in.read()) >= 0 && ch != '\n')
        {
            if (ch != '\r')
            {
                b.append((char)ch);
            }
        }

        if (ch < 0)
        {
            return null;
        }

        return b.toString();
    }

    private static class LineOutputStream
        extends FilterOutputStream
    {
        private static byte newline[];

        public LineOutputStream(OutputStream outputstream)
        {
            super(outputstream);
        }

        public void writeln(String s)
            throws MessagingException
        {
            try
            {
                byte abyte0[] = Strings.toUTF8ByteArray(s);
                super.out.write(abyte0);
                super.out.write(newline);
            }
            catch (Exception exception)
            {
                throw new MessagingException("IOException", exception);
            }
        }

        public void writeln()
            throws MessagingException
        {
            try
            {
                super.out.write(newline);
            }
            catch (Exception exception)
            {
                throw new MessagingException("IOException", exception);
            }
        }

        static
        {
            newline = new byte[2];
            newline[0] = 13;
            newline[1] = 10;
        }
    }
}
