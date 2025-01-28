package org.bouncycastle.cms.jcajce;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.OutputStream;

class JceAADStream
    extends OutputStream
{
     private final byte[] SINGLE_BYTE = new byte[1];
     private Cipher cipher;

     JceAADStream(Cipher cipher)
     {
         this.cipher = cipher;
     }

     public void write(byte[] buf, int off, int len)
         throws IOException
     {
         cipher.updateAAD(buf, off, len);
     }

     public void write(int b)
         throws IOException
     {
         SINGLE_BYTE[0] = (byte)b;
         cipher.updateAAD(SINGLE_BYTE, 0, 1);
     }
 }
