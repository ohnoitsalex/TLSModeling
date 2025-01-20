package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;

import java.security.Key;

public interface PicnicKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a PcnicParameterSpec
     */
    PicnicParameterSpec getParameterSpec();
}
