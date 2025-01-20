package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import java.security.Key;

public interface KyberKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a KyberParameterSpec
     */
    KyberParameterSpec getParameterSpec();
}
