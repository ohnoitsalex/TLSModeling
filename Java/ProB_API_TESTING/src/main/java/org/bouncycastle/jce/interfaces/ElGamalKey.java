package org.bouncycastle.jce.interfaces;

import org.bouncycastle.jce.spec.ElGamalParameterSpec;

import javax.crypto.interfaces.DHKey;

public interface ElGamalKey
    extends DHKey
{
    public ElGamalParameterSpec getParameters();
}
