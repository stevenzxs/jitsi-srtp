/*
 * Copyright @ 2026 CloudMeet contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.jitsi.srtp.crypto;

import java.security.Provider;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Factory for SM4 ciphers backed by Bouncy Castle.
 *
 * The provider is intentionally kept local to the cipher factory. Installing
 * a global provider is a JVB integration decision and is not appropriate for
 * this library-level prototype.
 */
public final class Sm4
{
    private static final Provider PROVIDER = new BouncyCastleProvider();

    private Sm4()
    {
    }

    /**
     * Creates an SM4 cipher using the supplied transformation, for example
     * {@code SM4/GCM/NoPadding} or {@code SM4/CTR/NoPadding}.
     *
     * @param transformation the JCE SM4 transformation
     * @return a new SM4 cipher
     */
    public static Cipher createCipher(String transformation)
    {
        try
        {
            return Cipher.getInstance(transformation, PROVIDER);
        }
        catch (Exception e)
        {
            throw new IllegalStateException(
                "SM4 transformation is not available: " + transformation,
                e);
        }
    }
}
