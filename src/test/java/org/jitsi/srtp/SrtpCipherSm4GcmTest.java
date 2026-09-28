/*
 * Copyright @ 2026 CloudMeet contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package org.jitsi.srtp;

import org.jitsi.srtp.crypto.Sm4;
import org.jitsi.srtp.crypto.SrtpCipherGcm;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Library-level SM4-GCM checks. DTLS profile negotiation is intentionally not
 * covered here and remains a JVB/libwebrtc integration task.
 */
public class SrtpCipherSm4GcmTest
{
    private static final byte[] KEY =
        new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    private static final byte[] IV =
        new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    private static final byte[] AAD = "rtp-header".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PLAINTEXT =
        "SM4-SRTP prototype payload".getBytes(StandardCharsets.UTF_8);

    @Test
    public void testSm4GcmRoundTripAndTamperDetection() throws Exception
    {
        SrtpCipherGcm encryptor = new SrtpCipherGcm(
            Sm4.createCipher("SM4/GCM/NoPadding"));
        encryptor.init(KEY, null);
        byte[] encrypted = Arrays.copyOf(PLAINTEXT, PLAINTEXT.length + 16);
        encryptor.setIV(IV, Cipher.ENCRYPT_MODE);
        encryptor.processAAD(AAD, 0, AAD.length);
        int encryptedLength = encryptor.process(encrypted, 0, PLAINTEXT.length);
        assertEquals(PLAINTEXT.length + 16, encryptedLength);

        SrtpCipherGcm decryptor = new SrtpCipherGcm(
            Sm4.createCipher("SM4/GCM/NoPadding"));
        decryptor.init(KEY, null);
        decryptor.setIV(IV, Cipher.DECRYPT_MODE);
        decryptor.processAAD(AAD, 0, AAD.length);
        int plaintextLength = decryptor.process(encrypted, 0, encryptedLength);
        assertEquals(PLAINTEXT.length, plaintextLength);
        assertArrayEquals(PLAINTEXT,
            Arrays.copyOf(encrypted, plaintextLength));

        byte[] tampered = Arrays.copyOf(encrypted, encryptedLength);
        tampered[0] ^= 1;
        SrtpCipherGcm rejectingDecryptor = new SrtpCipherGcm(
            Sm4.createCipher("SM4/GCM/NoPadding"));
        rejectingDecryptor.init(KEY, null);
        rejectingDecryptor.setIV(IV, Cipher.DECRYPT_MODE);
        rejectingDecryptor.processAAD(AAD, 0, AAD.length);
        assertThrows(AEADBadTagException.class,
            () -> rejectingDecryptor.process(tampered, 0, tampered.length));
    }

    @Test
    public void testSm4PolicyConstants()
    {
        SrtpPolicy policy = new SrtpPolicy(
            SrtpPolicy.SM4GCM_ENCRYPTION,
            16,
            SrtpPolicy.NULL_AUTHENTICATION,
            0,
            16,
            14);

        assertEquals(SrtpPolicy.SM4GCM_ENCRYPTION, policy.getEncType());
        assertEquals(16, policy.getEncKeyLength());
        assertEquals(16, policy.getAuthTagLength());
    }
}
