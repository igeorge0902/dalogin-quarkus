package com.dalogin.crypto;

import com.dalogin.utils.AesUtil;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Stateless replacement for a Servlet-held {@code AesUtil} instance. {@code AesUtil} stores a
 * mutable {@code Cipher} field, and {@code Cipher} is not thread-safe; each Servlet is a singleton
 * serving concurrent requests. This service creates a fresh {@code AesUtil} per operation so its
 * cryptographic state is always request-local, while preserving the algorithm and wire format.
 */
@ApplicationScoped
public class CryptoService {

    private static final int KEY_SIZE = 128;
    private static final int ITERATION_COUNT = 1000;

    public String encrypt(String salt, String iv, String passphrase, String plaintext) {
        return new AesUtil(KEY_SIZE, ITERATION_COUNT).encrypt(salt, iv, passphrase, plaintext);
    }

    public String decrypt(String salt, String iv, String passphrase, String ciphertext) {
        return new AesUtil(KEY_SIZE, ITERATION_COUNT).decrypt(salt, iv, passphrase, ciphertext);
    }
}
