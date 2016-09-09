package org.interledger.cryptoconditions.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Convenience class for crypto functions
 *
 * @author adrianhopebailie
 *
 */
public class Crypto {

    /**
     * Get the Sha256 hash of a pre-image.
     *
     * Convenience function which hides NoSuchAlgorithmException.
     *
     * @param input
     * @return hash of input
     */
    public static byte[] getSha256Hash(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
