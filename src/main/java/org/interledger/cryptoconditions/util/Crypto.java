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
     * @param preimage
     * @return hash of preimage
     */
    public static byte[] getSha256Hash(byte[] preimage) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(preimage);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }
    
}
