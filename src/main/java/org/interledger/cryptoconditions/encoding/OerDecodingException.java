package org.interledger.cryptoconditions.encoding;


/**
 * Base exception for all OER decoding exceptions
 * 
 * @author adrianhopebailie
 *
 */
public abstract class OerDecodingException extends Exception {
    
    private static final long serialVersionUID = 7363031559695469596L;

    public OerDecodingException(String message) {
        super(message);
    }

}
