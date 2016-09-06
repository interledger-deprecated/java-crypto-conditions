package org.interledger.cryptoconditions;

/**
 * Base exception for any exceptions thrown when unsupported 
 * crypto-conditions are encountered
 * 
 * @author adrianhopebailie
 *
 */
public abstract class UnsupportedConditionException extends Exception {

    private static final long serialVersionUID = -4173529087643312558L;

    public UnsupportedConditionException(String message) {
        super(message);
    }

}
