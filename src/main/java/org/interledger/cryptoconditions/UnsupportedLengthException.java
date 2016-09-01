package org.interledger.cryptoconditions;

/**
 * Thrown when a field length exceeds supported bounds
 * 
 * @author adrianhopebailie
 *
 */
public class UnsupportedLengthException extends UnsupportedConditionException {

    private static final long serialVersionUID = 6368777371981462844L;

    public UnsupportedLengthException(String message) {
        super(message);
    }

}
