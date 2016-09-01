package org.interledger.cryptoconditions.encoding;

/**
 * Thrown if an illegal OER length indicator is encountered
 * 
 * @author adrianhopebailie
 *
 */
public class IllegalLengthIndicatorException extends OerDecodingException {

    private static final long serialVersionUID = 2076963320466312387L;

    public IllegalLengthIndicatorException(String message) {
        super(message);
    }

}
