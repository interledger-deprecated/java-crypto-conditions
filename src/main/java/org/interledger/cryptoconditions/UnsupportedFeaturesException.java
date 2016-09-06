package org.interledger.cryptoconditions;

/**
 * Thrown when a feature is encountered that is unrecognized
 * 
 * @author adrianhopebailie
 *
 */
public class UnsupportedFeaturesException extends UnsupportedConditionException {

    private static final long serialVersionUID = 4065337161784477150L;
    
    public UnsupportedFeaturesException(String message) {
        super(message);
    }
    
}
