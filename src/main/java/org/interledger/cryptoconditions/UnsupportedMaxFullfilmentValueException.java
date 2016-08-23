package org.interledger.cryptoconditions;

/**
 * Thrown by implementations that encounter a max fulfillment value that exceeds
 * the size considered safe to process
 * 
 * @author adrianhopebailie
 *
 */
public class UnsupportedMaxFullfilmentValueException extends UnsupportedConditionException {

	private static final long serialVersionUID = 6076981317066854350L;

	public UnsupportedMaxFullfilmentValueException(String message) {
		super(message);
	}

}
