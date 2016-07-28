package org.interledger.cryptoconditions.encoding;

public class IllegalLengthIndicatorException extends DecodingException {

	private static final long serialVersionUID = 2076963320466312387L;

	public IllegalLengthIndicatorException(String message) {
		super(message);
	}

}
