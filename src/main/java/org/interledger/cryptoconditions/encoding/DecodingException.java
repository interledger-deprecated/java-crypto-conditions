package org.interledger.cryptoconditions.encoding;

public abstract class DecodingException extends Exception {
	
	private static final long serialVersionUID = 7363031559695469596L;

	public DecodingException(String message) {
		super(message);
	}

}
