package org.interledger.cryptoconditions;

public abstract class UnsupportedConditionException extends Exception {

	private static final long serialVersionUID = -4173529087643312558L;

	public UnsupportedConditionException(String message) {
		super(message);
	}

}
