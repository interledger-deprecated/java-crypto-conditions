package org.interledger.cryptoconditions;

/**
 * Represents a {@code Fulfillment} exception.
 *
 * @author mrmx
 */
public class FulfillmentException extends RuntimeException {

    /**
     * Constructs an instance of {@code FulfillmentException} with the specified
     * detail message.
     *
     * @param msg the detail message.
     */
    public FulfillmentException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of {@code FulfillmentException} with the specified
     * detail message and {@code Throwable} cause.
     *
     * @param msg the detail message.
     * @param cause the {@code Throwable} cause
     */
    public FulfillmentException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
