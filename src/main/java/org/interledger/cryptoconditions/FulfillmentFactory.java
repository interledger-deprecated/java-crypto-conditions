package org.interledger.cryptoconditions;

import java.lang.reflect.Constructor;


import org.interledger.cryptoconditions.encoding.Base64Url;
import org.interledger.cryptoconditions.types.FulfillmentPayload;

public class FulfillmentFactory {
	private static final String FULFILLMENT_REGEX = "^cf:([1-9a-f][0-9a-f]{0,3}|0):[a-zA-Z0-9_-]*$";
	private static final java.util.regex.Pattern p = java.util.regex.Pattern.compile(FULFILLMENT_REGEX);
	
	public static Fulfillment getFulfillmentFromURI(String URI){
		if (URI == null)
			throw new RuntimeException("serializedFulfillment == null");
		if ("".equals(URI.trim()))
			throw new RuntimeException("serializedFulfillment was an empy string");
		if (!URI.startsWith("cf:"))
			throw new RuntimeException("serializedFulfillment must start with 'cf:'");

		java.util.regex.Matcher m = p.matcher(URI);
		if (!m.matches())
			throw new RuntimeException(
					"serializedFulfillment '" + URI + "' doesn't match " + FulfillmentFactory.FULFILLMENT_REGEX);
		String[] pieces = URI.split(":");
		
		String BASE16Type = pieces[1];
		String BASE64URLPayload = (pieces.length == 3 ) ? pieces[2] : "" /*case empty payload*/;
		
		ConditionType type = ConditionType.valueOf(Integer.parseInt(BASE16Type, 16));
		FulfillmentPayload payload = new FulfillmentPayload(Base64Url.decode(BASE64URLPayload));

		// Get Fulfillment class (Sha256, PreimageSha256, ...)
		Class<?> clazz = FulfillmentRegistry.getClass(type);
		Constructor<?> constructor;
		try {
			constructor = clazz.getConstructor(ConditionType.class, FulfillmentPayload.class);
		} catch (NoSuchMethodException e) {
			
			throw new RuntimeException(clazz.getCanonicalName() +
					" doesn't look to implement constructor "+
					clazz.getSimpleName() + "(ConditionType type, byte[] payload)");
		}
		try {
			Fulfillment result = (Fulfillment)constructor.newInstance( type , payload);
			return result;
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}

	}

	/*
	 * 
	 */
	
}
