package org.interledger.cryptoconditions.uri;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.types.Ed25519Sha256Condition;
import org.interledger.cryptoconditions.types.PrefixSha256Condition;
import org.interledger.cryptoconditions.types.PreimageSha256Condition;
import org.interledger.cryptoconditions.types.RsaSha256Condition;
import org.interledger.cryptoconditions.types.ThresholdSha256Condition;

/**
 * This class is responsible for parsing a uri-formatted crypto-condition
 */
public class CryptoConditionUri {
  
  //This is a stricter version based on limitations of the current
  //implementation. Specifically, we can't handle bitmasks greater than 32 bits.
  public static final String SCHEME_PREFIX = "ni://";
  public static final String HASH_FUNCTION_NAME = "sha-256";
  
  public static final String CONDITION_REGEX_STRICT = "^" + SCHEME_PREFIX + "([A-Za-z0-9_-]?)/" + HASH_FUNCTION_NAME + ";([a-zA-Z0-9_-]{0,86})\\?(.+)$";
  
  public static class QueryParams {
    public static final String COST = "cost";
    public static final String TYPE = "fpt";
    public static final String SUBTYPES = "subtypes";
  }
  
  /**
   * Parses a URI formatted crypto-condition
   *
   * @param uri
   *  The crypto-condition formatted as a uri.
   *  
   * @return
   *  The crypto condition
   */
  public static Condition parse(URI uri) throws URIEncodingException {
    //based strongly on the five bells implementation at 
    //https://github.com/interledgerjs/five-bells-condition (7b6a97990cd3a51ee41b276c290e4ae65feb7882)
    
    if (!"ni".equals(uri.getScheme())) {
      throw new URIEncodingException("Serialized condition must start with 'ni:'");
    }
    
    //the regex covers the entire uri format including the 'ni:' scheme
    Matcher m = Pattern.compile(CONDITION_REGEX_STRICT).matcher(uri.toString());
    
    if (!m.matches()) {
      throw new URIEncodingException("Invalid condition format");
    }
    
    Map<String, List<String>> queryParams = null;
    try {
      queryParams = splitQuery(uri.getQuery());
    } catch (UnsupportedEncodingException x) {
      throw new URIEncodingException("Invalid condition format");
    }    
    
    if(!queryParams.containsKey(QueryParams.TYPE)){
      throw new URIEncodingException("No fingerprint type provided");
    }
    
    ConditionType type = ConditionType.fromString(queryParams.get(QueryParams.TYPE).get(0));
    
    long cost = 0;
    try {
      cost = Long.parseLong(queryParams.get(QueryParams.COST).get(0));
    } catch (NumberFormatException | NullPointerException x) {
      throw new URIEncodingException("No or invalid cost provided");
    }
    
    byte[] fingerprint = Base64.getUrlDecoder().decode(m.group(2));
    
    EnumSet<ConditionType> subtypes = null;
    if (type == ConditionType.PREFIX_SHA256 || type == ConditionType.THRESHOLD_SHA256) {

      if(!queryParams.containsKey(QueryParams.SUBTYPES)){
        throw new URIEncodingException("No subtypes provided");
      }
      
      subtypes = ConditionType.getEnumOfTypesFromString(queryParams.get(QueryParams.SUBTYPES).get(0));
    }

    switch (type) {
      case PREIMAGE_SHA256:
        return new PreimageSha256Condition(fingerprint, cost);
      case PREFIX_SHA256:
        return new PrefixSha256Condition(fingerprint, cost, subtypes);
      case THRESHOLD_SHA256:
        return new ThresholdSha256Condition(fingerprint, cost, subtypes);
      case RSA_SHA256:
        return new RsaSha256Condition(fingerprint, cost);
      case ED25519_SHA256:
        return new Ed25519Sha256Condition(fingerprint, cost);
       default:
         throw new URIEncodingException("No or invalid type provided");
    }
  }
  
  //Lightly adapted from http://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
  //so that we dont need an external library.
  private static Map<String, List<String>> splitQuery(String queryParams)
      throws UnsupportedEncodingException {
    final Map<String, List<String>> query_pairs = new LinkedHashMap<String, List<String>>();
    final String[] pairs = queryParams.split("&");
    for (String pair : pairs) {
      final int idx = pair.indexOf("=");
      final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
      if (!query_pairs.containsKey(key)) {
        query_pairs.put(key, new LinkedList<String>());
      }
      final String value = idx > 0 && pair.length() > idx + 1
          ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
      query_pairs.get(key).add(value);
    }
    return query_pairs;
  }
}

