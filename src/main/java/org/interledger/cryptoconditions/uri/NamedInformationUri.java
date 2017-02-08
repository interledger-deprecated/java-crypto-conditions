package org.interledger.cryptoconditions.uri;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

public class NamedInformationUri {

  public static final String SCHEME = "ni";
  public static final String SCHEME_PREFIX = SCHEME + "://";
  public static final String REGEX_STRICT = "^" + SCHEME_PREFIX + "([A-Za-z0-9_-]?)/" + getHashFunctionRegexGroup() + ";([a-zA-Z0-9_-]{0,86})\\?(.+)$";

  //TODO Could implement a parse function but for now it's probably faster to just parse the condition directly and not wrap that around an ni URI parser
  
  public static URI getUri(HashFunction hashFunction, byte[] hash,
      Map<String, String> queryStringParams) {

    StringBuilder sb = new StringBuilder();
    sb.append(SCHEME_PREFIX) // Scheme prefix
        // No authority portion
        .append("/") // Path prefix
        .append(hashFunction.getName()).append(";") // Hash function name
        .append(Base64.getUrlEncoder().withoutPadding().encodeToString(hash)); //Hash
    
    if(!queryStringParams.isEmpty()) {
      sb.append("?");
      queryStringParams.forEach((key, value) -> {
        try {
          sb.append(key).append("=").append(URLEncoder.encode(queryStringParams.get(key), "UTF-8"));
          sb.append("&");
        } catch (UnsupportedEncodingException e) {
          throw new RuntimeException(e);
        }
      });
      
      //Delete the trailing "&"
      sb.deleteCharAt(sb.length() - 1);
    }
    
    return URI.create(sb.toString());
    
  }
  
  private static String getHashFunctionRegexGroup() {
    return "(" + String.join("|", Arrays.stream(HashFunction.values()).map(s -> s.getName()).toArray(String[]::new))  + ")";
  }
  
  /**
   * From https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
   * @author adrianhopebailie
   *
   */
  public enum HashFunction {
    MD2("md2", "1.2.840.113549.2.2"),
    MD5("md5", "1.2.840.113549.2.5"),
    SHA_1("sha-1", "1.3.14.3.2.26"),
    SHA_224("sha-224", "2.16.840.1.101.3.4.2.4"),
    SHA_256("sha-256", "2.16.840.1.101.3.4.2.1"),
    SHA_384("sha-384", "2.16.840.1.101.3.4.2.2"),
    SHA_512("sha-512", "2.16.840.1.101.3.4.2.3");
    
    private String name;
    private String oid;
    
    HashFunction(String name, String oid) {
      this.name = name;
      this.oid = oid;
    }
    
    public String getName() {
      return name;
    }
    
    public String getOid() {
      return oid;
    }
    
  }

}
