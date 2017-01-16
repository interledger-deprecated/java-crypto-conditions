package org.interledger.cryptoconditions.test;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown=true)
public class TestVectorJson {
  private String type;
  private String preimage;
  private int maxMessageLength;
  private String prefix;
  
  
  @JsonProperty
  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  @JsonProperty
  public String getPreimage() {
    return preimage;
  }

  public void setPreimage(String preimage) {
    this.preimage = preimage;
  }
  
  @JsonProperty
  public int getMaxMessageLength() {
    return maxMessageLength;
  }

  public void setMaxMessageLength(int maxMessageLength) {
    this.maxMessageLength = maxMessageLength;
  }

  @JsonProperty
  public String getPrefix() {
    return prefix;
  }

  public void setPrefix(String prefix) {
    this.prefix = prefix;
  }
}
