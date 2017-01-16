package org.interledger.cryptoconditions.test;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TestVector {
  private TestVectorJson json;
  private long cost;
  private List<String> subtypes;
  private String fingerprintContents;
  private String fulfillment;
  private String conditionBinary;
  private String conditionUri;
  private String message;

  @JsonProperty
  public TestVectorJson getJson() {
    return json;
  }

  public void setJson(TestVectorJson json) {
    this.json = json;
  }
  
  @JsonProperty
  public long getCost() {
    return cost;
  }

  public void setCost(long cost) {
    this.cost = cost;
  }
  
  @JsonProperty
  public List<String> getSubtypes() {
    return subtypes;
  }

  public void setSubtypes(List<String> subtypes) {
    this.subtypes = subtypes;
  }


  @JsonProperty
  public String getFingerprintContents() {
    return fingerprintContents;
  }

  public void setFingerprintContents(String fingerprintContents) {
    this.fingerprintContents = fingerprintContents;
  }

  @JsonProperty
  public String getFulfillment() {
    return fulfillment;
  }

  public void setFulfillment(String fulfillment) {
    this.fulfillment = fulfillment;
  }

  @JsonProperty
  public String getConditionBinary() {
    return conditionBinary;
  }

  public void setConditionBinary(String conditionBinary) {
    this.conditionBinary = conditionBinary;
  }

  @JsonProperty
  public String getConditionUri() {
    return conditionUri;
  }

  public void setConditionUri(String conditionUri) {
    this.conditionUri = conditionUri;
  }

  @JsonProperty
  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }
}
