package org.interledger.cryptoconditions.types;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;
import org.interledger.cryptoconditions.der.DerOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Implementation of a fulfillment based on a number of subconditions and subfulfillments.
 */
public class ThresholdSha256Fulfillment implements Fulfillment {

  private ThresholdSha256Condition condition;
  private Condition[] subconditions;
  private Fulfillment[] subfulfillments;

  /**
   * Constructs an instance of the fulfillment.
   * 
   * @param subconditions A set of conditions that this fulfillment relates to.
   * @param subfulfillments A set of subfulfillments this fulfillment relates to.
   */
  public ThresholdSha256Fulfillment(Condition[] subconditions, Fulfillment[] subfulfillments) {
    this.subconditions = new Condition[subconditions.length];
    System.arraycopy(subconditions, 0, this.subconditions, 0, subconditions.length);

    // TODO Clone each fulfillment?
    this.subfulfillments = new Fulfillment[subfulfillments.length];
    System.arraycopy(subfulfillments, 0, this.subfulfillments, 0, subfulfillments.length);
  }

  @Override
  public ConditionType getType() {
    return ConditionType.THRESHOLD_SHA256;
  }

  public int getThreshold() {
    return subfulfillments.length;
  }

  /**
   * Returns a copy of the subconditions linked to this fulfillment.
   */
  public Condition[] getSubconditions() {
    Condition[] subconditions = new Condition[this.subconditions.length];
    System.arraycopy(this.subconditions, 0, subconditions, 0, this.subconditions.length);
    return subconditions;
  }

  /**
   * Returns a copy of the subfulfillments linked to this fulfillment.
   */
  public Fulfillment[] getSubfulfillments() {
    Fulfillment[] subfulfillments = new Fulfillment[this.subfulfillments.length];
    System.arraycopy(this.subfulfillments, 0, subfulfillments, 0, this.subfulfillments.length);
    return subfulfillments;
  }

  @Override
  public byte[] getEncoded() {
    try {
      // Build subfulfillment sequence
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      for (int i = 0; i < subfulfillments.length; i++) {
        baos.write(subfulfillments[i].getEncoded());
      }
      baos.close();
      byte[] fulfillmentsBuffer = baos.toByteArray();

      // Wrap SET OF
      baos = new ByteArrayOutputStream();
      DerOutputStream out = new DerOutputStream(baos);
      out.writeTaggedConstructedObject(0, fulfillmentsBuffer);
      out.close();
      fulfillmentsBuffer = baos.toByteArray();

      // Build subcondition sequence
      baos = new ByteArrayOutputStream();
      for (int i = 0; i < subconditions.length; i++) {
        baos.write(subconditions[i].getEncoded());
      }
      out.close();
      byte[] conditionsBuffer = baos.toByteArray();

      // Wrap SET OF
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeTaggedConstructedObject(1, conditionsBuffer);
      out.close();
      conditionsBuffer = baos.toByteArray();

      byte[] buffer = new byte[fulfillmentsBuffer.length + conditionsBuffer.length];
      System.arraycopy(fulfillmentsBuffer, 0, buffer, 0, fulfillmentsBuffer.length);
      System.arraycopy(conditionsBuffer, 0, buffer, fulfillmentsBuffer.length,
          conditionsBuffer.length);

      // Wrap CHOICE
      baos = new ByteArrayOutputStream();
      out = new DerOutputStream(baos);
      out.writeTaggedConstructedObject(getType().getTypeCode(), buffer);
      out.close();

      return baos.toByteArray();

    } catch (IOException ioe) {
      throw new UncheckedIOException("DER Encoding Error", ioe);
    }
  }

  @Override
  public ThresholdSha256Condition getCondition() {
    if (condition == null) {

      // Copy all subconditions into another array along with the conditions *derived* from all
      // subfulfillments
      Condition[] allConditions = new Condition[subconditions.length + subfulfillments.length];
      System.arraycopy(subconditions, 0, allConditions, 0, subconditions.length);
      int idx = subconditions.length;
      for (int i = 0; i < subfulfillments.length; i++) {
        allConditions[idx] = subfulfillments[i].getCondition();
        idx++;
      }
      condition = new ThresholdSha256Condition(subfulfillments.length, allConditions);
    }
    return condition;
  }

  @Override
  public boolean verify(Condition condition, byte[] message) {

    if (condition == null) {
      throw new IllegalArgumentException(
          "Can't verify a ThresholdSha256Fulfillment against an null condition.");
    }

    if (!(condition instanceof ThresholdSha256Condition)) {
      throw new IllegalArgumentException(
          "Must verify a ThresholdSha256Fulfillment against ThresholdSha256Condition.");
    }

    if (!getCondition().equals(condition)) {
      return false;
    }

    for (int i = 0; i < subfulfillments.length; i++) {
      Condition subcondition = subfulfillments[i].getCondition();
      if (!subfulfillments[i].verify(subcondition, message)) {
        return false;
      }
    }

    return true;
  }

}
