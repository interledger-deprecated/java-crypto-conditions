package org.interledger.cryptoconditions;

import static org.interledger.cryptoconditions.CryptoConditionType.THRESHOLD_SHA256;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * An implementation of {@link Fulfillment} for a crypto-condition fulfillment of type
 * "THRESHOLD-SHA-256" based upon a number of sub-conditions and sub-fulfillments.
 *
 * @see "https://datatracker.ietf.org/doc/draft-thomas-crypto-conditions/"
 */
public class ThresholdSha256Fulfillment extends FulfillmentBase<ThresholdSha256Condition>
    implements Fulfillment<ThresholdSha256Condition> {

  // TODO: Remove subconditions as a property...?
  private final List<Condition> subconditions;
  private final List<Fulfillment> subfulfillments;
  private final ThresholdSha256Condition condition;

  /**
   * Required-args Constructor.
   *
   * @param subconditions   An ordered {@link List} of sub-conditions that this
   *                        fulfillment contains.
   * @param subfulfillments An ordered {@link List} of sub-fulfillments that this
   *                        fulfillment contains.
   */
  public ThresholdSha256Fulfillment(
      final List<Condition> subconditions, final List<Fulfillment> subfulfillments
  ) {
    super(THRESHOLD_SHA256);
    // Create a new Collections that are unmodifiable so that neither the backing collections
    // nor the actual Collections can be mutated. This works so long as fulfillments are immutable,
    // which they are.
    this.subconditions = Collections.unmodifiableList(new ArrayList<>(subconditions));
    this.subfulfillments = Collections.unmodifiableList(new ArrayList<>(subfulfillments));
    this.condition = this.constructCondition();
  }

  private ThresholdSha256Condition constructCondition() {
    final List<Condition> allConditions = new ArrayList<>();

    // Add all subconditions...
    allConditions.addAll(this.subconditions);

    // Add all derived subconditions...
    allConditions.addAll(
        this.subfulfillments.stream().map(Fulfillment::getCondition).collect(Collectors.toList())
    );

    return new ThresholdSha256Condition(this.subfulfillments.size(), allConditions);
  }

  /**
   * Accessor for the subconditions of this fulfillment.
   *
   * @return An unordered {@link List} of zero or more sub-conditions.
   */
  public final List<Condition> getSubconditions() {
    return this.subconditions;
  }

  /**
   * Accessor for the subfulfillments of this fulfillment.
   *
   * @return An unordered {@link List} of zero or more sub-fulfillments.
   */
  public final List<Fulfillment> getSubfulfillments() {
    return this.subfulfillments;
  }

  @Override
  public ThresholdSha256Condition getCondition() {
    return this.condition;
  }

  @Override
  public boolean verify(final ThresholdSha256Condition condition, final byte[] message) {
    Objects.requireNonNull(condition,
        "Can't verify a ThresholdSha256Fulfillment against an null condition.");
    Objects.requireNonNull(message, "Message must not be null!");

    if (!getCondition().equals(condition)) {
      return false;
    }

    for (int i = 0; i < subfulfillments.size(); i++) {
      Condition subcondition = subfulfillments.get(i).getCondition();
      if (!subfulfillments.get(i).verify(subcondition, message)) {
        return false;
      }
    }

    return true;
  }

  @Override
  public boolean equals(Object object) {
    if (this == object) {
      return true;
    }
    if (object == null || getClass() != object.getClass()) {
      return false;
    }
    if (!super.equals(object)) {
      return false;
    }

    ThresholdSha256Fulfillment that = (ThresholdSha256Fulfillment) object;

    if (!subconditions.equals(that.subconditions)) {
      return false;
    }
    if (!subfulfillments.equals(that.subfulfillments)) {
      return false;
    }
    return condition.equals(that.condition);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + subconditions.hashCode();
    result = 31 * result + subfulfillments.hashCode();
    result = 31 * result + condition.hashCode();
    return result;
  }

  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("ThresholdSha256Fulfillment{");
    sb.append("\nsubconditions=").append(subconditions);
    sb.append(", \n\tsubfulfillments=").append(subfulfillments);
    sb.append(", \n\tcondition=").append(condition);
    sb.append(", \n\ttype=").append(getType());
    sb.append("\n}");
    return sb.toString();
  }
}
