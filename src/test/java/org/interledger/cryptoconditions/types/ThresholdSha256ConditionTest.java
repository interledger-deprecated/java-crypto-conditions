package org.interledger.cryptoconditions.types;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.interledger.cryptoconditions.ConditionType.THRESHOLD_SHA256;

import com.google.common.io.BaseEncoding;

import org.hamcrest.CoreMatchers;
import org.interledger.cryptoconditions.Condition;
import org.junit.Test;

/**
 * Unit tests for {@link ThresholdSha256Condition}.
 */
public class ThresholdSha256ConditionTest extends AbstractCryptoConditionTest {

  /**
   * Tests concurrently creating an instance of {@link ThresholdSha256Condition}. This test
   * validates the fix for Github issue #40 where construction of this class was not thread-safe.
   *
   * @see "https://github.com/interledger/java-crypto-conditions/issues/40"
   * @see "https://github.com/junit-team/junit4/wiki/multithreaded-code-and-concurrency"
   */
  @Test
  public void testConstructionUsingMultipleThreads() throws Exception {
    final Runnable runnableTest = () -> {

      final PreimageSha256Condition preimageCondition = new PreimageSha256Condition(
          AUTHOR.getBytes());

      final ThresholdSha256Condition thresholdSha256Condition = new ThresholdSha256Condition(
          1, new Condition[]{preimageCondition}
      );

      assertThat(thresholdSha256Condition.getType(), is(THRESHOLD_SHA256));
      assertThat(thresholdSha256Condition.getCost(), CoreMatchers.is(1033L));
      assertThat(thresholdSha256Condition.getUri().toString(), is(
          "ni:///sha-256;W-kFFQRd_dtz60dK3Jq0wr-DEDWHLFh8D1TQHCTi75I?cost=1033&"
              + "fpt=threshold-sha-256&subtypes=preimage-sha-256"));

      assertThat(BaseEncoding.base64().encode(thresholdSha256Condition.getFingerprint()),
          is("W+kFFQRd/dtz60dK3Jq0wr+DEDWHLFh8D1TQHCTi75I="));
      assertThat(BaseEncoding.base64().encode(thresholdSha256Condition.getFingerprintContents()),
          is("MCyAAQGhJ6AlgCBjEgvXn574GWJrrBNHDMuo/bgLkhTNwoj1GUDp77vDnYEBCQ=="));
      assertThat(BaseEncoding.base64().encode(thresholdSha256Condition.getEncoded()),
          is("oiqAIFvpBRUEXf3bc+tHStyatMK/gxA1hyxYfA9U0Bwk4u+SgQIECYICB4A="));
    };

    this.runConcurrent(1, runnableTest);
    this.runConcurrent(runnableTest);
  }
}
