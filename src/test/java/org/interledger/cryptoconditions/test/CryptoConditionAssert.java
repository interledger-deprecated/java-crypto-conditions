package org.interledger.cryptoconditions.test;

import static org.junit.Assert.assertEquals;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.Fulfillment;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class CryptoConditionAssert {

  /**
   * Tests that the given URIs are equal.
   * 
   * @param message A detail message to record if the assertion fails.
   * @param expected    The expected URI
   * @param actual  The URI to test against the one expected.
   */
  public static void assertUriEqual(String message, URI expected, URI actual)
      throws UnsupportedEncodingException {

    if (expected.equals(actual)) {
      return;
    }

    // Hierarchical URIs with different query strings so decompose and test them
    if (!actual.isOpaque() && (expected.getQuery() != null)
        && !expected.getRawQuery().equals(actual.getRawQuery())) {

      Map<String, List<String>> expectedQuery = splitQuery(expected.getRawQuery());
      Map<String, List<String>> actualQuery = splitQuery(actual.getRawQuery());

      for (String key : expectedQuery.keySet()) {
        List<String> expectedValues = expectedQuery.get(key);
        List<String> actualValues = actualQuery.get(key);

        if (!expectedValues.equals(actualValues)) {
          if (actualValues == null) {
            throw new AssertionError(message + " - expected query string param [" + key
                + "] with the values " + "[" + String.join(",", expectedValues)
                + "] but got null [Query: " + actual.getRawQuery() + "].");
          }
          throw new AssertionError(message + " - expected query string param [" + key
              + "] with the values " + "[" + String.join(",", expectedValues) + "] but got ["
              + String.join(",", actualValues) + "] from [Query: " + actual.getRawQuery() + "].");
        }
        actualQuery.remove(key);
      }

      if (actualQuery.size() > 0) {
        throw new AssertionError(message + " - unexpected query string params ["
            + String.join(",", actualQuery.keySet()) + "]");
      }

      // If the query strings are actually the same then let's compare the URIs again ignoring query
      // string
      try {
        URI expectedNoQuery =
            new URI(expected.getScheme(), expected.getUserInfo(), expected.getHost(),
                expected.getPort(), expected.getPath(), null, expected.getFragment());
        URI actualNoQuery = new URI(actual.getScheme(), actual.getUserInfo(), actual.getHost(),
            actual.getPort(), actual.getPath(), null, actual.getFragment());
        assertEquals(expectedNoQuery, actualNoQuery);
      } catch (URISyntaxException e) {
        throw new RuntimeException("Unexpected error comparing URIs.", e);
      } catch (AssertionError e) {
        throw new AssertionError(message + "URIs don't match even after stripping query string.",
            e);
      }

    }

  }

  // Lightly adapted from
  // http://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
  // so that we dont need an external library.
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

  /**
   * Asserts the the set of types given are equal.
   * @param message A detail message to record if the assertion fails.
   * @param expected    A list of expected condition types.
   * @param actual  A set of condition types to compare against the ones expected.
   */
  public static void assertSetOfTypesIsEqual(String message, List<String> expected,
      EnumSet<ConditionType> actual) {
    EnumSet<ConditionType> expectedSet = ConditionType
        .getEnumOfTypesFromString(String.join(",", expected.toArray(new String[expected.size()])));

    if (!expectedSet.containsAll(actual)) {
      throw new AssertionError(message + " - expected does not contain all values from actual.");
    }
    expectedSet.removeAll(actual);
    if (!expectedSet.isEmpty()) {
      throw new AssertionError(message + " - expected contains values not in actual.");
    }
  }

  /**
   * Asserts that the fulfillment is valid for the given condition.
   * 
   * @param assertionMessage A detail message to record if the assertion fails.
   * @param fulfillment The fulfillment to examine
   * @param condition   The condition that the fufillment is expected to fulfill.
   * @param message A message used to verify the fulfillment against the condition.
   */
  public static void assertFulfillmentIsvalidForCondition(String assertionMessage,
      Fulfillment fulfillment, Condition condition, byte[] message) {
    if (!fulfillment.verify(condition, message)) {
      if (!fulfillment.getCondition().equals(condition)) {
        throw new AssertionError(
            assertionMessage + " - derived condition is not equal to generated condition.");
      }
      throw new AssertionError(assertionMessage + " - verify return false.");
    }
  }

}
