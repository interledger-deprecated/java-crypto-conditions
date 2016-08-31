package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import org.junit.Test;

import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionImpl;

public class TestConditionImpl {

	@Test
	public void testURISerialization() {
		String URICondition = "cc:2:1:x07W1xU1_oBcV9zUheOzspx6Beq8vgy0vYgBVifNV1Q:10";
		Condition cond = new ConditionImpl(URICondition);
		assertTrue(URICondition.equals(cond.toURI()));
	}

}
