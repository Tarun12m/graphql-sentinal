package com.gqlsentinel.modules;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the false-positive-sensitive core of the field-authorization module. These cases encode
 * the decisions an interviewer would probe: when do we flag, and — more importantly — when do we
 * deliberately stay silent?
 */
class AuthzComparatorTest {

    private final AuthzComparator comparator = new AuthzComparator();

    @Test
    void identicalPrivilegedDataLeakedToLowerPrincipalIsAHighConfidenceLeak() {
        String priv = "{\"data\":{\"me\":{\"ssn\":\"123-45-6789\"}}}";
        String lower = "{\"data\":{\"me\":{\"ssn\":\"123-45-6789\"}}}";

        AuthzComparator.Result r = comparator.compare(200, priv, 200, lower);

        assertTrue(r.isLeak());
        assertEquals(1, r.leakedFields().size());
        assertEquals("me", r.leakedFields().get(0).name());
        assertTrue(r.leakedFields().get(0).identicalValue(), "same value ⇒ definite leak");
    }

    @Test
    void http403IsTreatedAsProperDenialNotALeak() {
        String priv = "{\"data\":{\"secret\":\"x\"}}";
        AuthzComparator.Result r = comparator.compare(200, priv, 403, "Forbidden");
        assertEquals(AuthzComparator.Outcome.DENIED, r.outcome());
        assertFalse(r.isLeak());
    }

    @Test
    void graphqlAuthErrorWithNoDataIsDenial() {
        String priv = "{\"data\":{\"secret\":\"x\"}}";
        String lower = "{\"errors\":[{\"message\":\"You are not authorized to view this\"}],\"data\":null}";
        AuthzComparator.Result r = comparator.compare(200, priv, 200, lower);
        assertEquals(AuthzComparator.Outcome.DENIED, r.outcome());
        assertFalse(r.isLeak());
    }

    @Test
    void noPrivilegedBaselineDataMeansNothingToLeak() {
        AuthzComparator.Result r = comparator.compare(200, "{\"data\":{}}", 200, "{\"data\":{\"a\":1}}");
        assertEquals(AuthzComparator.Outcome.NO_BASELINE, r.outcome());
    }

    @Test
    void differentNonNullValueIsAWeakerReachabilityFinding() {
        // Lower principal sees their OWN record for the same field — reachable but maybe row-scoped.
        String priv = "{\"data\":{\"me\":{\"id\":\"1\"}}}";
        String lower = "{\"data\":{\"me\":{\"id\":\"2\"}}}";
        AuthzComparator.Result r = comparator.compare(200, priv, 200, lower);
        assertTrue(r.isLeak());
        assertFalse(r.leakedFields().get(0).identicalValue(), "different value ⇒ downgraded");
    }

    @Test
    void fieldErroredForLowerPrincipalIsNotCountedAsLeaked() {
        String priv = "{\"data\":{\"admin\":{\"k\":\"v\"},\"pub\":1}}";
        String lower = "{\"data\":{\"admin\":null,\"pub\":1},"
                + "\"errors\":[{\"message\":\"denied\",\"path\":[\"admin\"]}]}";
        AuthzComparator.Result r = comparator.compare(200, priv, 200, lower);
        // 'admin' is denied via error+null; only 'pub' remains and it leaked.
        assertTrue(r.isLeak());
        assertEquals(1, r.leakedFields().size());
        assertEquals("pub", r.leakedFields().get(0).name());
    }

    @Test
    void malformedLowerResponseIsInconclusiveNotAFinding() {
        AuthzComparator.Result r = comparator.compare(200, "{\"data\":{\"a\":1}}", 200, "<<not json>>");
        assertEquals(AuthzComparator.Outcome.INCONCLUSIVE, r.outcome());
        assertFalse(r.isLeak());
    }
}
