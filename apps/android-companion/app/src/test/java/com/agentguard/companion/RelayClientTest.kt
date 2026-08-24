package com.agentguard.companion

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Reading the engine's answer.
 *
 * The relay used to drain `responseCode` and discard it, which made confirmation a
 * desktop-only feature: the phone could report a payment sheet, the engine could decide
 * `Block` with `require_confirm`, and nothing on the phone would ever know. These tests cover
 * the parse, including the case that matters most — a response missing the field must not
 * invent a confirmation.
 */
class RelayClientTest {

    @Test
    fun `a confirm verdict is read out of the response`() {
        val body = """
            {"ok":true,"ingested":1,"decisions":[
              {"event_id":"e1","action":"Block","rule_id":"CRIT-001","severity":"Critical",
               "require_confirm":true,"human_message":"Confirm the payment"}]}
        """.trimIndent()
        val v = RelayClient.parseVerdicts(body)
        assertEquals(1, v.size)
        assertEquals("CRIT-001", v[0].ruleId)
        assertTrue(v[0].requireConfirm)
        assertEquals("Confirm the payment", v[0].humanMessage)
    }

    @Test
    fun `a missing require_confirm defaults to false and not to true`() {
        // An older host that does not send the field must not cause a confirmation prompt the
        // engine never asked for: a guard that interrupts on every event is a guard that gets
        // turned off.
        val body = """{"decisions":[{"event_id":"e1","action":"Allow","rule_id":"ALLOW"}]}"""
        val v = RelayClient.parseVerdicts(body)
        assertEquals(1, v.size)
        assertFalse(v[0].requireConfirm)
    }

    @Test
    fun `a malformed or empty response yields no verdicts rather than throwing`() {
        // The relay runs on a worker thread inside an accessibility service. An exception here
        // would take out the observer for the rest of the session.
        assertTrue(RelayClient.parseVerdicts("").isEmpty())
        assertTrue(RelayClient.parseVerdicts("not json").isEmpty())
        assertTrue(RelayClient.parseVerdicts("{}").isEmpty())
        assertTrue(RelayClient.parseVerdicts("""{"decisions":[]}""").isEmpty())
        assertTrue(RelayClient.parseVerdicts("""{"decisions":"nope"}""").isEmpty())
    }

    @Test
    fun `multiple decisions are all returned in order`() {
        val body = """
            {"decisions":[
              {"event_id":"a","action":"Allow","rule_id":"ALLOW","require_confirm":false},
              {"event_id":"b","action":"Alert","rule_id":"PRIV-FM","require_confirm":false},
              {"event_id":"c","action":"Block","rule_id":"CRIT-001","require_confirm":true}]}
        """.trimIndent()
        val v = RelayClient.parseVerdicts(body)
        assertEquals(listOf("a", "b", "c"), v.map { it.eventId })
        assertEquals(1, v.count { it.requireConfirm })
    }
}
