package com.agentguard.companion

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EventLogRetentionTest {
    private val now = 10_000_000_000L
    private fun e(name: String, bytes: Long, ageMs: Long) =
        EventLogRetention.Entry(name, bytes, now - ageMs)

    @Test
    fun `old files go, current session file never goes`() {
        val entries = listOf(
            e("session-cur.jsonl", 1, 0),
            e("session-old.jsonl", 1, EventLogRetention.MAX_AGE_MS + 1),
            e("session-fresh.jsonl", 1, 1000),
        )
        val del = EventLogRetention.select(entries, now, "session-cur.jsonl")
        assertEquals(listOf("session-old.jsonl"), del)
    }

    @Test
    fun `too many files drops the oldest beyond the cap`() {
        val entries = (0 until EventLogRetention.MAX_FILES + 5).map { i -> e("s$i.jsonl", 10, i * 1000L) }
        val del = EventLogRetention.select(entries, now, null)
        assertEquals(5, del.size)
        // 删的是最旧的五个(age 最大的 i)。
        assertTrue(del.all { it.removePrefix("s").removeSuffix(".jsonl").toInt() >= EventLogRetention.MAX_FILES })
    }

    @Test
    fun `total size cap deletes from the oldest until under the cap`() {
        val big = EventLogRetention.MAX_TOTAL_BYTES / 2 + 1
        val entries = listOf(e("a.jsonl", big, 3000), e("b.jsonl", big, 2000), e("c.jsonl", 10, 1000))
        val del = EventLogRetention.select(entries, now, null)
        assertEquals(listOf("a.jsonl"), del)
    }

    @Test
    fun `current session file is not counted against age or count but does take a slot`() {
        val entries = (0 until EventLogRetention.MAX_FILES).map { i -> e("s$i.jsonl", 1, (i + 1) * 1000L) } +
            e("cur.jsonl", 1, EventLogRetention.MAX_AGE_MS + 99)
        val del = EventLogRetention.select(entries, now, "cur.jsonl")
        assertFalse(del.contains("cur.jsonl"))
        assertEquals("当前会话占一个名额,所以要多删一个旧的", 1, del.size)
    }

    @Test
    fun `nothing to delete on a small fresh set`() {
        val entries = listOf(e("a.jsonl", 1, 1000), e("b.jsonl", 1, 2000))
        assertTrue(EventLogRetention.select(entries, now, "a.jsonl").isEmpty())
    }
}
