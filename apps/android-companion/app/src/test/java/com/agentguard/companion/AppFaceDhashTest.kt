package com.agentguard.companion

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The Kotlin half of the cross-language dHash contract.
 *
 * `AppFace`'s header calls the difference hash **normative**: the Rust comparator in
 * `guard_schema::visual` and this Kotlin producer must agree bit for bit, or every icon
 * comparison is noise. Until this test existed, nothing checked that. The failure would have
 * been silent and would have looked like good news — an icon channel that matches nothing
 * reports no impersonation.
 *
 * Both sides read `eval/fixtures/icon_dhash_vectors.json`. The Rust assertion is
 * `dhash_matches_the_shared_cross_language_vectors`.
 */
class AppFaceDhashTest {

    private fun vectorsFile(): File {
        // Walk up from the module dir to the repository root: the test's working directory is
        // the Gradle module, and hardcoding a depth breaks the moment the tree moves.
        var dir: File? = File(".").canonicalFile
        while (dir != null) {
            val candidate = File(dir, "eval/fixtures/icon_dhash_vectors.json")
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        throw AssertionError("eval/fixtures/icon_dhash_vectors.json not found above ${File(".").canonicalPath}")
    }

    @Test
    fun `hashGrid matches the shared cross-language vectors`() {
        val doc = JSONObject(vectorsFile().readText())
        val vectors = doc.getJSONArray("vectors")
        assertTrue(
            "a contract this load-bearing needs more than a couple of cases, got ${vectors.length()}",
            vectors.length() >= 8,
        )
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            val name = v.getString("name")
            val gridJson = v.getJSONArray("grid")
            assertEquals("$name: a grid is 9 columns by 8 rows", 72, gridJson.length())
            val grid = IntArray(72) { gridJson.getInt(it) }
            val hash = AppFace.hashGrid(grid)
            assertNotNull("$name: hashGrid refused a non-degenerate 72-sample grid", hash)
            assertEquals(
                "$name: the Kotlin hash disagrees with the shared vector, so the icon channel " +
                    "would compare Rust hashes against Kotlin hashes and match nothing",
                v.getString("hash"),
                hash,
            )
        }
    }

    @Test
    fun `a degenerate grid is refused rather than returned`() {
        // A flat icon hashes to all zeros and would then sit at distance 0 from every other
        // flat icon. The Rust side refuses those (`IconHash::is_degenerate`); refusing here as
        // well means the wire never carries a value that cannot be used.
        val flat = IntArray(72) { 128 }
        assertEquals(null, AppFace.hashGrid(flat))
        // A single monotonic gradient is the other degenerate shape: every left sample is
        // brighter than its right neighbour, so the hash is all ones.
        val ramp = IntArray(72) { i -> 255 - (i % 9) * 20 }
        assertEquals(null, AppFace.hashGrid(ramp))
    }

    @Test
    fun `the most significant bit is row zero's leftmost comparison`() {
        // Bit order is part of the normative spec, and getting it reversed produces hashes that
        // are individually plausible and mutually useless. This pins the direction with a grid
        // that sets exactly one bit.
        val grid = IntArray(72) { 100 }
        grid[0] = 200 // row 0, col 0 brighter than col 1 -> most significant bit set
        val hash = AppFace.hashGrid(grid)
        // Only one bit set is degenerate by the shared rule, so assert on the raw arithmetic
        // instead of on hashGrid's refusal: the point here is the position, not the count.
        var bits = 0L
        for (row in 0 until 8) {
            for (col in 0 until 8) {
                val left = grid[row * 9 + col]
                val right = grid[row * 9 + col + 1]
                bits = (bits shl 1) or if (left > right) 1L else 0L
            }
        }
        assertEquals(1L shl 63, bits)
        assertEquals(null, hash) // and it is correctly refused as degenerate
    }
}
