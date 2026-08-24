package com.agentguard.companion

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable

/**
 * The **display identity** of an observed app: its label and its icon (AgentScan §3.6).
 *
 * # Why this is a separate thing from [AppAttestor]
 *
 * `AppAttestor` answers "what is this app, cryptographically" — the signing certificate,
 * which the observed app cannot choose. This answers "what does this app look like", which
 * the observed app chooses entirely. AgentScan clones an icon and a name and reports 10/10
 * (100 %) success against three of the agents it tested, the highest rate in the paper,
 * because an agent driving a GUI decides which app it is in by looking at the screen.
 *
 * The two are only useful together, and only in one direction: the appearance is the
 * accusation and the certificate is the authority. Matching WeChat's icon never makes an app
 * WeChat. Matching WeChat's icon while *not being* WeChat is the finding. The engine-side
 * rule is `APP-LOOKALIKE`; see `guard_schema::visual` and docs/app-lookalike.md.
 *
 * # Read from the OS, not from the screen
 *
 * Both values come from `PackageManager` for a package name, not from the accessibility
 * tree. The distinction matters: a label read off the screen is chosen by whatever drew on
 * top, so a malicious overlay could make any app look like any other and produce a finding
 * against an innocent app. `getApplicationLabel` and `getApplicationIcon` are what the OS
 * itself would show in the launcher and the app switcher — still attacker-chosen, but chosen
 * by the app whose identity is in question, which is the only thing worth accusing.
 *
 * # The hash
 *
 * A 64-bit difference hash, and the algorithm is **normative** — the Rust comparator and
 * this producer must agree bit for bit or the comparison is noise. It is stated once, in
 * `guard_schema::visual::IconHash`, and reimplemented here rather than shared, because the
 * companion does not load the Rust engine. `visual::IconHash::from_grid_9x8` is the
 * authority; [gridFrom] must produce the same grid and [hashGrid] the same bits.
 *
 * # Package visibility decides whether any of this runs
 *
 * `getApplicationLabel` and `getApplicationIcon` are subject to Android 11+ package-visibility
 * filtering, and the clone this whole mechanism exists to catch is by construction *not* one of
 * the registered packages the manifest lists. Without a MAIN/LAUNCHER `<queries>` entry both calls
 * throw for every clone and this file returns nulls forever — the mechanism computing a value the
 * engine never receives. The manifest has that entry, with the privacy trade written next to it;
 * [Face.error] makes the remaining failures visible instead of silent.
 *
 * That "reimplemented rather than shared" is the shape of iteration 17's worst defect (a
 * Rust redactor that never ran on the platform that needed it), so the risk is no longer left
 * as a careful reading. [hashGrid] is asserted against `eval/fixtures/icon_dhash_vectors.json`
 * by `AppFaceDhashTest`, and `guard_schema::visual`'s
 * `dhash_matches_the_shared_cross_language_vectors` asserts the Rust comparator against the
 * same file. A drift between the two languages now fails a test on both sides.
 *
 * What is still **not** covered by a test: [gridFrom], because it renders a `Drawable` through
 * `Canvas` and `Bitmap`, which are `Stub!` on the JVM. The rendering-to-grid step therefore
 * rests on a reading of the code; the grid-to-bits step does not.
 */
object AppFace {

    /** Icon render size: 9 columns × 8 rows, per the pinned dHash definition. */
    private const val COLS = 9
    private const val ROWS = 8

    /**
     * What the OS says an app looks like.
     *
     * [error] is why a null is null. It exists because an absent appearance and a *clean*
     * appearance are different claims and the engine must not confuse them — the same rule
     * `log_readers_enumerable` and `scan_errors` already follow. On API 30+ the common value is
     * `NameNotFoundException`, i.e. package-visibility filtering, and without the MAIN/LAUNCHER
     * query in the manifest that is what every clone returns.
     */
    data class Face(val label: String?, val iconDhash: String?, val error: String? = null)

    /**
     * The label and icon hash for [packageName], or nulls when `PackageManager` cannot see
     * it. A failure is silence, never a guess: an absent appearance produces no finding,
     * whereas a wrong one would accuse an innocent app.
     */
    fun read(context: Context, packageName: String): Face {
        val pm = context.packageManager
        var error: String? = null
        val label = try {
            val info = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(info).toString().takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            error = e.javaClass.simpleName
            null
        }
        val hash = try {
            hashGrid(gridFrom(pm.getApplicationIcon(packageName)))
        } catch (e: Exception) {
            if (error == null) error = e.javaClass.simpleName
            null
        }
        return Face(label, hash, error)
    }

    /**
     * Render a drawable to a [ROWS] × [COLS] greyscale grid, row-major.
     *
     * Drawn onto an opaque **white** canvas first. Launcher icons are mostly transparent
     * around a glyph, and compositing onto transparent black would make the padding the
     * darkest part of the image — every icon would then hash as "bright glyph on dark
     * ground" and the structure that distinguishes two icons would be the alpha channel's
     * shape rather than the artwork's. White matches what a launcher shows.
     */
    private fun gridFrom(drawable: Drawable): IntArray {
        // Render at a larger size and box-average down: sampling a 9×8 canvas directly makes
        // the hash depend on the drawable's own scaler, and two renderers disagreeing by one
        // pixel row flips bits.
        val side = 72
        val bitmap = if (drawable is BitmapDrawable && drawable.bitmap != null) {
            Bitmap.createScaledBitmap(drawable.bitmap, side, side, true)
        } else {
            Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888).also { bmp ->
                val canvas = Canvas(bmp)
                canvas.drawColor(Color.WHITE)
                drawable.setBounds(0, 0, side, side)
                drawable.draw(canvas)
            }
        }
        val pixels = IntArray(side * side)
        bitmap.getPixels(pixels, 0, side, 0, 0, side, side)
        val grid = IntArray(ROWS * COLS)
        for (row in 0 until ROWS) {
            for (col in 0 until COLS) {
                val x0 = col * side / COLS
                val x1 = (col + 1) * side / COLS
                val y0 = row * side / ROWS
                val y1 = (row + 1) * side / ROWS
                var sum = 0L
                var n = 0
                for (y in y0 until y1) {
                    for (x in x0 until x1) {
                        val p = pixels[y * side + x]
                        val a = Color.alpha(p)
                        // Composite onto white, so a transparent pixel reads as background
                        // rather than as black. `drawColor(WHITE)` above covers the canvas
                        // path; a pre-scaled BitmapDrawable keeps its own alpha.
                        val r = (Color.red(p) * a + 255 * (255 - a)) / 255
                        val g = (Color.green(p) * a + 255 * (255 - a)) / 255
                        val b = (Color.blue(p) * a + 255 * (255 - a)) / 255
                        // Rec. 601 luma, integer arithmetic so the result does not depend on
                        // floating-point rounding across ABIs.
                        sum += (299L * r + 587L * g + 114L * b) / 1000L
                        n++
                    }
                }
                grid[row * COLS + col] = if (n == 0) 0 else (sum / n).toInt()
            }
        }
        return grid
    }

    /**
     * The pinned dHash: per row, 8 comparisons of adjacent columns, bit set when the **left**
     * sample is strictly brighter; row 0's leftmost comparison is the most significant bit;
     * 16 lowercase hex characters.
     *
     * Returns null for a **degenerate** hash — fewer than 8 set or fewer than 8 clear bits.
     * A flat or single-gradient icon hashes to nearly all zeros or all ones and would then
     * match every other flat icon at distance 0. The Rust side refuses those too
     * (`IconHash::is_degenerate`); refusing here as well means the wire carries no value that
     * cannot be used.
     */
    /**
     * `internal` rather than `private` so `AppFaceDhashTest` can assert it against
     * `eval/fixtures/icon_dhash_vectors.json`.
     *
     * The header above calls this algorithm normative and notes there is **no test on this
     * file**. That is no longer true of this function, which is the one that had to match the
     * Rust comparator bit for bit.
     */
    internal fun hashGrid(grid: IntArray): String? {
        var bits = 0L
        for (row in 0 until ROWS) {
            for (col in 0 until COLS - 1) {
                val left = grid[row * COLS + col]
                val right = grid[row * COLS + col + 1]
                bits = (bits shl 1) or if (left > right) 1L else 0L
            }
        }
        val ones = java.lang.Long.bitCount(bits)
        if (ones < 8 || ones > 56) return null
        return String.format("%016x", bits)
    }

    /**
     * Per-package cache, for the same reason [AppAttestor.SignerCache] has one: the
     * accessibility service emits an event per screen change, and rendering an icon is far
     * more expensive than a binder call. A package's label and icon can change on update,
     * which restarts the app being observed; within a process lifetime, caching is sound.
     *
     * A failed read is cached too. On Android 11+ a package outside the companion's
     * `<queries>` list is permanently invisible, so retrying per frame would be a guaranteed
     * failure per frame.
     */
    class FaceCache(private val context: Context) {
        private val cache = HashMap<String, Face>()

        @Synchronized
        fun face(packageName: String): Face = cache.getOrPut(packageName) { read(context, packageName) }

        @Synchronized
        fun clear() = cache.clear()

        /** Metadata for an event, or an empty map when the OS told us nothing. */
        fun metadata(packageName: String?): Map<String, String> {
            if (packageName.isNullOrBlank()) return emptyMap()
            val out = LinkedHashMap<String, String>()
            val f = face(packageName)
            f.label?.let { out["app_label"] = it }
            f.iconDhash?.let { out["icon_dhash"] = it }
            // Only when nothing at all could be read: a partial read is not a failure worth
            // reporting, and an error key alongside a good label would read as one.
            if (f.label == null && f.iconDhash == null) {
                f.error?.let { out["face_error"] = it }
            }
            return out
        }
    }
}
