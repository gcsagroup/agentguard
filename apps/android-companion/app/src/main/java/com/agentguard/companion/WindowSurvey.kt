package com.agentguard.companion

import android.accessibilityservice.AccessibilityService
import android.graphics.Rect
import android.view.accessibility.AccessibilityWindowInfo

/**
 * What windows are on screen, and whether one is covering another.
 *
 * # Why this exists
 *
 * `PayloadSerializer.overlayMarker` had no caller. `OVL-001`, `OVL-002` and the whole
 * transparent-overlay surface were therefore inert on Android — the platform where
 * AgentScan and (A)I Sees actually demonstrate the attack — while the coverage matrix
 * counted the surface as covered because the *desktop* adapter could produce markers.
 *
 * # Why the window list and not the pixels
 *
 * An accessibility service cannot read pixels, so opacity is not available and the desktop's
 * `low_opacity_ratio` heuristic has no analogue here. What it *can* read is authoritative in a
 * different way: `getWindows()` comes from the window manager, so the type, the layer and the
 * bounds are facts rather than inferences. A window of type
 * [AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY] drawn by something other than this
 * service, or a non-active window whose bounds contain the active window's, is a structural
 * statement that something is on top.
 *
 * # What it cannot see
 *
 * A window that declares itself non-accessible, and anything drawn by a process that has
 * excluded itself from the accessibility window list. So a clean survey is not proof of a
 * clean screen, which is why [Survey.enumerable] exists: an empty list from a call that
 * failed must not read the same as an empty list from a call that worked.
 *
 * **And it does not catch a phishing Activity** ((A)I Sees A3). A fake payment sheet launched
 * as a normal Activity *becomes* the active window, so it is the thing this scan takes as the
 * baseline and skips. The surface this covers is the draw-over-other-apps overlay — a window
 * on top of an active window it is not part of. A3 is covered, where it is covered at all, by
 * app identity: `APP-LOOKALIKE` and the signing-certificate pin. Saying so here rather than
 * letting the marker name imply otherwise, because the marker string this emits is the same
 * one the overlay rules match and it would be easy to read as covering both.
 */
object WindowSurvey {

    /**
     * A rectangle, free of `android.graphics`.
     *
     * `Rect`'s methods throw `Stub!` in a JVM unit test, so a `coverRatio` that took one could
     * only be exercised on a device — and this ratio *is* the overlay decision. The Android
     * type is converted at the boundary and the arithmetic is testable.
     */
    data class Box(val left: Int, val top: Int, val right: Int, val bottom: Int) {
        val width: Int get() = right - left
        val height: Int get() = bottom - top
    }

    /** A window worth reporting, and why. */
    data class Finding(
        val marker: String,
        val detail: String,
    )

    data class Survey(
        val findings: List<Finding>,
        /** Whether the window list could be read at all. */
        val enumerable: Boolean,
        val error: String? = null,
    )

    /** Marker strings the engine's overlay rules already match. */
    const val MARKER_OVERLAY = "[AG_TRANSPARENT_OVERLAY]"
    const val MARKER_FOREIGN_A11Y_OVERLAY = "[AG_FOREIGN_A11Y_OVERLAY]"

    /**
     * Minimum fraction of the active window a covering window must span before it is
     * reported.
     *
     * A keyboard, an autofill dropdown and a toast are all legitimately on top of the active
     * window, and reporting each one would drown the real finding. The published attack covers
     * the decision surface — a fake payment sheet over a real one — so it is large by
     * construction. The threshold is a false-negative choice made deliberately: a small
     * covering window is not reported, and that is a gap, not a clean result.
     */
    const val MIN_COVER_RATIO = 0.55f

    fun scan(service: AccessibilityService): Survey {
        val windows = try {
            service.windows ?: emptyList()
        } catch (e: Exception) {
            return Survey(emptyList(), enumerable = false, error = e.javaClass.simpleName)
        }
        if (windows.isEmpty()) {
            // Not an error and not clean: on some OEM builds the list is empty unless the
            // service declares `canRetrieveWindowContent`, and the caller has to be able to
            // tell that apart from a device with one window.
            return Survey(emptyList(), enumerable = false, error = "window list empty")
        }

        val ownPackage = service.packageName
        val active = windows.firstOrNull { it.isActive }
        val activeRect = active?.let { boxOf(it) }
        val findings = mutableListOf<Finding>()

        for (w in windows) {
            if (w === active) continue
            val rect = boxOf(w)
            val pkg = packageOf(w)

            // A foreign accessibility overlay is the strongest signal available here: it is a
            // window type only an accessibility service can create, and this service knows it
            // did not create it.
            if (w.type == AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY && pkg != ownPackage) {
                findings.add(
                    Finding(
                        MARKER_FOREIGN_A11Y_OVERLAY,
                        "accessibility overlay from ${pkg ?: "an unnamed package"} at " +
                            "${rect.left},${rect.top} ${rect.width}x${rect.height}",
                    ),
                )
                continue
            }

            if (activeRect == null) continue
            val ratio = coverRatio(rect, activeRect)
            if (ratio >= MIN_COVER_RATIO && !w.isFocused) {
                findings.add(
                    Finding(
                        MARKER_OVERLAY,
                        "window ${pkg ?: "unnamed"} type=${w.type} layer=${w.layer} covers " +
                            "${(ratio * 100).toInt()}% of the active window without focus",
                    ),
                )
            }
        }
        return Survey(findings, enumerable = true)
    }

    /**
     * Fraction of [target] that [cover] overlaps, 0..1.
     *
     * Pure arithmetic, kept separate from the Android calls so it can be tested on the JVM.
     * That matters here more than usual: this ratio is the whole decision, and before this
     * iteration the Kotlin half of the companion had no tests at all.
     */
    fun coverRatio(cover: Box, target: Box): Float {
        val targetArea = target.width.toLong() * target.height.toLong()
        if (targetArea <= 0L) return 0f
        val left = maxOf(cover.left, target.left)
        val top = maxOf(cover.top, target.top)
        val right = minOf(cover.right, target.right)
        val bottom = minOf(cover.bottom, target.bottom)
        if (right <= left || bottom <= top) return 0f
        val overlap = (right - left).toLong() * (bottom - top).toLong()
        return (overlap.toDouble() / targetArea.toDouble()).toFloat()
    }

    private fun boxOf(w: AccessibilityWindowInfo): Box {
        val r = Rect()
        w.getBoundsInScreen(r)
        return Box(r.left, r.top, r.right, r.bottom)
    }

    private fun packageOf(w: AccessibilityWindowInfo): String? =
        try {
            w.root?.packageName?.toString()
        } catch (e: Exception) {
            null
        }
}
