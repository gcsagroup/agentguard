#ifndef AGENTGUARD_SCK_H
#define AGENTGUARD_SCK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** ScreenCaptureKit bridge status codes. */
enum {
  AG_SCK_OK = 0,
  AG_SCK_UNSUPPORTED = 1,
  AG_SCK_DENIED = 2,
  AG_SCK_BUSY = 3,
  AG_SCK_ERROR = 4,
  AG_SCK_NOT_STREAMING = 5
};

/**
 * Current layout version of agentguard_frame_stats.
 *
 * ABI contract: the first 16 bytes (abi_version, width, height, reserved0) and
 * the `ocr_text` slot must never move, so a consumer that rejects an unknown
 * abi_version can still release the OCR string instead of leaking it. New fields
 * are appended after `ocr_text`.
 */
#define AG_FRAME_STATS_ABI 2

/**
 * Coarse frame statistics — never contains raw pixels.
 *
 * Passed by pointer so new heuristics can be added without reshuffling a long
 * positional callback signature (which is how the earlier subliminal_ratio /
 * lsb_flip_rate / ocr_text additions grew). Field order is fixed and padded
 * explicitly so the Rust `#[repr(C)]` mirror matches byte for byte; bump
 * AG_FRAME_STATS_ABI if it ever changes.
 *
 * mean_luma / low_opacity_ratio: 0..1 (may be 0 when sampling is skipped).
 * subliminal_ratio: fraction of a 16x9 grid whose local luma contrast lands in
 *   the strong subliminal band [0.008, 0.08) — A1 low-contrast text injection.
 * subliminal_ratio_wide: same grid, band [0.08, 0.22) — the 8–20 % opacity
 *   range that (A)I Sees §V-C shows VLMs still read perfectly.
 * lsb_flip_rate: horizontal LSB flip rate on the green channel (A1/A4 stego
 *   hint; chance = 0.5, smooth natural UI ~ 0).
 * chroma_lsb_flip_rate: same statistic on the Cb/Cr planes (max of the two).
 *   A4 as published embeds in chroma *while preserving luminance*, so the luma
 *   rate above cannot see it.
 * frame_digest: structural grid digest, "luma|cb|cr" with one hex nibble per block
 *   of a 16x9 grid (see Rust `framehash`). Used for A4 screenshot-integrity
 *   comparison across the TOCTOU window, and recorded in the signed audit trail.
 *   Whole-frame mean luminance cannot do this job: a line of injected text moves
 *   the frame mean by under a thousandth. NULL when the frame was too small.
 *   Caller-owned; release with agentguard_sck_string_free.
 * ocr_text: contrast-enhanced OCR of the frame (Visual Input Sanitization),
 *   populated when a subliminal band trips and periodically so that
 *   accessibility-tree vs rendered-text cross-validation has an input.
 *   NULL otherwise; when non-NULL the callee owns it and must release it with
 *   agentguard_sck_string_free.
 */
typedef struct {
  uint32_t abi_version;
  uint32_t width;
  uint32_t height;
  uint32_t reserved0;
  int64_t timestamp_ms;
  float mean_luma;
  float low_opacity_ratio;
  float subliminal_ratio;
  float subliminal_ratio_wide;
  float lsb_flip_rate;
  float chroma_lsb_flip_rate;
  const char *ocr_text;
  const char *frame_digest;
} agentguard_frame_stats;

typedef void (*agentguard_sck_frame_cb)(const agentguard_frame_stats *stats, void *userdata);

/** Probe ScreenCaptureKit + Screen Recording permission (sync). */
int agentguard_sck_probe(void);

/** Start a low-FPS display stream; invokes cb on the capture queue. */
int agentguard_sck_start(agentguard_sck_frame_cb cb, void *userdata);

/** Stop the active stream (idempotent). */
int agentguard_sck_stop(void);

/** Human-readable last error (static buffer; may be empty). */
const char *agentguard_sck_last_error(void);

/** Free a string returned via the frame callback (ocr_text). */
void agentguard_sck_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* AGENTGUARD_SCK_H */
