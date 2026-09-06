// AgentGuard ScreenCaptureKit bridge (macOS 12.3+).
// Privacy: callbacks expose coarse dimensions + optional luma heuristics only.

#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreImage/CoreImage.h>
#import <Vision/Vision.h>
#import <Foundation/Foundation.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "agentguard_sck.h"

// Matches Rust `subliminal::SUSPICION_THRESHOLD` / `WIDE_SUSPICION_THRESHOLD`;
// when either band trips we sanitize the frame (contrast enhancement + OCR) to
// surface hidden payloads.
#define AG_SUBLIMINAL_SUSPICION 0.10f
#define AG_SUBLIMINAL_SUSPICION_WIDE 0.30f

// Subliminal contrast bands (mirror Rust `subliminal` constants).
#define AG_BAND_MIN 0.008f
#define AG_BAND_MAX 0.08f
#define AG_BAND_MAX_WIDE 0.22f
#define AG_CELL_BAND_FRACTION 0.15f

// Run OCR on every Nth frame even when nothing looks subliminal, so that
// accessibility-tree vs rendered-text cross-validation (AgentScan Viewtree
// Interference) has an input. At ~2 FPS this is roughly one OCR every 4 s.
#define AG_OCR_EVERY_N_FRAMES 8

void agentguard_sck_string_free(char *s) {
  free(s);
}

// Contrast-enhance the frame and run fast OCR. Returns a bounded,
// caller-owned C string (NULL when nothing recognized or on error).
// Pixels themselves are never passed across the FFI boundary.
static char *ag_sanitize_and_ocr(CVImageBufferRef imageBuffer) {
  @autoreleasepool {
    CIImage *input = [[CIImage alloc] initWithCVImageBuffer:imageBuffer];
    CIFilter *boost = [CIFilter filterWithName:@"CIColorControls"];
    [boost setValue:input forKey:kCIInputImageKey];
    [boost setValue:@(4.0) forKey:kCIInputContrastKey];
    [boost setValue:@(0.15) forKey:kCIInputBrightnessKey];
    CIImage *enhanced = boost.outputImage;
    if (enhanced == nil) {
      return NULL;
    }
    // dispatch_once: the sample handler may run concurrently, and a plain
    // `if (ctx == nil)` would race on an ARC strong slot.
    static CIContext *ctx = nil;
    static dispatch_once_t ctx_once;
    dispatch_once(&ctx_once, ^{
      ctx = [CIContext contextWithOptions:nil];
    });
    CGImageRef cg = [ctx createCGImage:enhanced fromRect:enhanced.extent];
    if (cg == NULL) {
      return NULL;
    }
    VNRecognizeTextRequest *req = [[VNRecognizeTextRequest alloc] init];
    req.recognitionLevel = VNRequestTextRecognitionLevelFast;
    req.usesLanguageCorrection = NO;
    VNImageRequestHandler *handler =
        [[VNImageRequestHandler alloc] initWithCGImage:cg options:@{}];
    NSError *err = nil;
    BOOL ok = [handler performRequests:@[ req ] error:&err];
    CGImageRelease(cg);
    if (!ok || err != nil) {
      return NULL;
    }
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (VNRecognizedTextObservation *obs in req.results) {
      if (lines.count >= 24) {
        break;
      }
      VNRecognizedText *top = [[obs topCandidates:1] firstObject];
      if (top.string.length > 0) {
        [lines addObject:[top.string substringToIndex:MIN((NSUInteger)80, top.string.length)]];
      }
    }
    if (lines.count == 0) {
      return NULL;
    }
    NSString *joined = [lines componentsJoinedByString:@" | "];
    return strdup([joined UTF8String]);
  }
}

// Structural grid digest: 16x9 blocks, all pixels, mean luma/Cb/Cr plus an
// edge-density detail plane, quantised to 4 bits. Mirrors Rust
// `framehash::digest_rgba_stride` exactly — the two must agree, since a digest
// computed here is compared against one computed there. Returns a caller-owned
// "luma|cb|cr|detail" string, or NULL when the input is invalid.
#define AG_DIGEST_COLS 16
#define AG_DIGEST_ROWS 9
#define AG_DIGEST_LEVELS 16
#define AG_DETAIL_EDGE_THRESHOLD 0.25f
#define AG_DETAIL_SCALE 5.0f

static inline float ag_luma(const uint8_t *px, int bgra) {
  float r = bgra ? px[2] : px[0];
  float g = px[1];
  float b = bgra ? px[0] : px[2];
  return (0.299f * r + 0.587f * g + 0.114f * b) / 255.0f;
}

static inline int ag_quantise(float value) {
  if (value < 0.0f) value = 0.0f;
  if (value > 1.0f) value = 1.0f;
  int q = (int)roundf(value * (float)(AG_DIGEST_LEVELS - 1));
  if (q < 0) q = 0;
  if (q > AG_DIGEST_LEVELS - 1) q = AG_DIGEST_LEVELS - 1;
  return q;
}

char *agentguard_sck_frame_digest_rgba(const uint8_t *base, size_t width,
                                       size_t height, size_t bytesPerRow,
                                       int bgra) {
  if (base == NULL || width < AG_DIGEST_COLS || height < AG_DIGEST_ROWS ||
      bytesPerRow < width * 4 || bytesPerRow % 4 != 0) {
    return NULL;
  }
  static const char HEX[] = "0123456789abcdef";
  const size_t blocks = AG_DIGEST_COLS * AG_DIGEST_ROWS;
  // luma + '|' + cb + '|' + cr + '|' + detail + NUL
  char *out = (char *)malloc(blocks * 4 + 4);
  if (out == NULL) {
    return NULL;
  }
  size_t maxCellWidth = (width + AG_DIGEST_COLS - 1) / AG_DIGEST_COLS;
  float *previousRow = (float *)malloc(maxCellWidth * sizeof(float));
  if (previousRow == NULL) {
    free(out);
    return NULL;
  }
  size_t li = 0, bi = blocks + 1, ri = 2 * blocks + 2;
  size_t di = 3 * blocks + 3;
  out[blocks] = '|';
  out[2 * blocks + 1] = '|';
  out[3 * blocks + 2] = '|';
  out[blocks * 4 + 3] = '\0';
  for (int gy = 0; gy < AG_DIGEST_ROWS; gy++) {
    for (int gx = 0; gx < AG_DIGEST_COLS; gx++) {
      float y_sum = 0.0f, cb_sum = 0.0f, cr_sum = 0.0f;
      float count = 0.0f, edge_sum = 0.0f, edge_count = 0.0f;
      // Proportional boundaries cover every source pixel exactly once. Fixed
      // floor(width/cols) cells silently dropped the last row/column at 321x181.
      size_t x0 = (size_t)gx * width / AG_DIGEST_COLS;
      size_t x1 = (size_t)(gx + 1) * width / AG_DIGEST_COLS;
      size_t y0 = (size_t)gy * height / AG_DIGEST_ROWS;
      size_t y1 = (size_t)(gy + 1) * height / AG_DIGEST_ROWS;
      size_t cellWidth = x1 - x0;
      BOOL hasPreviousRow = y0 > 0;
      if (hasPreviousRow) {
        const uint8_t *above = base + (y0 - 1) * bytesPerRow;
        for (size_t x = 0; x < cellWidth; x++) {
          previousRow[x] = ag_luma(above + (x0 + x) * 4, bgra);
        }
      }
      for (size_t y = y0; y < y1; y++) {
        const uint8_t *row = base + y * bytesPerRow;
        float previousLuma = 0.0f;
        BOOL hasPreviousLuma = NO;
        for (size_t x = 0; x < cellWidth; x++) {
          const uint8_t *px = row + (x0 + x) * 4;
          float r = bgra ? px[2] : px[0];
          float g = px[1];
          float b = bgra ? px[0] : px[2];
          float luma = (0.299f * r + 0.587f * g + 0.114f * b) / 255.0f;
          y_sum += luma;
          cb_sum += (128.0f - 0.168736f * r - 0.331264f * g + 0.5f * b) / 255.0f;
          cr_sum += (128.0f + 0.5f * r - 0.418688f * g - 0.081312f * b) / 255.0f;
          count += 1.0f;
          if (hasPreviousLuma) {
            if (fabsf(luma - previousLuma) > AG_DETAIL_EDGE_THRESHOLD) {
              edge_sum += 1.0f;
            }
            edge_count += 1.0f;
          }
          if (hasPreviousRow) {
            if (fabsf(luma - previousRow[x]) > AG_DETAIL_EDGE_THRESHOLD) {
              edge_sum += 1.0f;
            }
            edge_count += 1.0f;
          }
          previousLuma = luma;
          hasPreviousLuma = YES;
          previousRow[x] = luma;
        }
        hasPreviousRow = YES;
      }
      if (count == 0.0f) count = 1.0f;
      if (edge_count == 0.0f) edge_count = 1.0f;
      out[li++] = HEX[ag_quantise(y_sum / count)];
      out[bi++] = HEX[ag_quantise(cb_sum / count)];
      out[ri++] = HEX[ag_quantise(cr_sum / count)];
      out[di++] = HEX[ag_quantise(sqrtf((edge_sum / edge_count) * AG_DETAIL_SCALE))];
    }
  }
  free(previousRow);
  return out;
}

int agentguard_sck_band_ratios_rgba(const uint8_t *base, size_t width,
                                     size_t height, size_t bytesPerRow,
                                     int bgra, float *strongOut,
                                     float *wideOut) {
  if (base == NULL || strongOut == NULL || wideOut == NULL ||
      width < AG_DIGEST_COLS || height < AG_DIGEST_ROWS ||
      bytesPerRow < width * 4 || bytesPerRow % 4 != 0) {
    return 0;
  }
  size_t cw = width / AG_DIGEST_COLS;
  size_t ch = height / AG_DIGEST_ROWS;
  float *previousRow = (float *)malloc(cw * sizeof(float));
  if (previousRow == NULL) {
    return 0;
  }
  int strongCells = 0;
  int wideCells = 0;
  for (int cy = 0; cy < AG_DIGEST_ROWS; cy++) {
    for (int cx = 0; cx < AG_DIGEST_COLS; cx++) {
      size_t x0 = (size_t)cx * cw;
      size_t y0 = (size_t)cy * ch;
      size_t strongPairs = 0, widePairs = 0, pairs = 0;
      BOOL hasPreviousRow = NO;
      for (size_t y = y0; y < y0 + ch; y++) {
        const uint8_t *row = base + y * bytesPerRow;
        float previousLuma = 0.0f;
        BOOL hasPreviousLuma = NO;
        for (size_t x = 0; x < cw; x++) {
          float luma = ag_luma(row + (x0 + x) * 4, bgra);
          if (hasPreviousLuma) {
            float d = fabsf(luma - previousLuma);
            if (d >= AG_BAND_MIN && d < AG_BAND_MAX) {
              strongPairs++;
            } else if (d >= AG_BAND_MAX && d < AG_BAND_MAX_WIDE) {
              widePairs++;
            }
            pairs++;
          }
          if (hasPreviousRow) {
            float d = fabsf(luma - previousRow[x]);
            if (d >= AG_BAND_MIN && d < AG_BAND_MAX) {
              strongPairs++;
            } else if (d >= AG_BAND_MAX && d < AG_BAND_MAX_WIDE) {
              widePairs++;
            }
            pairs++;
          }
          previousLuma = luma;
          hasPreviousLuma = YES;
          previousRow[x] = luma;
        }
        hasPreviousRow = YES;
      }
      if (pairs == 0) continue;
      float strongFraction = (float)strongPairs / (float)pairs;
      float wideFraction = (float)widePairs / (float)pairs;
      if (strongFraction >= AG_CELL_BAND_FRACTION) {
        strongCells++;
      } else if (wideFraction >= AG_CELL_BAND_FRACTION) {
        wideCells++;
      }
    }
  }
  free(previousRow);
  const float cells = (float)(AG_DIGEST_COLS * AG_DIGEST_ROWS);
  *strongOut = (float)strongCells / cells;
  *wideOut = (float)wideCells / cells;
  return 1;
}

// BT.601 Cb/Cr for one packed 4-byte pixel (mirrors Rust `stego::chroma_at`).
static inline void ag_chroma(const uint8_t *px, int bgra, uint8_t *cb_out, uint8_t *cr_out) {
  float r, g, b;
  if (bgra) {
    b = px[0];
    g = px[1];
    r = px[2];
  } else {
    r = px[0];
    g = px[1];
    b = px[2];
  }
  float cb = 128.0f - 0.168736f * r - 0.331264f * g + 0.5f * b;
  float cr = 128.0f + 0.5f * r - 0.418688f * g - 0.081312f * b;
  cb = roundf(cb);
  cr = roundf(cr);
  if (cb < 0.0f) cb = 0.0f;
  if (cb > 255.0f) cb = 255.0f;
  if (cr < 0.0f) cr = 0.0f;
  if (cr > 255.0f) cr = 255.0f;
  *cb_out = (uint8_t)cb;
  *cr_out = (uint8_t)cr;
}

static NSString *gLastError = nil;
static pthread_mutex_t gErrorLock = PTHREAD_MUTEX_INITIALIZER;
// Protects the strong stream/output slots and the independent native operation
// token. Rust deliberately clears its ACTIVE_GENERATION when a synchronous FFI
// call times out; this token must outlive that return until Apple's late
// completion (and any required stop cleanup) has actually finished.
static pthread_mutex_t gSckStateLock = PTHREAD_MUTEX_INITIALIZER;
static SCStream *gStream = nil;
static id gOutput = nil;
// Non-nil only after Apple reports that a stream could not be stopped. The
// process then keeps strong ownership and remains fail-closed until restart.
static NSString *gSckBlockedReason = nil;
static _Atomic(uint64_t) gSckGeneration = 0;
static uint64_t gSckStartInflight = 0;
static NSString *const kAgSckBusyInProgress =
    @"capture start or cleanup already in progress";

// Called while gSckStateLock is held. Returning a copied strong value lets the
// caller release the state lock before touching gErrorLock, while a concurrent
// cleanup callback may safely replace/clear gSckBlockedReason.
static NSString *ag_sck_busy_reason_copy(NSString *blocked_reason) {
  return [blocked_reason ?: kAgSckBusyInProgress copy];
}

// These transitions are framework-independent. Production callers hold
// gSckStateLock; the deterministic self-test below uses local state to exercise
// the exact same claim/cancel/retire rules without invoking TCC or SCK.
static BOOL ag_sck_claim_slot(uint64_t generation, BOOL has_stream,
                              uint64_t *inflight,
                              _Atomic(uint64_t) *active_generation) {
  if (has_stream || *inflight != 0) {
    return NO;
  }
  *inflight = generation;
  atomic_store(active_generation, generation);
  return YES;
}

static void ag_sck_cancel_slot(uint64_t generation, uint64_t *inflight,
                               _Atomic(uint64_t) *active_generation) {
  // Cancellation revokes commit eligibility but intentionally does not release
  // the slot. Only a matching completion/cleanup may do that.
  if (*inflight == generation) {
    uint64_t expected = generation;
    atomic_compare_exchange_strong(active_generation, &expected, 0);
  }
}

static BOOL ag_sck_retire_slot(uint64_t generation, uint64_t *inflight,
                               _Atomic(uint64_t) *active_generation) {
  if (*inflight != generation) {
    return NO;
  }
  BOOL was_current = atomic_load(active_generation) == generation;
  *inflight = 0;
  uint64_t expected = generation;
  atomic_compare_exchange_strong(active_generation, &expected, 0);
  return was_current;
}

static BOOL ag_sck_complete_cleanup_slot(
    uint64_t generation, BOOL cleanup_succeeded, uint64_t *inflight,
    _Atomic(uint64_t) *active_generation) {
  // A failed stop is not cleanup. Preserve the matching slot so no successor
  // can coexist with a stream whose stop was never confirmed.
  if (!cleanup_succeeded || *inflight != generation) {
    return NO;
  }
  (void)ag_sck_retire_slot(generation, inflight, active_generation);
  return YES;
}

int agentguard_sck_singleflight_state_self_test(void) {
  _Atomic(uint64_t) active_generation = 0;
  uint64_t inflight = 0;
  const uint64_t g1 = 41;
  const uint64_t g2 = 42;

  if (!ag_sck_claim_slot(g1, NO, &inflight, &active_generation)) return 0;
  ag_sck_cancel_slot(g1, &inflight, &active_generation);
  if (atomic_load(&active_generation) != 0 || inflight != g1) return 0;
  // g1 timed out: cleanup failure must leave g2 BUSY and preserve g1's slot.
  if (ag_sck_claim_slot(g2, NO, &inflight, &active_generation)) return 0;
  if (ag_sck_complete_cleanup_slot(g1, NO, &inflight, &active_generation)) return 0;
  if (inflight != g1 || atomic_load(&active_generation) != 0) return 0;
  if (ag_sck_claim_slot(g2, NO, &inflight, &active_generation)) return 0;
  // Only confirmed cleanup retires g1 and lets g2 claim the native slot.
  if (!ag_sck_complete_cleanup_slot(g1, YES, &inflight, &active_generation)) return 0;
  if (!ag_sck_claim_slot(g2, NO, &inflight, &active_generation)) return 0;
  // A duplicate late g1 callback cannot clear the new g2 token.
  if (ag_sck_complete_cleanup_slot(g1, YES, &inflight, &active_generation)) return 0;
  if (inflight != g2 || atomic_load(&active_generation) != g2) return 0;
  if (!ag_sck_retire_slot(g2, &inflight, &active_generation)) return 0;
  if (inflight != 0 || atomic_load(&active_generation) != 0) return 0;
  if (ag_sck_claim_slot(g1, YES, &inflight, &active_generation)) return 0;
  return 1;
}

int agentguard_sck_busy_reason_state_self_test(void) {
  @autoreleasepool {
    NSMutableString *blocked = [NSMutableString stringWithString:
        @"cleanup failed; restart required"];
    NSString *ownedReason = ag_sck_busy_reason_copy(blocked);
    [blocked setString:@"mutated after state unlock"];
    if (![ownedReason isEqualToString:@"cleanup failed; restart required"]) {
      return 0;
    }
    NSString *temporaryReason = ag_sck_busy_reason_copy(nil);
    if (![temporaryReason isEqualToString:kAgSckBusyInProgress]) {
      return 0;
    }
    return 1;
  }
}

static void ag_set_error(NSString *msg) {
  pthread_mutex_lock(&gErrorLock);
  gLastError = [msg copy];
  pthread_mutex_unlock(&gErrorLock);
}

char *agentguard_sck_last_error_copy(void) {
  @autoreleasepool {
    pthread_mutex_lock(&gErrorLock);
    const char *utf8 = gLastError == nil ? "" : [gLastError UTF8String];
    char *copy = strdup(utf8 == NULL ? "" : utf8);
    pthread_mutex_unlock(&gErrorLock);
    return copy;
  }
}

// Retire only the matching operation. A late callback from generation N must
// never clear generation N+1's token. Returns YES only when the caller was
// still current (rather than already cancelled by a timeout/stop), which lets
// late callbacks avoid overwriting the timeout error seen by the FFI caller.
static BOOL ag_sck_retire_start(uint64_t generation) {
  pthread_mutex_lock(&gSckStateLock);
  BOOL was_current = ag_sck_retire_slot(
      generation, &gSckStartInflight, &gSckGeneration);
  pthread_mutex_unlock(&gSckStateLock);
  return was_current;
}

static BOOL ag_sck_start_is_current(uint64_t generation) {
  pthread_mutex_lock(&gSckStateLock);
  BOOL current = gSckStartInflight == generation &&
                 atomic_load(&gSckGeneration) == generation;
  pthread_mutex_unlock(&gSckStateLock);
  return current;
}

static int ag_sck_probe_impl(void) {
  if (@available(macOS 12.3, *)) {
    if (!CGPreflightScreenCaptureAccess()) {
      ag_set_error(@"Screen Recording permission not granted");
      return AG_SCK_DENIED;
    }
    ag_set_error(@"");
    return AG_SCK_OK;
  }
  ag_set_error(@"ScreenCaptureKit requires macOS 12.3+");
  return AG_SCK_UNSUPPORTED;
}

int agentguard_sck_probe(void) {
  @autoreleasepool {
    return ag_sck_probe_impl();
  }
}

@interface AgentGuardSCKOutput : NSObject <SCStreamOutput>
@property(nonatomic, assign) agentguard_sck_frame_cb callback;
@property(nonatomic, assign) void *userdata;
@property(nonatomic, assign) uint64_t generation;
- (instancetype)initWithCallback:(agentguard_sck_frame_cb)callback
                         userdata:(void *)userdata
                       generation:(uint64_t)generation;
@end

@implementation AgentGuardSCKOutput

- (instancetype)initWithCallback:(agentguard_sck_frame_cb)callback
                         userdata:(void *)userdata
                       generation:(uint64_t)generation {
  self = [super init];
  if (self != nil) {
    _callback = callback;
    _userdata = userdata;
    _generation = generation;
  }
  return self;
}

- (void)stream:(SCStream *)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
                   ofType:(SCStreamOutputType)type {
  @autoreleasepool {
  // callback/userdata/generation 属于这个 output，而不是进程全局槽。旧 stream 即使在
  // stop/start 后才投递，仍携带旧代际；不会误用继任 stream 的 callback。
  agentguard_sck_frame_cb cb = self.callback;
  void *userdata = self.userdata;
  uint64_t generation = self.generation;
  if (type != SCStreamOutputTypeScreen || cb == NULL || generation == 0 ||
      atomic_load(&gSckGeneration) != generation) {
    return;
  }
  CVImageBufferRef imageBuffer = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (imageBuffer == NULL) {
    return;
  }
  size_t width = CVPixelBufferGetWidth(imageBuffer);
  size_t height = CVPixelBufferGetHeight(imageBuffer);
  // CMSampleBuffer PTS is tied to the capture/media clock, while AX snapshots
  // use Unix wall time. Mixing the two made their absolute delta roughly the
  // machine uptime and silently disabled AX↔OCR cross-validation. Use callback
  // wall time for cross-source pairing; media PTS remains SCK-internal ordering.
  int64_t ts_ms = (int64_t)llround(
      [[NSDate date] timeIntervalSince1970] * 1000.0);

  float mean_luma = 0.0f;
  float low_opacity = 0.0f;
  float subliminal = 0.0f;
  float subliminal_wide = 0.0f;
  float lsb_flip = 0.0f;
  float chroma_flip = 0.0f;
  char *frame_digest = NULL;

  // Privacy-preserving in-place analysis: pixels are scanned inside the capture
  // callback but never retained and never cross the FFI boundary.
  if (CVPixelBufferLockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly) == kCVReturnSuccess) {
    OSType fmt = CVPixelBufferGetPixelFormatType(imageBuffer);
    size_t bytesPerRow = CVPixelBufferGetBytesPerRow(imageBuffer);
    uint8_t *base = (uint8_t *)CVPixelBufferGetBaseAddress(imageBuffer);
    if (base && width > 0 && height > 0) {
      const int samples = 64;
      float sum = 0.0f;
      int low = 0;
      for (int i = 0; i < samples; i++) {
        size_t x = (size_t)((i * 17) % width);
        size_t y = (size_t)((i * 29) % height);
        uint8_t *row = base + y * bytesPerRow;
        float luma = 0.5f;
        float alpha = 1.0f;
        if (fmt == kCVPixelFormatType_32BGRA) {
          uint8_t *px = row + x * 4;
          luma = (0.114f * px[0] + 0.587f * px[1] + 0.299f * px[2]) / 255.0f;
          alpha = px[3] / 255.0f;
        } else if (fmt == kCVPixelFormatType_32RGBA) {
          uint8_t *px = row + x * 4;
          luma = (0.299f * px[0] + 0.587f * px[1] + 0.114f * px[2]) / 255.0f;
          alpha = px[3] / 255.0f;
        }
        sum += luma;
        if (alpha < 0.05f) {
          low += 1;
        }
      }
      mean_luma = sum / (float)samples;
      low_opacity = (float)low / (float)samples;

      // A1:全像素、相位无关的相邻对分布。这个纯函数也被 Rust 跨语言
      // 金标准测试直接调用，防止原生采集和模拟/CLI 判决再次漂移。
      if (fmt == kCVPixelFormatType_32BGRA || fmt == kCVPixelFormatType_32RGBA) {
        const int bgra = (fmt == kCVPixelFormatType_32BGRA);
        (void)agentguard_sck_band_ratios_rgba(
            base, width, height, bytesPerRow, bgra, &subliminal,
            &subliminal_wide);

        // A4 integrity:四平面结构摘要；包括细笔画所需的 detail 平面。
        frame_digest = agentguard_sck_frame_digest_rgba(
            base, width, height, bytesPerRow, bgra);
      }

      // A1/A4 stego hint: horizontal LSB flip rate on the green channel,
      // strided sampling (mirrors Rust `stego::lsb_flip_rate`).
      if (fmt == kCVPixelFormatType_32BGRA || fmt == kCVPixelFormatType_32RGBA) {
        const int bgra_order = (fmt == kCVPixelFormatType_32BGRA);
        const size_t SX = 7, SY = 11;
        if (width >= SX * 2 && height >= SY * 2) {
          size_t flips = 0, pairs = 0;
          size_t cb_flips = 0, cr_flips = 0;
          for (size_t y = 0; y < height; y += SY) {
            uint8_t *row = base + y * bytesPerRow;
            for (size_t x = 0; x + SX < width; x += SX) {
              uint8_t *pa = row + x * 4;
              uint8_t *pb = row + (x + SX) * 4;
              flips += (size_t)((pa[1] & 1) ^ (pb[1] & 1));

              // A4 as published embeds in Cb/Cr while preserving Y, which the
              // green-channel rate above cannot see. BT.601, matching Rust
              // `stego::chroma_at`.
              uint8_t cb_a, cr_a, cb_b, cr_b;
              ag_chroma(pa, bgra_order, &cb_a, &cr_a);
              ag_chroma(pb, bgra_order, &cb_b, &cr_b);
              cb_flips += (size_t)((cb_a & 1) ^ (cb_b & 1));
              cr_flips += (size_t)((cr_a & 1) ^ (cr_b & 1));
              pairs += 1;
            }
          }
          if (pairs > 0) {
            lsb_flip = (float)flips / (float)pairs;
            float cb_rate = (float)cb_flips / (float)pairs;
            float cr_rate = (float)cr_flips / (float)pairs;
            chroma_flip = cb_rate > cr_rate ? cb_rate : cr_rate;
          }
        }
      }
    }
    CVPixelBufferUnlockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly);
  }

  // A1 sanitization hook: OCR when either subliminal band trips, and every Nth
  // frame regardless so viewtree cross-validation has rendered text to compare.
  // Atomic: the sample handler queue is serial today, but SCK reserves the right
  // to deliver concurrently and a torn counter would only jitter OCR cadence.
  static _Atomic uint64_t frame_seq = 0;
  uint64_t seq = ++frame_seq;
  char *ocr = NULL;
  // `>=` where Rust `subliminal::is_suspicious` uses `>`: differs only at exact
  // equality, and over-triggering OCR is the safe direction (Rust still decides
  // whether a finding is raised).
  BOOL suspicious = (subliminal >= AG_SUBLIMINAL_SUSPICION) ||
                    (subliminal_wide >= AG_SUBLIMINAL_SUSPICION_WIDE);
  BOOL periodic = (seq % AG_OCR_EVERY_N_FRAMES) == 0;
  if (suspicious || periodic) {
    ocr = ag_sanitize_and_ocr(imageBuffer);
  }

  agentguard_frame_stats stats = {
      .abi_version = AG_FRAME_STATS_ABI,
      .width = (uint32_t)width,
      .height = (uint32_t)height,
      .reserved0 = 0,
      .timestamp_ms = ts_ms,
      .mean_luma = mean_luma,
      .low_opacity_ratio = low_opacity,
      .subliminal_ratio = subliminal,
      .subliminal_ratio_wide = subliminal_wide,
      .lsb_flip_rate = lsb_flip,
      .chroma_lsb_flip_rate = chroma_flip,
      .ocr_text = ocr,
      .frame_digest = frame_digest,
  };
  cb(&stats, userdata);
  }
}

@end

static int ag_sck_start_impl(agentguard_sck_frame_cb cb, void *userdata,
                             uint64_t generation) {
  if (@available(macOS 12.3, *)) {
    if (cb == NULL) {
      ag_set_error(@"null callback");
      return AG_SCK_ERROR;
    }
    if (generation == 0) {
      ag_set_error(@"SCK generation must be non-zero");
      return AG_SCK_ERROR;
    }
    int probe = agentguard_sck_probe();
    if (probe != AG_SCK_OK) {
      return probe;
    }

    // Claim the native slot only after permission probing. A timed-out start
    // intentionally keeps this slot until its late completion/cleanup; callers
    // therefore get BUSY instead of stacking another asynchronous SCK start.
    BOOL busy = NO;
    NSString *busyReason = nil;
    pthread_mutex_lock(&gSckStateLock);
    if (!ag_sck_claim_slot(generation, gStream != nil,
                           &gSckStartInflight, &gSckGeneration)) {
      busy = YES;
      busyReason = ag_sck_busy_reason_copy(gSckBlockedReason);
    }
    pthread_mutex_unlock(&gSckStateLock);
    if (busy) {
      // State and error locks are never nested. busyReason owns the selected
      // diagnostic across the unlock, even if a cleanup callback changes state.
      ag_set_error(busyReason);
      return AG_SCK_BUSY;
    }

    __block int result = AG_SCK_ERROR;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    [SCShareableContent
        getShareableContentWithCompletionHandler:^(SCShareableContent *content, NSError *error) {
          @autoreleasepool {
            if (error || content.displays.count == 0) {
              BOOL report_error = ag_sck_retire_start(generation);
              if (report_error) {
                ag_set_error(error.localizedDescription ?: @"no shareable displays");
              }
              dispatch_semaphore_signal(sem);
              return;
            }

            // The caller may have hit its deadline while content enumeration
            // was pending. No native resource exists yet, so this completion
            // itself is the cleanup boundary and may release the matching slot.
            if (!ag_sck_start_is_current(generation)) {
              ag_sck_retire_start(generation);
              dispatch_semaphore_signal(sem);
              return;
            }

            SCDisplay *display = content.displays.firstObject;
            SCContentFilter *filter =
                [[SCContentFilter alloc] initWithDisplay:display excludingWindows:@[]];
            SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
            config.width = 640;
            config.height = 360;
            config.minimumFrameInterval = CMTimeMake(1, 2); // ~2 FPS
            config.queueDepth = 2;
            config.showsCursor = NO;
            config.pixelFormat = kCVPixelFormatType_32BGRA;

            AgentGuardSCKOutput *output =
                [[AgentGuardSCKOutput alloc] initWithCallback:cb
                                                     userdata:userdata
                                                   generation:generation];
            SCStream *stream = [[SCStream alloc] initWithFilter:filter
                                                  configuration:config
                                                       delegate:nil];
            NSError *addErr = nil;
            // Private serial queue rather than the concurrent global queue: OCR
            // can approach the frame interval, and a serial queue makes SCK drop
            // overlapping frames instead of running two handlers at once.
            dispatch_queue_t sampleQueue = dispatch_queue_create(
                "com.agentguard.sck.samples",
                dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
                                                        QOS_CLASS_UTILITY, 0));
            BOOL ok = [stream addStreamOutput:output
                                         type:SCStreamOutputTypeScreen
                           sampleHandlerQueue:sampleQueue
                                        error:&addErr];
            if (!ok || addErr) {
              BOOL report_error = ag_sck_retire_start(generation);
              if (report_error) {
                ag_set_error(addErr.localizedDescription ?: @"addStreamOutput failed");
              }
              dispatch_semaphore_signal(sem);
              return;
            }

            [stream startCaptureWithCompletionHandler:^(NSError *startErr) {
              @autoreleasepool {
                if (startErr) {
                  BOOL report_error = ag_sck_retire_start(generation);
                  if (report_error) {
                    ag_set_error(startErr.localizedDescription);
                  }
                  dispatch_semaphore_signal(sem);
                  return;
                }

                // Serialize the deadline and the commit. If the wrapper wins,
                // generation is zeroed but the inflight slot stays occupied;
                // this late stream is stopped before that slot is released.
                BOOL committed = NO;
                pthread_mutex_lock(&gSckStateLock);
                if (gSckStartInflight == generation &&
                    atomic_load(&gSckGeneration) == generation && gStream == nil) {
                  gStream = stream;
                  gOutput = output;
                  gSckStartInflight = 0;
                  result = AG_SCK_OK;
                  committed = YES;
                }
                pthread_mutex_unlock(&gSckStateLock);

                if (committed) {
                  ag_set_error(@"");
                } else {
                  // Do not release gSckStartInflight here: startCapture has
                  // succeeded, so cleanup is not complete until stopCapture's
                  // matching completion arrives. Capturing output explicitly
                  // also keeps the callback target alive through that cleanup.
                  [stream stopCaptureWithCompletionHandler:^(NSError *stopErr) {
                    @autoreleasepool {
                      (void)stream;
                      (void)output;
                      NSString *failureReason = stopErr == nil ? nil :
                          [NSString stringWithFormat:
                              @"ScreenCaptureKit cleanup failed; restart required before capture can be retried: %@",
                              stopErr.localizedDescription ?: @"unknown stop error"];
                      BOOL owned = NO;
                      pthread_mutex_lock(&gSckStateLock);
                      if (gSckStartInflight == generation) {
                        owned = YES;
                        if (stopErr == nil) {
                          (void)ag_sck_complete_cleanup_slot(
                              generation, YES, &gSckStartInflight,
                              &gSckGeneration);
                          gSckBlockedReason = nil;
                        } else {
                          // Stopping failed: retain the unconfirmed stream and
                          // its callback target, and keep the slot occupied for
                          // the rest of this process. Only restart is safe.
                          gStream = stream;
                          gOutput = output;
                          gSckBlockedReason = [failureReason copy];
                        }
                      }
                      pthread_mutex_unlock(&gSckStateLock);
                      if (owned && failureReason != nil) {
                        ag_set_error(failureReason);
                      }
                    }
                  }];
                }
                dispatch_semaphore_signal(sem);
              }
            }];
          }
        }];

    // Wait up to 8s for TCC / content enumeration.
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)8 * NSEC_PER_SEC)) !=
        0) {
      // A success completion may have committed while the semaphore deadline
      // fired. The same state lock makes that race deterministic: committed
      // success wins; otherwise cancel generation but retain the inflight token
      // until the asynchronous completion/cleanup retires it.
      BOOL committed = NO;
      pthread_mutex_lock(&gSckStateLock);
      committed = result == AG_SCK_OK;
      if (!committed && gSckStartInflight == generation) {
        ag_sck_cancel_slot(generation, &gSckStartInflight,
                           &gSckGeneration);
      }
      pthread_mutex_unlock(&gSckStateLock);
      if (committed) {
        ag_set_error(@"");
        return AG_SCK_OK;
      }
      ag_set_error(@"timed out starting ScreenCaptureKit stream");
      return AG_SCK_TIMEOUT;
    }
    // Failure completions without a started stream retire their own slot. A
    // stale *successful* start deliberately leaves it occupied until the
    // asynchronous stop cleanup finishes, so do not retire it here.
    return result;
  }
  ag_set_error(@"ScreenCaptureKit requires macOS 12.3+");
  return AG_SCK_UNSUPPORTED;
}

int agentguard_sck_start(agentguard_sck_frame_cb cb, void *userdata,
                         uint64_t generation) {
  @autoreleasepool {
    return ag_sck_start_impl(cb, userdata, generation);
  }
}

static int ag_sck_stop_impl(uint64_t generation) {
  if (@available(macOS 12.3, *)) {
    SCStream *stream = nil;
    id output = nil;
    pthread_mutex_lock(&gSckStateLock);
    if (generation == 0 || atomic_load(&gSckGeneration) != generation) {
      pthread_mutex_unlock(&gSckStateLock);
      return AG_SCK_NOT_STREAMING;
    }
    if (gStream == nil) {
      // A stop racing an in-flight start cancels commit eligibility but leaves
      // the native slot for that start's eventual completion/cleanup.
      ag_sck_cancel_slot(generation, &gSckStartInflight,
                         &gSckGeneration);
      pthread_mutex_unlock(&gSckStateLock);
      return AG_SCK_NOT_STREAMING;
    }
    stream = gStream;
    output = gOutput;
    gStream = nil;
    gOutput = nil;
    uint64_t expected = generation;
    atomic_compare_exchange_strong(&gSckGeneration, &expected, 0);
    // Reuse the operation token to prevent a new stream from starting before
    // stopCapture has actually completed (including a late completion after a
    // 3s synchronous stop timeout).
    gSckStartInflight = generation;
    pthread_mutex_unlock(&gSckStateLock);

    __block int result = -1;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [stream stopCaptureWithCompletionHandler:^(NSError *error) {
      @autoreleasepool {
        (void)stream;
        (void)output;
        NSString *failureReason = error == nil ? nil :
            [NSString stringWithFormat:
                @"ScreenCaptureKit stop failed; restart required before capture can be retried: %@",
                error.localizedDescription ?: @"unknown stop error"];
        BOOL owned = NO;
        pthread_mutex_lock(&gSckStateLock);
        if (gSckStartInflight == generation) {
          owned = YES;
          if (error == nil) {
            (void)ag_sck_complete_cleanup_slot(
                generation, YES, &gSckStartInflight, &gSckGeneration);
            gSckBlockedReason = nil;
            result = AG_SCK_OK;
          } else {
            // An error does not prove the stream stopped. Keep both strong
            // resources and the native token, preventing a concurrent successor
            // until process restart.
            gStream = stream;
            gOutput = output;
            gSckBlockedReason = [failureReason copy];
            result = AG_SCK_ERROR;
          }
        }
        pthread_mutex_unlock(&gSckStateLock);
        if (owned) {
          ag_set_error(failureReason ?: @"");
        }
        dispatch_semaphore_signal(sem);
      }
    }];
    if (dispatch_semaphore_wait(
            sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)3 * NSEC_PER_SEC)) != 0) {
      // As with start, a completion may have won while its signal lost the
      // deadline race. Observe result under the state lock before declaring a
      // timeout; otherwise keep the operation token until the late callback.
      pthread_mutex_lock(&gSckStateLock);
      int completed_result = result;
      pthread_mutex_unlock(&gSckStateLock);
      if (completed_result != -1) {
        return completed_result;
      }
      ag_set_error(@"timed out stopping ScreenCaptureKit stream");
      return AG_SCK_TIMEOUT;
    }
    return result;
  }
  return AG_SCK_UNSUPPORTED;
}

int agentguard_sck_stop(uint64_t generation) {
  @autoreleasepool {
    return ag_sck_stop_impl(generation);
  }
}
