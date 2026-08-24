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

// Structural grid digest: 16x9 blocks, 3x3 samples each, mean luma/Cb/Cr
// quantised to 4 bits. Mirrors Rust `framehash::digest_rgba` exactly — the two
// must agree, since a digest computed here is compared against one computed there.
// Returns a caller-owned "luma|cb|cr" string, or NULL when the frame is too small.
#define AG_DIGEST_COLS 16
#define AG_DIGEST_ROWS 9
#define AG_DIGEST_SAMPLES 3
#define AG_DIGEST_LEVELS 16

static char *ag_frame_digest(const uint8_t *base, size_t width, size_t height,
                             size_t bytesPerRow, int bgra) {
  if (base == NULL || width < AG_DIGEST_COLS || height < AG_DIGEST_ROWS) {
    return NULL;
  }
  static const char HEX[] = "0123456789abcdef";
  const size_t blocks = AG_DIGEST_COLS * AG_DIGEST_ROWS;
  // luma + '|' + cb + '|' + cr + NUL
  char *out = (char *)malloc(blocks * 3 + 3);
  if (out == NULL) {
    return NULL;
  }
  size_t cw = width / AG_DIGEST_COLS;
  size_t ch = height / AG_DIGEST_ROWS;
  size_t li = 0, bi = blocks + 1, ri = 2 * blocks + 2;
  out[blocks] = '|';
  out[2 * blocks + 1] = '|';
  out[blocks * 3 + 2] = '\0';
  for (int gy = 0; gy < AG_DIGEST_ROWS; gy++) {
    for (int gx = 0; gx < AG_DIGEST_COLS; gx++) {
      float y_sum = 0.0f, cb_sum = 0.0f, cr_sum = 0.0f;
      float count = 0.0f;
      for (int sy = 0; sy < AG_DIGEST_SAMPLES; sy++) {
        for (int sx = 0; sx < AG_DIGEST_SAMPLES; sx++) {
          size_t x = gx * cw + (size_t)(sx * cw / AG_DIGEST_SAMPLES);
          size_t yy = gy * ch + (size_t)(sy * ch / AG_DIGEST_SAMPLES);
          const uint8_t *px = base + yy * bytesPerRow + x * 4;
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
          y_sum += (0.299f * r + 0.587f * g + 0.114f * b) / 255.0f;
          cb_sum += (128.0f - 0.168736f * r - 0.331264f * g + 0.5f * b) / 255.0f;
          cr_sum += (128.0f + 0.5f * r - 0.418688f * g - 0.081312f * b) / 255.0f;
          count += 1.0f;
        }
      }
      float vals[3] = {y_sum / count, cb_sum / count, cr_sum / count};
      size_t *idx[3] = {&li, &bi, &ri};
      for (int c = 0; c < 3; c++) {
        float v = vals[c];
        if (v < 0.0f) v = 0.0f;
        if (v > 1.0f) v = 1.0f;
        int q = (int)roundf(v * (float)(AG_DIGEST_LEVELS - 1));
        if (q < 0) q = 0;
        if (q > AG_DIGEST_LEVELS - 1) q = AG_DIGEST_LEVELS - 1;
        out[*idx[c]] = HEX[q];
        (*idx[c])++;
      }
    }
  }
  return out;
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
static SCStream *gStream = nil;
static agentguard_sck_frame_cb gCallback = NULL;
static void *gUserdata = NULL;
static id gOutput = nil;

static void ag_set_error(NSString *msg) {
  gLastError = [msg copy];
}

const char *agentguard_sck_last_error(void) {
  if (gLastError == nil) {
    return "";
  }
  return [gLastError UTF8String];
}

int agentguard_sck_probe(void) {
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

@interface AgentGuardSCKOutput : NSObject <SCStreamOutput>
@end

@implementation AgentGuardSCKOutput

- (void)stream:(SCStream *)stream
    didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer
                   ofType:(SCStreamOutputType)type {
  // Snapshot the callback once: agentguard_sck_stop() clears gCallback from
  // another thread without waiting for in-flight handlers, and OCR can hold this
  // handler for 100 ms+, so re-reading the global at the end could call NULL.
  agentguard_sck_frame_cb cb = gCallback;
  void *userdata = gUserdata;
  if (type != SCStreamOutputTypeScreen || cb == NULL) {
    return;
  }
  CVImageBufferRef imageBuffer = CMSampleBufferGetImageBuffer(sampleBuffer);
  if (imageBuffer == NULL) {
    return;
  }
  size_t width = CVPixelBufferGetWidth(imageBuffer);
  size_t height = CVPixelBufferGetHeight(imageBuffer);
  CMTime pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer);
  int64_t ts_ms = (int64_t)(CMTimeGetSeconds(pts) * 1000.0);

  float mean_luma = 0.0f;
  float low_opacity = 0.0f;
  float subliminal = 0.0f;
  float subliminal_wide = 0.0f;
  float lsb_flip = 0.0f;
  float chroma_flip = 0.0f;
  char *frame_digest = NULL;

  // Sparse sample (privacy-preserving): a few pixels only, never retained.
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

      // A1 subliminal-text grid: 16x9 cells, 3x3 samples per cell, count cells
      // whose local contrast lands in the subliminal band [0.008, 0.08).
      // Mirrors crates' Rust `subliminal_ratio` (BGRA channel order here).
      const int COLS = 16, ROWS = 9, CS = 3;
      if ((fmt == kCVPixelFormatType_32BGRA || fmt == kCVPixelFormatType_32RGBA) &&
          width >= (size_t)COLS && height >= (size_t)ROWS) {
        const int bgra = (fmt == kCVPixelFormatType_32BGRA);
        size_t cw = width / COLS, ch = height / ROWS;
        int sub_cells = 0;
        int wide_cells = 0;
        for (int cy = 0; cy < ROWS; cy++) {
          for (int cx = 0; cx < COLS; cx++) {
            float lo = 1e9f, hi = -1e9f;
            for (int sy = 0; sy < CS; sy++) {
              for (int sx = 0; sx < CS; sx++) {
                size_t x = cx * cw + (size_t)(sx * cw / CS);
                size_t y = cy * ch + (size_t)(sy * ch / CS);
                uint8_t *px = base + y * bytesPerRow + x * 4;
                float l;
                if (bgra) {
                  l = (0.114f * px[0] + 0.587f * px[1] + 0.299f * px[2]) / 255.0f;
                } else {
                  l = (0.299f * px[0] + 0.587f * px[1] + 0.114f * px[2]) / 255.0f;
                }
                if (l < lo) lo = l;
                if (l > hi) hi = l;
              }
            }
            float contrast = hi - lo;
            if (contrast >= AG_BAND_MIN && contrast < AG_BAND_MAX) {
              sub_cells += 1;
            } else if (contrast >= AG_BAND_MAX && contrast < AG_BAND_MAX_WIDE) {
              wide_cells += 1;
            }
          }
        }
        subliminal = (float)sub_cells / (float)(COLS * ROWS);
        subliminal_wide = (float)wide_cells / (float)(COLS * ROWS);
      }

      // A4 integrity: structural grid digest for TOCTOU comparison.
      if (fmt == kCVPixelFormatType_32BGRA || fmt == kCVPixelFormatType_32RGBA) {
        frame_digest = ag_frame_digest(base, width, height, bytesPerRow,
                                      fmt == kCVPixelFormatType_32BGRA);
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

@end

int agentguard_sck_start(agentguard_sck_frame_cb cb, void *userdata) {
  if (@available(macOS 12.3, *)) {
    int probe = agentguard_sck_probe();
    if (probe != AG_SCK_OK) {
      return probe;
    }
    if (gStream != nil) {
      ag_set_error(@"capture already running");
      return AG_SCK_BUSY;
    }
    if (cb == NULL) {
      ag_set_error(@"null callback");
      return AG_SCK_ERROR;
    }

    gCallback = cb;
    gUserdata = userdata;

    __block int result = AG_SCK_ERROR;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    [SCShareableContent
        getShareableContentWithCompletionHandler:^(SCShareableContent *content, NSError *error) {
          if (error || content.displays.count == 0) {
            ag_set_error(error.localizedDescription ?: @"no shareable displays");
            result = AG_SCK_ERROR;
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

          AgentGuardSCKOutput *output = [[AgentGuardSCKOutput alloc] init];
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
            ag_set_error(addErr.localizedDescription ?: @"addStreamOutput failed");
            result = AG_SCK_ERROR;
            dispatch_semaphore_signal(sem);
            return;
          }

          [stream startCaptureWithCompletionHandler:^(NSError *startErr) {
            if (startErr) {
              ag_set_error(startErr.localizedDescription);
              result = AG_SCK_ERROR;
            } else {
              gStream = stream;
              gOutput = output;
              ag_set_error(@"");
              result = AG_SCK_OK;
            }
            dispatch_semaphore_signal(sem);
          }];
        }];

    // Wait up to 8s for TCC / content enumeration.
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)8 * NSEC_PER_SEC)) !=
        0) {
      ag_set_error(@"timed out starting ScreenCaptureKit stream");
      gCallback = NULL;
      gUserdata = NULL;
      return AG_SCK_ERROR;
    }
    if (result != AG_SCK_OK) {
      gCallback = NULL;
      gUserdata = NULL;
    }
    return result;
  }
  ag_set_error(@"ScreenCaptureKit requires macOS 12.3+");
  return AG_SCK_UNSUPPORTED;
}

int agentguard_sck_stop(void) {
  if (@available(macOS 12.3, *)) {
    if (gStream == nil) {
      return AG_SCK_NOT_STREAMING;
    }
    SCStream *stream = gStream;
    gStream = nil;
    gOutput = nil;
    gCallback = NULL;
    gUserdata = NULL;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [stream stopCaptureWithCompletionHandler:^(NSError *error) {
      if (error) {
        ag_set_error(error.localizedDescription);
      } else {
        ag_set_error(@"");
      }
      dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)3 * NSEC_PER_SEC));
    return AG_SCK_OK;
  }
  return AG_SCK_UNSUPPORTED;
}
