//! Reading text off a Windows frame, with the OCR that ships in the OS.
//!
//! # Why not Tesseract
//!
//! Windows 10 and later include `Windows.Media.Ocr`: offline, free, no model files, and with
//! simplified and traditional Chinese among the languages it installs by default. It is the
//! structural counterpart of the Vision framework the macOS path uses, and it is already
//! reachable through the `windows` crate this adapter depends on.
//!
//! Tesseract would add a C++ build dependency, `leptonica`, and 15–50 MB of language data per
//! language, for worse accuracy on screen text without preprocessing. An ONNX pipeline
//! (RapidOCR, PaddleOCR) would add a runtime plus ~10 MB of models to ship. Neither buys
//! anything here.
//!
//! # What this module does and does not decide
//!
//! It does not decide **when** to read, **how much** contrast to apply, or **how much** text
//! to carry. All three live in `guard_vision::ocr`, shared with the macOS path, because those
//! are the parts that drift and the symptom of drift is one platform quietly reading less than
//! the other. This module owns exactly the engine call.
//!
//! # Threading
//!
//! WinRT activation is per-apartment, same as the UI Automation client, so the engine is
//! thread-local for the same reason and with the same failure mode if it were not: an
//! interface created on one thread and used from another is undefined behaviour that works
//! intermittently.
//!
//! `RecognizeAsync` is asynchronous and this call site is synchronous, so completion is
//! awaited through a channel with a **timeout**. A poller that can block forever on OCR is a
//! poller that stops observing, and the frame it was reading is exactly the frame an attacker
//! would want it stuck on.

#![cfg(windows)]

use std::cell::RefCell;
use std::sync::mpsc;
use std::time::Duration;

use windows::Graphics::Imaging::{BitmapPixelFormat, SoftwareBitmap};
use windows::Media::Ocr::OcrEngine;
use windows::Security::Cryptography::CryptographicBuffer;
use windows_future::{AsyncOperationCompletedHandler, AsyncStatus};

/// Longest this will wait for one frame to be read.
///
/// The poll interval is 2500 ms and OCR runs at most every 8th frame, so a second is generous
/// for a normal read and short enough that a stuck engine costs one cycle rather than the
/// session.
pub const OCR_TIMEOUT: Duration = Duration::from_millis(1000);

thread_local! {
    /// This thread's OCR engine, created on first use.
    ///
    /// The `Result` is cached including its failure: an engine is unavailable because no
    /// recognizer language is installed, which does not change within a process, so retrying
    /// per frame would repeat a failing activation forever.
    static ENGINE: RefCell<Option<Result<OcrEngine, String>>> = const { RefCell::new(None) };
}

fn with_engine<R>(f: impl FnOnce(Result<&OcrEngine, &str>) -> R) -> R {
    ENGINE.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(create_engine());
        }
        match slot.as_ref().expect("just initialised") {
            Ok(e) => f(Ok(e)),
            Err(e) => f(Err(e.as_str())),
        }
    })
}

fn create_engine() -> Result<OcrEngine, String> {
    // The user's own profile languages first: on a Chinese install that gives a Chinese
    // recognizer, and this project's registry is full of Chinese app names. Falling straight to
    // English would read a Chinese payment sheet as nothing and report a clean screen.
    let first_error = match OcrEngine::TryCreateFromUserProfileLanguages() {
        Ok(engine) => return Ok(engine),
        // Not fatal: a profile language may have no recognizer installed. Try the ones this
        // project actually needs before giving up.
        Err(e) => format!("{e}"),
    };
    for tag in ["zh-Hans-CN", "zh-Hant-TW", "en-US"] {
        if let Ok(lang) = windows::Globalization::Language::CreateLanguage(&tag.into()) {
            if let Ok(engine) = OcrEngine::TryCreateFromLanguage(&lang) {
                return Ok(engine);
            }
        }
    }
    Err(format!(
        "no OCR recognizer available (profile languages: {first_error}; zh-Hans, zh-Hant and \
         en-US also unavailable). Windows installs recognizers with language packs, so this \
         host has none for the languages tried."
    ))
}

/// Whether this thread can read text, and why not when it cannot.
pub fn ocr_status() -> Result<String, String> {
    with_engine(|e| match e {
        Ok(engine) => {
            let lang = engine
                .RecognizerLanguage()
                .and_then(|l| l.DisplayName())
                .map(|n| n.to_string())
                .unwrap_or_else(|_| "unknown language".into());
            Ok(format!("OCR engine ready ({lang})"))
        }
        Err(e) => Err(e.to_string()),
    })
}

/// The largest edge this engine accepts, or `None` when it cannot be asked.
pub fn max_image_dimension() -> Option<u32> {
    OcrEngine::MaxImageDimension().ok()
}

/// Read text from a BGRA frame.
///
/// `px` is the **raw** frame. Contrast enhancement happens here, on a copy, using the shared
/// policy — the caller's buffer is also the input to the frame digest and the stego detectors,
/// and enhancing it in place would make those measurements describe the enhancement.
///
/// Returns `Ok(None)` when the engine ran and recognised nothing — different from `Err`, which
/// means it did not run. `analyze_frame` skips the viewtree comparison on an absent
/// `ocr_text` rather than comparing the accessibility tree against an empty string.
pub fn read_text(px: &[u8], width: u32, height: u32) -> Result<Option<String>, String> {
    if width == 0 || height == 0 {
        return Err("frame has no area".into());
    }
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|p| p.checked_mul(4))
        .ok_or_else(|| "frame dimensions overflow".to_string())?;
    if px.len() < expected {
        return Err(format!(
            "buffer is {} bytes, {width}x{height} BGRA needs {expected}",
            px.len()
        ));
    }
    if let Some(max) = max_image_dimension() {
        if width > max || height > max {
            // Refused rather than downscaled. Downscaling to fit would shrink the very text
            // this is trying to read — a subliminal payload is small and low-contrast, and a
            // resampled frame that returns no text is indistinguishable from a clean screen.
            return Err(format!(
                "frame {width}x{height} exceeds the engine's {max}px limit; refused rather than \
                 downscaled, because resampling would drop the small low-contrast text this \
                 read exists to find"
            ));
        }
    }

    let enhanced = guard_vision::ocr::enhance_contrast(&px[..expected]);
    let lines = recognize(&enhanced, width, height)?;
    Ok(guard_vision::ocr::join_lines(lines))
}

fn recognize(px: &[u8], width: u32, height: u32) -> Result<Vec<String>, String> {
    with_engine(|engine| {
        let engine = engine.map_err(|e| e.to_string())?;
        let buffer = CryptographicBuffer::CreateFromByteArray(px)
            .map_err(|e| format!("CreateFromByteArray failed: {e}"))?;
        let bitmap = SoftwareBitmap::CreateCopyFromBuffer(
            &buffer,
            BitmapPixelFormat::Bgra8,
            width as i32,
            height as i32,
        )
        .map_err(|e| format!("CreateCopyFromBuffer failed: {e}"))?;

        let op = engine
            .RecognizeAsync(&bitmap)
            .map_err(|e| format!("RecognizeAsync failed: {e}"))?;

        // A channel rather than a spin on `Status()`: a busy-wait on the poller thread burns a
        // core for as long as the read takes, and there is no upper bound on that.
        let (tx, rx) = mpsc::channel::<AsyncStatus>();
        let handler = AsyncOperationCompletedHandler::new(move |_op, status| {
            // A send failure means the receiver timed out and went away, which is a normal
            // race and not an error worth propagating into WinRT.
            let _ = tx.send(status);
            Ok(())
        });
        op.SetCompleted(&handler)
            .map_err(|e| format!("SetCompleted failed: {e}"))?;

        match rx.recv_timeout(OCR_TIMEOUT) {
            Err(_) => {
                // Best-effort cancel so the engine is not still working on a frame nobody will
                // read. The result is deliberately ignored: a cancel that fails changes nothing
                // about this call's outcome.
                let _ = op.Cancel();
                Err(format!("OCR timed out after {OCR_TIMEOUT:?}"))
            }
            Ok(AsyncStatus::Completed) => {
                let result = op
                    .GetResults()
                    .map_err(|e| format!("GetResults failed: {e}"))?;
                let mut out = Vec::new();
                let lines = result
                    .Lines()
                    .map_err(|e| format!("OcrResult::Lines failed: {e}"))?;
                for line in lines {
                    // `Text()` per line rather than `OcrResult::Text()` for the whole frame:
                    // the shared policy caps lines and characters per line, which needs the
                    // lines separate. A single blob would also lose the line structure the
                    // separator is there to preserve.
                    if let Ok(t) = line.Text() {
                        out.push(t.to_string());
                    }
                    if out.len() >= guard_vision::ocr::MAX_LINES {
                        break;
                    }
                }
                Ok(out)
            }
            Ok(status) => Err(format!("OCR did not complete: {status:?}")),
        }
    })
}
