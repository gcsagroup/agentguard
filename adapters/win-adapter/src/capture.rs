//! Real Windows frame capture, via GDI.
//!
//! # Why GDI and not Windows.Graphics.Capture
//!
//! Graphics Capture is the modern API and the right long-term answer, but it is async WinRT
//! with a D3D11 device, a frame pool and a dispatcher — several hundred lines whose failure
//! modes cannot be exercised from this repository's CI at all. `BitBlt` is synchronous, is
//! about forty lines, needs no graphics device, and produces exactly what the analysis
//! needs: a BGRA buffer at native resolution. It is chosen because it is the version that
//! can be reviewed and reasoned about, and [`GRAPHICS_CAPTURE_NOTE`] records what it costs.
//!
//! # The analysis is not here
//!
//! This module's whole output is a buffer plus a width and a height. Everything measured
//! from those pixels — the subliminal contrast bands, the LSB and chroma flip rates, the
//! block digest — happens in `guard-vision`, the same code the macOS ScreenCaptureKit path
//! calls. Windows contributes pixels, not thresholds.
//!
//! # Why an oversized window is refused rather than downscaled
//!
//! Downscaling would keep the pipeline running and quietly invalidate half of it. Box
//! averaging preserves local contrast well enough for the subliminal bands, but it destroys
//! the LSB plane completely: `lsb_flip_rate` over a resampled frame is a number about the
//! resampler, not about the frame. It would still be *a* number, in range, indistinguishable
//! from a real measurement. So a frame beyond [`MAX_PIXELS`] produces an error, and the
//! caller reports that the frame was not analysed — the same rule as everywhere else here:
//! a failure is silence, never a guess.

#![cfg(windows)]

use guard_vision::FrameStats;
use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GetWindowDC, ReleaseDC,
    SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, HGDIOBJ,
    SRCCOPY,
};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowRect};

/// Largest frame this path will analyse: 4K and a margin.
///
/// Above it the frame is refused rather than resampled; see the module note.
pub const MAX_PIXELS: usize = 16_000_000;

/// What choosing GDI over Graphics Capture costs, recorded where it is made rather than in
/// a roadmap file.
///
/// `BitBlt` on a window DC reads what that window rendered. It does **not** see another
/// process's window composited on top of it, which is precisely the (A)I Sees A3 phishing
/// overlay. On Windows the overlay surface is therefore covered only where the overlaying
/// window is itself the foreground window. Graphics Capture, which samples the composed
/// desktop, would close that gap.
pub const GRAPHICS_CAPTURE_NOTE: &str =
    "GDI BitBlt reads the target window's own rendering, not the composed desktop: a phishing \
     window drawn over it by another process is not in these pixels unless it is itself the \
     foreground window.";

/// A captured frame: BGRA, top-down, no padding.
pub struct Frame {
    pub px: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl Frame {
    /// Run every shared pixel detector over this frame.
    pub fn to_stats(&self, timestamp_ms: i64) -> FrameStats {
        // `true` = BGRA. GDI hands back blue-first, and getting this wrong is not cosmetic:
        // Rec. 601 weights red at 0.299 and blue at 0.114, so a swapped buffer moves
        // mean_luma, which is the A4 fallback threshold.
        //
        // `AlphaChannel::Padding` because `BitBlt` into a 32-bit BI_RGB DIB writes three
        // channels and leaves the fourth alone — zero, in practice. Reported as alpha that is
        // "fully transparent everywhere", which would have made `low_opacity_ratio` 1.0 and
        // fired a transparent-overlay finding on every single frame this adapter captured.
        guard_vision::stats_from_pixels(
            &self.px,
            self.width,
            self.height,
            timestamp_ms,
            true,
            guard_vision::AlphaChannel::Padding,
        )
    }
}

/// Capture the foreground window.
pub fn capture_foreground() -> Result<Frame, String> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return Err("no foreground window".into());
        }
        capture_window(hwnd)
    }
}

/// Capture one window's client rendering into a BGRA buffer.
pub fn capture_window(hwnd: HWND) -> Result<Frame, String> {
    unsafe {
        let mut rect = Default::default();
        GetWindowRect(hwnd, &mut rect).map_err(|e| format!("GetWindowRect failed: {e}"))?;
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        if width <= 0 || height <= 0 {
            return Err(format!("window has no area ({width}x{height})"));
        }
        let pixels = (width as usize)
            .checked_mul(height as usize)
            .ok_or_else(|| "window dimensions overflow".to_string())?;
        if pixels > MAX_PIXELS {
            return Err(format!(
                "frame is {pixels} pixels, above the {MAX_PIXELS} analysis limit; refused rather \
                 than downscaled because resampling destroys the LSB plane while leaving \
                 lsb_flip_rate looking like a measurement"
            ));
        }

        let window_dc = GetWindowDC(Some(hwnd));
        if window_dc.is_invalid() {
            return Err("GetWindowDC returned no device context".into());
        }
        // From here on every early return has to release what it took, so the body is a
        // closure and the cleanup runs once on the way out.
        let result = capture_into(window_dc, hwnd, width, height, pixels);
        ReleaseDC(Some(hwnd), window_dc);
        result
    }
}

unsafe fn capture_into(
    window_dc: windows::Win32::Graphics::Gdi::HDC,
    _hwnd: HWND,
    width: i32,
    height: i32,
    pixels: usize,
) -> Result<Frame, String> {
    let mem_dc = CreateCompatibleDC(Some(window_dc));
    if mem_dc.is_invalid() {
        return Err("CreateCompatibleDC failed".into());
    }

    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: core::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            // Negative height requests a top-down DIB. A bottom-up buffer would put row 0
            // at the bottom, and the frame digest defines row 0 as the top — the two sides
            // would disagree on every comparison while both looking well-formed.
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut bits: *mut core::ffi::c_void = core::ptr::null_mut();
    let bitmap = match CreateDIBSection(Some(mem_dc), &info, DIB_RGB_COLORS, &mut bits, None, 0) {
        Ok(b) if !b.is_invalid() && !bits.is_null() => b,
        Ok(_) | Err(_) => {
            let _ = DeleteDC(mem_dc);
            return Err("CreateDIBSection failed".into());
        }
    };

    let previous = SelectObject(mem_dc, HGDIOBJ(bitmap.0));
    // CAPTUREBLT includes layered windows, which is what a transparent overlay is drawn as.
    // Without it the very windows this project exists to notice are excluded from the copy.
    let blt = BitBlt(
        mem_dc,
        0,
        0,
        width,
        height,
        Some(window_dc),
        0,
        0,
        SRCCOPY | CAPTUREBLT,
    );

    let out = match blt {
        Ok(()) => {
            let byte_len = pixels * 4;
            let mut px = vec![0u8; byte_len];
            core::ptr::copy_nonoverlapping(bits as *const u8, px.as_mut_ptr(), byte_len);
            Ok(Frame {
                px,
                width: width as u32,
                height: height as u32,
            })
        }
        Err(e) => Err(format!("BitBlt failed: {e}")),
    };

    // `info` is only read by CreateDIBSection; naming it here keeps the compiler from
    // warning about an unused mutable while documenting that it must outlive the section.
    let _ = &mut info;
    if !previous.is_invalid() {
        SelectObject(mem_dc, previous);
    }
    let _ = DeleteObject(HGDIOBJ(bitmap.0));
    let _ = DeleteDC(mem_dc);
    out
}
