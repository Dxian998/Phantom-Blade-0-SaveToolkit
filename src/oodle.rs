use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

type FnDecompress = unsafe extern "system" fn(
    comp_buf: *const u8,
    comp_len: usize,
    raw_buf: *mut u8,
    raw_len: usize,
    fuzz_safe: i32,
    check_crc: i32,
    verbosity: i32,
    dec_buf_base: *mut u8,
    dec_buf_size: usize,
    fp_callback: *mut std::ffi::c_void,
    callback_user_data: *mut std::ffi::c_void,
    decoder_memory: *mut std::ffi::c_void,
    decoder_memory_size: usize,
    thread_phase: i32,
) -> usize;

type FnCompress = unsafe extern "system" fn(
    compressor: i32,
    raw_buf: *const u8,
    raw_len: usize,
    comp_buf: *mut u8,
    level: i32,
    p_options: *const std::ffi::c_void,
    dictionary_base: *const std::ffi::c_void,
    lrm: *const std::ffi::c_void,
    scratch_mem: *mut std::ffi::c_void,
    scratch_size: usize,
) -> usize;

#[cfg(windows)]
unsafe extern "system" {
    fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *mut std::ffi::c_void;
}

pub struct Oodle {
    decompress_fn: FnDecompress,
    compress_fn: FnCompress,
}

unsafe impl Send for Oodle {}
unsafe impl Sync for Oodle {}

static OODLE_INSTANCE: OnceLock<Option<Oodle>> = OnceLock::new();

impl Oodle {
    pub fn get() -> Option<&'static Oodle> {
        OODLE_INSTANCE.get_or_init(|| Self::init().ok()).as_ref()
    }

    fn init() -> Result<Self> {
        let dll_path = Self::find_dll()
            .context("oo2core_9_win64.dll not found. Please place oo2core_9_win64.dll in the same directory as pbz-savecrypt.exe")?;

        #[cfg(windows)]
        {
            let c_path = CString::new(dll_path.to_string_lossy().as_bytes())?;
            let handle = unsafe { LoadLibraryA(c_path.as_ptr() as *const u8) };
            if handle.is_null() {
                bail!("LoadLibraryA failed for: {:?}", dll_path);
            }

            let dec_sym = CString::new("OodleLZ_Decompress")?;
            let dec_ptr = unsafe { GetProcAddress(handle, dec_sym.as_ptr() as *const u8) };
            if dec_ptr.is_null() {
                bail!("GetProcAddress failed for OodleLZ_Decompress in {:?}", dll_path);
            }

            let comp_sym = CString::new("OodleLZ_Compress")?;
            let comp_ptr = unsafe { GetProcAddress(handle, comp_sym.as_ptr() as *const u8) };
            if comp_ptr.is_null() {
                bail!("GetProcAddress failed for OodleLZ_Compress in {:?}", dll_path);
            }

            let decompress_fn: FnDecompress = unsafe { std::mem::transmute(dec_ptr) };
            let compress_fn: FnCompress = unsafe { std::mem::transmute(comp_ptr) };

            Ok(Self {
                decompress_fn,
                compress_fn,
            })
        }

        #[cfg(not(windows))]
        {
            bail!("Oodle dynamic loading only supported on Windows.");
        }
    }

    fn find_dll() -> Option<PathBuf> {
        if let Ok(mut exe) = std::env::current_exe() {
            exe.pop();
            let p = exe.join("oo2core_9_win64.dll");
            if p.exists() {
                return Some(p);
            }
        }

        let cwd_dll = Path::new("oo2core_9_win64.dll");
        if cwd_dll.exists() {
            return Some(cwd_dll.to_path_buf());
        }

        None
    }

    pub fn decompress_data(&self, comp: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; uncompressed_size];
        let ret = unsafe {
            (self.decompress_fn)(
                comp.as_ptr(),
                comp.len(),
                out.as_mut_ptr(),
                uncompressed_size,
                1, 0, 0,
                std::ptr::null_mut(), 0,
                std::ptr::null_mut(), std::ptr::null_mut(),
                std::ptr::null_mut(), 0,
                0,
            )
        };
        if ret != uncompressed_size {
            bail!("OodleLZ_Decompress failed: expected {} bytes, got {}", uncompressed_size, ret);
        }
        Ok(out)
    }

    pub fn compress_data(&self, raw: &[u8], level: i32) -> Result<Vec<u8>> {
        let max_comp_len = raw.len() + 65536;
        let mut out = vec![0u8; max_comp_len];

        // 8 = kraken compressor
        let comp_len = unsafe {
            (self.compress_fn)(
                8,
                raw.as_ptr(),
                raw.len(),
                out.as_mut_ptr(),
                level,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
            )
        };
        if comp_len == 0 {
            bail!("OodleLZ_Compress failed to compress payload");
        }
        out.truncate(comp_len);
        Ok(out)
    }
}
