use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::sync::{ Arc, Mutex };
use std::process;
use std::env;

use log::{ Log, Level, LevelFilter };

#[cfg(windows)]
extern "stdcall" {
    fn OutputDebugStringW(chars: *const u16);
}

pub fn output_debug_string(msg: impl AsRef<OsStr>) {
    let msg_wide = msg
        .as_ref()
        .encode_wide()
        .chain(Some(0)) // null terminator
        .collect::<Vec<_>>();

    unsafe { OutputDebugStringW(msg_wide.as_ptr()); }
}

static EARLY_LOGGER: EarlyLogger = EarlyLogger {};
static LOGGER: PirtLogger = PirtLogger {};

fn init() {
    log::set_logger(&EarlyLogger);
}

struct PirtLogger;
struct EarlyLogger;

impl Log for PirtLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        todo!()
    }

    fn log(&self, record: &log::Record) {
        todo!()
    }

    fn flush(&self) {
        todo!()
    }
}

impl Log for EarlyLogger {
    fn flush(&self) { }
    fn enabled(&self, _: &log::Metadata) -> bool { true }
    fn log(&self, record: &log::Record) {
        let procname = match env::current_exe() {
            Ok(p) => p.file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or("{no filename}".to_string()),
            Err(c) => format!("{{filename err {}}}", c)
        };

        output_debug_string(
            format!("kptnhook<{}@{}> {}: {}", procname, process::id(), record.args(), record.level()));
    }
}