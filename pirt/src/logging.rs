use crate::procenv;

use std::fmt::Display;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::sync::{ RwLock, RwLockReadGuard };
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

fn procname_failsafe() -> String {
    match procenv::procname() {
        Ok(name) => name.unwrap_or("{filename missing}".to_string()),
        Err(e) => format!("{{filename err {}}}", e)
    }
}

pub(crate) fn init() {
    let logger = PirtLogger::default();
    if let Err(_) = log::set_boxed_logger(Box::new(logger)) {
        log_dbg("attempted to initialize logging twice. please report this error!", Level::Error);
    }
}

pub(crate) fn configure(cfg: LoggingCfg) {

}

fn log_dbg(msg: impl Display, level: Level) {
    output_debug_string(
        format!("kptnhook<{}@{}> {}: {}",
            procname_failsafe(),
            procenv::pid(),
            msg,
            level));
}

pub(crate) struct FileLogCfg {
    level: Level
}

pub(crate) struct DbgLogCfg {
    level: Level
}

pub(crate) struct LoggingCfg {
    level: Level,
    dbg: DbgLogCfg,
    file: FileLogCfg
}

#[derive(Default)]
struct PirtLogger {
    cfg: RwLock<Option<LoggingCfg>>
}

impl PirtLogger {
    fn cfg(&self) -> RwLockReadGuard<Option<LoggingCfg>> {
        self.cfg.read().unwrap_or_else(|_| {
            log_dbg("logging lock is poisoned, check logs for further errors", Level::Error);
            panic!("logging lock is poisoned, check logs for further errors");
        })
    }
}

impl Log for PirtLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        match self.cfg.read() {
            // logging no configured yet
            Ok(x) => x
                .as_ref()
                .map(|x| metadata.level() >= x.level)
                .unwrap_or(true),
            Err(_) => {
                log_dbg("logging lock is poisoned, please report this error.", Level::Error);
                true
            }
        }
    }

    fn log(&self, record: &log::Record) {
        if let Some(lock) = &*self.cfg() {
            if lock.dbg.level >= record.level() {
                log_dbg(record.args(), record.level()); 
            }

            if lock.file.level >= record.level() {
                todo!();
            }
        }
        else { log_dbg(record.args(), record.level()); }
    }

    fn flush(&self) {
        todo!()
    }
}