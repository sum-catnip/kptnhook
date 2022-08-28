use std::env;
use std::io::Result as IOResult;
use std::process;

pub fn procname() -> IOResult<Option<String>> {
    Ok(env::current_exe()?.file_name().map(|f| f.to_string_lossy().into_owned()))
}

pub fn pid() -> u32 { process::id() }