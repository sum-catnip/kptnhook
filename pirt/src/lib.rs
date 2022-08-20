mod logging;

use std::fs;
use std::io::Result;
use std::sync::Once;

use log;
use log::LevelFilter;

static LOGGING_SETUP: Once = Once::new();

/*
fn index_ship() -> Result<()> {
    let dir = fs::read_dir("C:\\kptnhook\\ship")?

    Ok(())
} */

fn logging_setup() {
}

#[no_mangle]
extern "system" fn DllMain(_: *const u8, _: u32, _: *const u8) -> u32 {
    // load the other pirts from the ship
    LOGGING_SETUP.call_once(logging_setup);

    1
}