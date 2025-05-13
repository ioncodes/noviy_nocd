#![cfg(target_arch = "wasm32")]

extern crate console_error_panic_hook;
extern crate wasm_bindgen;

mod patcher;
mod pattern;

use patcher::Patcher;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("test");
}

#[wasm_bindgen]
pub fn patch(input: &[u8]) -> Vec<u8> {
    // redirect panic messages to the console
    console_error_panic_hook::set_once();

    // patch the input buffer
    let mut patcher = Patcher::new(input.to_vec());
    patcher.patch_checksum_checks();
    patcher.patch_early_cd_checks();
    patcher.patch_deco_checks();
    Vec::from(patcher.buffer())
}
