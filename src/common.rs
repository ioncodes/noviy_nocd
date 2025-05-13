#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! stdlog {
    ($($arg:tt)*) => {
        ::std::println!($($arg)*)
    };
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! stdlog {
    ($($arg:tt)*) => {
        crate::common::log(&format!($($arg)*))
    };
}
