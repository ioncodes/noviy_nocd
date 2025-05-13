#[macro_use]
mod common;
mod patcher;
mod pattern;

use clap::Parser;
use patcher::Patcher;
use std::{fs, path::PathBuf};

#[derive(Parser)]
struct Cli {
    #[clap(name = "input")]
    pub input_path: String,
    #[clap(name = "output")]
    pub output_path: Option<String>,
}

fn main() {
    let args = Cli::parse();

    let input_path = PathBuf::from(args.input_path);
    let output_path = if args.output_path.is_none() {
        let filename = input_path.file_stem().unwrap_or_default();
        let extension = input_path.extension().unwrap_or_default();
        input_path
            .parent()
            .unwrap_or_else(|| "".as_ref())
            .join(format!(
                "{}.nocd.{}",
                filename.to_string_lossy(),
                extension.to_string_lossy()
            ))
    } else {
        PathBuf::from(args.output_path.unwrap())
    };

    let buffer = fs::read(&input_path)
        .unwrap_or_else(|_| panic!("Failed to read file: {}", input_path.display()));

    println!("Patching: {}", input_path.display());
    println!("Output: {}", output_path.display());
    println!("File size: {} bytes", buffer.len());

    let mut patcher = Patcher::new(buffer);
    println!("Image base: 0x{:04X}", patcher.get_base_address());

    patcher.patch_checksum_checks();
    patcher.patch_early_cd_checks();
    patcher.patch_deco_checks();

    println!("\nWriting: {}", output_path.display());
    fs::write(&output_path, patcher.buffer())
        .unwrap_or_else(|_| panic!("Failed to write file: {}", output_path.display()));
}
