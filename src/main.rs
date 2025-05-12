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
    let output_path = PathBuf::from(args.output_path.unwrap_or_else(|| {
        let filename = input_path.file_stem().unwrap_or_default();
        let extension = input_path.extension();

        format!(
            "{}.nocd.{}",
            filename.to_string_lossy(),
            extension.unwrap_or_default().to_string_lossy()
        )
    }));

    let buffer = fs::read(&input_path)
        .unwrap_or_else(|_| panic!("Failed to read file: {}", input_path.display()));

    println!("Patching: {}", input_path.display());
    println!("File size: {} bytes", buffer.len());

    let mut patcher = Patcher::new(buffer);
    patcher.patch_checksum_checks();
    patcher.patch_deco_checks();
}
