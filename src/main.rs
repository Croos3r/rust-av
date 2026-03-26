use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Ok;
use clap::Parser;
use malware_oracle::MalwareOracle;
use scan::{generate_report_for_scans, scan_contents};
use simple_logger::SimpleLogger;

use crate::{
    contents::load_contents_for_paths, malware_oracle::text_file_database::TextFileDatabase,
};

mod contents;
mod malware_oracle;
mod scan;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Arguments {
    /// Path of the files or directories to scan
    #[arg(num_args=1.., required=true)]
    file_or_directory_paths: Vec<PathBuf>,
}

fn main() -> anyhow::Result<ExitCode> {
    SimpleLogger::new()
        .with_colors(true)
        .env()
        .with_local_timestamps()
        .init()
        .unwrap();
    let args = Arguments::parse();

    let oracle = TextFileDatabase::new(Path::new("malwares.txt"))?;

    let contents = load_contents_for_paths(args.file_or_directory_paths)?;
    log::info!(
        "Got contents of {} final entries, scanning for malware...",
        contents.len()
    );

    let scans = scan_contents(&oracle, contents);
    log::info!("Finished scanning, generating report...");

    generate_report_for_scans(scans);

    Ok(ExitCode::from(0))
}
