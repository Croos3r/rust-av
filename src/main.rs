use std::{
    fmt::Display,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::Context;
use clap::Parser;
use itertools::Itertools;
use malware_oracle::MalwareOracle;
use scan::{generate_report_for_scans, scan_contents};
use simple_logger::SimpleLogger;

use crate::{
    contents::load_contents_for_paths,
    malware_oracle::{text_file_database::TextFileDatabase, yara::Yara},
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

fn init_logger() {
    SimpleLogger::new()
        .with_colors(true)
        .with_level(log::LevelFilter::Warn)
        .env()
        .with_local_timestamps()
        .init()
        .unwrap();
}

fn main() -> ExitCode {
    init_logger();

    match run() {
        Ok(code) => code,
        Err(err) => {
            log::error!("{err:#}");
            err.exit_code
        }
    }
}

#[derive(Debug)]
struct RustAVError {
    error: anyhow::Error,
    exit_code: ExitCode,
}

impl RustAVError {
    fn new(error: anyhow::Error, exit_code: ExitCode) -> Self {
        Self { error, exit_code }
    }

    fn factory_for_code(exit_code: u8) -> impl FnOnce(anyhow::Error) -> Self {
        move |error| Self::new(error, exit_code.into())
    }
}

impl From<anyhow::Error> for RustAVError {
    fn from(value: anyhow::Error) -> Self {
        Self::new(value, 1.into())
    }
}

impl Display for RustAVError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

fn run() -> Result<ExitCode, RustAVError> {
    let args = Arguments::try_parse()
        .context("Could not parse arguments")
        .map_err(RustAVError::factory_for_code(2))?;

    let tfd_oracle = TextFileDatabase::new(Path::new("malwares.txt"));
    let yara_oracle = Yara::new();
    let tfd_oracle = tfd_oracle.map_err(RustAVError::factory_for_code(3))?;
    let yara_oracle = yara_oracle.map_err(RustAVError::factory_for_code(3))?;

    let contents = load_contents_for_paths(args.file_or_directory_paths)
        .map_err(RustAVError::factory_for_code(4))?;
    log::info!(
        "Got contents of {} final entries, scanning for malware...",
        contents.len()
    );

    let scans = scan_contents(&tfd_oracle, contents.clone())
        .into_iter()
        .chain(scan_contents(&yara_oracle, contents))
        .collect_vec();
    log::info!("Finished scanning, generating report...");

    let malware_found_count = generate_report_for_scans(scans);

    Ok(if malware_found_count > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}
