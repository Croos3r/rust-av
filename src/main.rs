use std::{path::PathBuf, process::ExitCode};

use anyhow::{Ok, Result, anyhow, bail};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Arguments {
    /// Path of the files or directories to scan
    #[arg(num_args=1.., required=true)]
    file_or_directory_paths: Vec<PathBuf>,
}

fn check_paths_to_read(paths: &Vec<PathBuf>) -> Result<()> {
    for path in paths {
        if !path.is_dir() && !path.is_file() {
            bail!("{} is not a regular file or a directory.", path.display());
        }
        if path
            .metadata()
            .map(|metadata| metadata.permissions().readonly())
            .map_err(|err| anyhow!("{} metadata is not readable: {err}", path.display()))?
        {
            bail!("{} is not readable.", path.display());
        }
    }

    Ok(())
}

fn main() -> Result<ExitCode> {
    let args = Arguments::parse();

    // Exit with an error if a path is not a file or a directory or if a path is not readable
    check_paths_to_read(&args.file_or_directory_paths)?;

    dbg!(args);

    Ok(ExitCode::from(0))
}

#[derive(Debug)]
enum ScanStatus {
    Clean,
    Unsure,
    Malware,
}

fn scan_content(_content: &str) -> Result<ScanStatus> {
    Ok(ScanStatus::Clean)
}
