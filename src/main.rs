use std::{
    collections::HashMap,
    fmt::Display,
    path::{Path, PathBuf},
    process::ExitCode,
};

use itertools::Itertools;

use anyhow::{Context, Ok, Result, bail};
use clap::Parser;
use sha1::Digest;
use simple_logger::SimpleLogger;

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

fn generate_report_for_scans(scans: Vec<(PathBuf, ScanStatus)>) -> usize {
    let scan_counts = scans.iter().counts_by(|scan| &scan.1);
    let clean_count = scan_counts.get(&ScanStatus::Clean).unwrap_or(&0usize);
    let unsure_count = scan_counts.get(&ScanStatus::Unsure).unwrap_or(&0usize);
    let malware_count = scans.len() - (clean_count + unsure_count);

    log::info!(
        "Scanned {} entries ({} clean(s), {} unsure(s), {} malware(s)):",
        scans.len(),
        clean_count,
        unsure_count,
        malware_count
    );
    for (path, scan_status) in scans.iter().sorted_by_key(|(_, status)| status) {
        log::info!("[{scan_status}] {}", path.display());
    }

    malware_count
}

fn scan_contents(
    oracle: &impl MalwareOracle,
    contents: Vec<(PathBuf, Vec<u8>)>,
) -> Vec<(PathBuf, ScanStatus)> {
    contents
        .into_iter()
        .map(|(file_path, content)| (file_path, oracle.is_malware(&content)))
        .collect()
}

fn load_contents_for_paths(paths: Vec<PathBuf>) -> anyhow::Result<Vec<(PathBuf, Vec<u8>)>> {
    log::info!("Reading contents of {} entries...", paths.len());
    paths
        .into_iter()
        .map(|path| load_content(&path))
        .collect::<Result<Vec<_>>>()
        .map(|res| res.into_iter().flatten().collect::<Vec<_>>())
        .context("Could not read all contents")
}

fn load_content(file_path: &Path) -> anyhow::Result<Vec<(PathBuf, Vec<u8>)>> {
    if file_path.is_dir() {
        log::info!(
            "Loading directory {} files' contents...",
            file_path.display()
        );
        load_directory_contents(file_path)
    } else if file_path.is_file() {
        log::info!("Loading file {}'s content...", file_path.display());
        load_file_content(file_path).map(|content| vec![content])
    } else {
        log::error!(
            "{} is not a directory or a regular file, aborting...",
            file_path.display()
        );
        bail!(
            "{} is not a directory or a regular file",
            file_path.display()
        );
    }
}

fn load_directory_contents(dir_path: &Path) -> anyhow::Result<Vec<(PathBuf, Vec<u8>)>> {
    log::info!("Reading directory entries of {}", dir_path.display());
    let dir_reader = dir_path
        .read_dir()
        .context(format!("Could not read directory {}", dir_path.display()))?;

    dir_reader
        .map(|dir_entry| {
            let dir_entry = dir_entry.context("Could not read dir entry")?;
            let contents = load_content(&dir_entry.path());
            contents
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(|res| res.into_iter().flatten().collect::<Vec<_>>())
}

fn load_file_content(file_path: &Path) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    log::info!("Reading file {}", file_path.display());
    std::fs::read(file_path)
        .context(format!("Could not read {}", file_path.display()))
        .map(|content| (file_path.to_path_buf(), content))
}

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ScanStatus {
    Clean,
    Unsure,
    Malware(String),
}

impl Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Clean => f.write_str("Clean"),
            ScanStatus::Unsure => f.write_str("Unsure"),
            ScanStatus::Malware(name) => write!(f, "Malware \"{name}\""),
        }
    }
}

trait MalwareOracle {
    fn is_malware(&self, content: &[u8]) -> ScanStatus;
}

struct TextFileDatabase<'a> {
    file_path: &'a Path,
    cache: HashMap<Vec<u8>, String>,
}

impl<'a> TextFileDatabase<'a> {
    pub fn new(file_path: &'a Path) -> anyhow::Result<Self> {
        let cache = Self::load_all_database_entries(file_path)?;
        log::info!("Loaded {} malware entries", cache.len());

        Ok(Self { file_path, cache })
    }

    fn load_all_database_entries(file_path: &'a Path) -> anyhow::Result<HashMap<Vec<u8>, String>> {
        log::info!(
            "Reading malware database located at {}...",
            file_path.display()
        );
        let content = std::fs::read_to_string(file_path)
            .context(format!("Could not read file {}", file_path.display()))?;

        Ok(content
            .lines()
            .filter_map(|line| {
                if line.starts_with("#") {
                    return None;
                }

                let parts: Vec<&str> = line.splitn(2, "|").collect();

                let [name, raw_hash] = parts.as_slice() else {
                    return None;
                };

                let hash = hex_to_bytes(raw_hash)?;

                log::info!("Loaded entry {name} with hash {raw_hash}");

                Some((hash, name.to_string()))
            })
            .collect())
    }
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 == 0 {
        (0..s.len())
            .step_by(2)
            .map(|i| {
                s.get(i..i + 2)
                    .and_then(|sub| u8::from_str_radix(sub, 16).ok())
            })
            .collect()
    } else {
        None
    }
}

impl MalwareOracle for TextFileDatabase<'_> {
    fn is_malware(&self, content: &[u8]) -> ScanStatus {
        let md5_hash = md5::compute(content);
        let sha256_hash = sha2::Sha256::digest(content);
        let sha1_hash = sha1::Sha1::digest(content);
        for hash in [
            md5_hash.as_slice(),
            sha256_hash.as_slice(),
            sha1_hash.as_slice(),
        ] {
            if let Some(name) = self.cache.get(hash) {
                log::warn!("Found match with {name}");
                return ScanStatus::Malware(name.clone());
            }
        }

        ScanStatus::Clean
    }
}
