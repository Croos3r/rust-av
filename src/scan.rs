use itertools::Itertools;
use log::log;
use std::{fmt::Display, path::PathBuf};

use crate::MalwareOracle;

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScanStatus {
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

pub(crate) fn generate_report_for_scans(scans: Vec<(PathBuf, ScanStatus)>) -> usize {
    let scan_counts = scans.iter().counts_by(|scan| &scan.1);
    let clean_count = scan_counts.get(&ScanStatus::Clean).unwrap_or(&0usize);
    let unsure_count = scan_counts.get(&ScanStatus::Unsure).unwrap_or(&0usize);
    let malware_count = scans.len() - (clean_count + unsure_count);

    log!(
        if malware_count != 0 {
            log::Level::Warn
        } else {
            log::Level::Info
        },
        "Scanned {} entries ({} clean(s), {} unsure(s), {} malware(s)):",
        scans.len(),
        clean_count,
        unsure_count,
        malware_count
    );
    for (path, scan_status) in scans.iter().sorted_by_key(|(_, status)| status) {
        log!(
            match scan_status {
                ScanStatus::Clean => log::Level::Info,
                _ => log::Level::Warn,
            },
            "[{scan_status}] {}",
            path.display()
        );
    }

    malware_count
}

pub(crate) fn scan_contents(
    oracle: &impl MalwareOracle,
    contents: Vec<(PathBuf, Vec<u8>)>,
) -> Vec<(PathBuf, ScanStatus)> {
    contents
        .into_iter()
        .map(|(file_path, content)| (file_path, oracle.is_malware(&content)))
        .collect()
}
