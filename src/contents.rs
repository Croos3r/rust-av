use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use itertools::Itertools;

pub(crate) fn load_contents_for_paths(
    paths: Vec<PathBuf>,
) -> anyhow::Result<Vec<(PathBuf, Vec<u8>)>> {
    log::info!("Reading contents of {} entries...", paths.len());
    paths
        .into_iter()
        .map(|path| load_content(&path))
        .collect::<anyhow::Result<Vec<_>>>()
        .map(|res| res.into_iter().flatten().collect_vec())
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
        .map(|res| res.into_iter().flatten().collect_vec())
}

fn load_file_content(file_path: &Path) -> anyhow::Result<(PathBuf, Vec<u8>)> {
    log::info!("Reading file {}", file_path.display());
    std::fs::read(file_path)
        .context(format!("Could not read {}", file_path.display()))
        .map(|content| (file_path.to_path_buf(), content))
}
