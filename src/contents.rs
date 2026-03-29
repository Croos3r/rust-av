use std::{
    error::Error,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use itertools::Itertools;
use rayon::prelude::*;

pub(crate) fn load_contents_for_paths<O: TryFrom<Vec<u8>> + Send>(
    paths: Vec<PathBuf>,
) -> anyhow::Result<Vec<(PathBuf, O)>>
where
    <O as TryFrom<Vec<u8>>>::Error: Send + Sync + Error + 'static,
{
    log::info!("Reading contents of {} entries...", paths.len());
    paths
        .into_par_iter()
        .map(|path| load_content(&path))
        .collect::<anyhow::Result<Vec<_>>>()
        .map(|res| res.into_iter().flatten().collect_vec())
        .context("Could not read all contents")
}

pub(crate) fn load_content<O: TryFrom<Vec<u8>> + Send>(
    file_path: &Path,
) -> anyhow::Result<Vec<(PathBuf, O)>>
where
    <O as TryFrom<Vec<u8>>>::Error: Send + Sync + Error + 'static,
{
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

pub(crate) fn load_directory_contents<O: TryFrom<Vec<u8>> + Send>(
    dir_path: &Path,
) -> anyhow::Result<Vec<(PathBuf, O)>>
where
    <O as TryFrom<Vec<u8>>>::Error: Send + Sync + Error + 'static,
{
    log::info!("Reading directory entries of {}", dir_path.display());
    let dir_reader = dir_path
        .read_dir()
        .context(format!("Could not read directory {}", dir_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .context("Could not read dir entry")?;

    dir_reader
        .into_par_iter()
        .map(|dir_entry| load_content(&dir_entry.path()))
        .collect::<anyhow::Result<Vec<_>>>()
        .map(|res| res.into_iter().flatten().collect_vec())
}

pub(crate) fn load_file_content<O: TryFrom<Vec<u8>> + Send>(
    file_path: &Path,
) -> anyhow::Result<(PathBuf, O)>
where
    <O as TryFrom<Vec<u8>>>::Error: Send + Sync + Error + 'static,
{
    log::info!("Reading file {}", file_path.display());
    std::fs::read(file_path)
        .context(format!("Could not read {}", file_path.display()))
        .map(|content| (file_path.to_path_buf(), content))
        .and_then(|(file_path, content)| {
            content
                .try_into()
                .context("Could not convert to requested type")
                .map(|content| (file_path, content))
        })
}
