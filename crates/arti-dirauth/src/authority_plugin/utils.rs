//! Utilities

use std::fs::{self, File};
use std::io::{self, BufWriter, Write as _};
use std::ops::RangeInclusive;
use std::str::FromStr;

use anyhow::{Context as _, anyhow};

use super::CliError;

/// Command line filename argument, allowing `-` for stdin/stdout
//
// TODO DIRAUTH currently this can only be used for output file arguments,
// but we will implement using this for an input file argument too.
//
// TODO move this somewhere deeper in the stack (tor-basic-utils even maybe?)
// and replace open-coding in eg crates/arti/src/subcommands/hsc.rs display_service_discovery_key
#[derive(Debug, Clone)]
pub(super) enum FilenameOrStdio {
    /// Filename
    Path(String),
    /// `-`
    Stdio,
}

impl FromStr for FilenameOrStdio {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Err(anyhow!("empty filename")),
            "-" => Ok(FilenameOrStdio::Stdio),
            other => Ok(FilenameOrStdio::Path(other.to_owned())),
        }
    }
}

impl FilenameOrStdio {
    /// Write the output file, with write-to-`.tmp`-and-rename
    ///
    /// `writer` should generate the actual output.
    /// It shouldn't fail other than for write errors.
    pub(super) fn write<W>(&self, writer: W) -> Result<(), CliError>
    where
        W: FnOnce(&mut dyn io::Write) -> io::Result<()>,
    {
        match self {
            FilenameOrStdio::Stdio => writer(&mut io::stdout().lock()).context("write to stdout"),
            FilenameOrStdio::Path(p) => (|| {
                let tmp = format!("{p}.tmp");
                let f = File::create(&tmp).with_context(|| format!("create {tmp:?}"))?;
                let mut f = BufWriter::new(f);
                (|| {
                    writer(&mut f)?;
                    f.flush()
                })()
                .with_context(|| format!("write {tmp:?}"))?;
                fs::rename(&tmp, p).with_context(|| format!("install {tmp:?} as {p:?}"))
            })(),
        }
        .context("write output")
        .map_err(CliError::OperationalError)
    }
}

/// What `RangeInclusive::map` ought to be
///
/// Open-coding this at the call site would risk accidental change of the range type,
/// changing inclusiveness, etc.  This function has the same range type as argument and return.
pub(super) fn map_range<T, U>(
    r: &RangeInclusive<T>,
    mut f: impl FnMut(&T) -> U,
) -> RangeInclusive<U> {
    f(r.start())..=f(r.end())
}
