// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::path::PathBuf;

pub(crate) type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("failed to {operation}. Path: {path}")]
    IO1 {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
        // Add this when `Backtrace` becomes stable.
        //backtrace: Backtrace,
    },

    #[error("failed to parse file")]
    ParseFile {
        #[source]
        source: goblin::error::Error,
        // Add this when `Backtrace` becomes stable.
        //backtrace: Backtrace,
    },

    #[error("failed to extract archive member: {member}")]
    ExtractArchiveMember {
        member: String,
        #[source]
        source: goblin::error::Error,
        // Add this when `Backtrace` becomes stable.
        //backtrace: Backtrace,
    },

    #[error("logging initialization failed")]
    LogInitialization(#[from] log::SetLoggerError),

    #[error("binary format of file '{0}' is not recognized")]
    UnknownBinaryFormat(PathBuf),

    #[error("binary format of '{name}' is not {expected}")]
    UnexpectedBinaryFormat {
        expected: &'static str,
        name: PathBuf,
    },

    #[error("architecture of '{0}' is unexpected")]
    UnexpectedBinaryArchitecture(PathBuf),

    #[error("binary format '{format}' of file '{path}' is recognized but unsupported")]
    UnsupportedBinaryFormat { format: String, path: PathBuf },

    #[error("dependent C runtime library is not recognized. Consider specifying --sysroot, --libc, --libc-spec or --no-libc")]
    UnrecognizedNeededLibC,

    #[error("dependent C runtime library '{0}' was not found")]
    NotFoundNeededLibC(PathBuf),

    #[error(transparent)]
    FromBytesWithNul(#[from] core::ffi::FromBytesWithNulError),

    #[error(transparent)]
    FromBytesUntilNul(#[from] core::ffi::FromBytesUntilNulError),

    #[error(transparent)]
    Scroll(#[from] scroll::Error),

    #[error(transparent)]
    DynamicLoaderCache(#[from] dynamic_loader_cache::Error),
}

impl Error {
    pub(crate) fn from_io1(
        source: std::io::Error,
        operation: &'static str,
        path: impl Into<PathBuf>,
    ) -> Self {
        Self::IO1 {
            operation,
            path: path.into(),
            source,
        }
    }
}
