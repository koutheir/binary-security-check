// Copyright 2018-2023 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{operation}({path}) failed")]
    IO1 {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
        // Add this when `Backtrace` becomes stable.
        //backtrace: Backtrace,
    },

    #[error("{operation}() failed")]
    Goblin {
        operation: &'static str,
        #[source]
        source: goblin::error::Error,
        // Add this when `Backtrace` becomes stable.
        //backtrace: Backtrace,
    },

    #[error("{operation}({param1}) failed")]
    Goblin1 {
        operation: &'static str,
        param1: String,
        #[source]
        source: goblin::error::Error,
        // Add this when `Backtrace` becomes stable.
        //backtrace: Backtrace,
    },

    #[error("logging initialization failed")]
    LogInitialization(#[from] log::SetLoggerError),

    #[error("Binary format of file '{0}' is not recognized")]
    UnknownBinaryFormat(PathBuf),

    #[error("Binary format of '{name}' is not {expected}")]
    UnexpectedBinaryFormat {
        expected: &'static str,
        name: PathBuf,
    },

    #[error("Architecture of '{0}' is unexpected")]
    UnexpectedBinaryArchitecture(PathBuf),

    #[error("Binary format '{format}' of file '{path}' is recognized but unsupported")]
    UnsupportedBinaryFormat { format: String, path: PathBuf },

    #[error("Dependent C runtime library is not recognized")]
    UnrecognizedNeededLibC,

    #[error("Dependent C runtime library '{0}' was not found")]
    NotFoundNeededLibC(PathBuf),
}

impl Error {
    pub fn from_io1(
        source: std::io::Error,
        operation: &'static str,
        path: impl Into<PathBuf>,
    ) -> Self {
        let path = path.into();
        Self::IO1 {
            operation,
            path,
            source,
        }
    }
}
