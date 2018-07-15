// Copyright 2018 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::fmt::Display;
use std::{fmt, result};

pub use failure::{Backtrace, Context, Fail, ResultExt};

pub type Result<T> = result::Result<T, Error>;

/// A plain enum with no data in any of its variants.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Failed to initialize logging")]
    LogInitialization,

    #[fail(display = "Failed to open file for reading")]
    OpenFileForReading,

    #[fail(display = "Failed to write to file")]
    WriteFile,

    #[fail(display = "Failed to map file contents for read-only access")]
    MapReadOnlyFile,

    #[fail(display = "Failed to parse binary file")]
    ParseBinary,

    #[fail(display = "Failed to extract archive member")]
    ExtractArchiveMember,

    #[fail(display = "Binary file format is not recognized")]
    UnknownBinaryFormat,

    #[fail(display = "Binary file format is recognized but unexpected")]
    UnexpectedBinaryFormat,

    #[fail(display = "Binary file format is recognized but unsupported")]
    UnsupportedBinaryFormat,

    #[fail(display = "Dependent C runtime library is not recognized")]
    UnrecognizedNeededLibC,

    #[fail(display = "Dependent C runtime library was not found")]
    NotFoundNeededLibC,
}

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

/*
impl Error {
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}
*/

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Self {
        Self { inner }
    }
}
