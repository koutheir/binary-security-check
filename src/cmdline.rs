// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use core::fmt;
use std::path::PathBuf;

use crate::elf;

const HELP_TEMPLATE: &str = "{before-help}{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
\u{1b}[1m\u{1b}[4mAuthors:\u{1b}[24m\u{1b}[22m
{tab}{author-with-newline}";

#[derive(Debug, clap::Parser)]
#[command(
    author,
    version,
    about,
    next_line_help = true,
    help_template = HELP_TEMPLATE,
    after_help = include_str!("command-line-after-help.txt"),
)]
pub(crate) struct Options {
    /// Verbose logging.
    #[arg(short = 'v', long, global = true, default_value_t = false)]
    pub(crate) verbose: bool,

    /// Use color in standard output.
    #[arg(short = 'c', long, global = true, value_enum, default_value_t = UseColor::Auto)]
    pub(crate) color: UseColor,

    /// Path of the C runtime library file.
    #[arg(short = 'l', long, conflicts_with_all = ["sysroot", "libc_spec", "no_libc"])]
    pub(crate) libc: Option<PathBuf>,

    /// Path of the system root for finding the corresponding C runtime library.
    #[arg(short = 's', long, conflicts_with_all = ["libc", "libc_spec", "no_libc"])]
    pub(crate) sysroot: Option<PathBuf>,

    /// Use an internal list of checked functions as specified by a specification.
    #[arg(short = 'i', long, value_enum, conflicts_with_all = ["libc", "sysroot", "no_libc"])]
    pub(crate) libc_spec: Option<LibCSpec>,

    /// Assume that input files do not use any C runtime libraries.
    #[arg(short = 'n', long, default_value_t = false, conflicts_with_all = ["libc", "sysroot", "libc_spec"])]
    pub(crate) no_libc: bool,

    /// Binary files to analyze.
    #[arg(required = true, value_hint = clap::ValueHint::FilePath)]
    pub(crate) input_files: Vec<PathBuf>,
}

#[derive(Debug, Copy, Clone, clap::ValueEnum)]
pub(crate) enum UseColor {
    Auto,
    Always,
    Never,
}

impl From<UseColor> for termcolor::ColorChoice {
    fn from(other: UseColor) -> Self {
        match other {
            UseColor::Auto => termcolor::ColorChoice::Auto,
            UseColor::Always => termcolor::ColorChoice::Always,
            UseColor::Never => termcolor::ColorChoice::Never,
        }
    }
}

// If this changes, then update the command line reference.
#[derive(Debug, Copy, Clone, clap::ValueEnum)]
pub(crate) enum LibCSpec {
    LSB1,
    LSB1dot1,
    LSB1dot2,
    LSB1dot3,
    LSB2,
    LSB2dot0dot1,
    LSB2dot1,
    LSB3,
    LSB3dot1,
    LSB3dot2,
    LSB4,
    LSB4dot1,
    LSB5,
}

impl fmt::Display for LibCSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let spec_name = match *self {
            LibCSpec::LSB1
            | LibCSpec::LSB1dot1
            | LibCSpec::LSB1dot2
            | LibCSpec::LSB1dot3
            | LibCSpec::LSB2
            | LibCSpec::LSB2dot0dot1
            | LibCSpec::LSB2dot1
            | LibCSpec::LSB3
            | LibCSpec::LSB3dot1
            | LibCSpec::LSB3dot2
            | LibCSpec::LSB4
            | LibCSpec::LSB4dot1
            | LibCSpec::LSB5 => "Linux Standard Base",
        };

        let spec_version = match *self {
            LibCSpec::LSB1 => "1.0.0",
            LibCSpec::LSB1dot1 => "1.1.0",
            LibCSpec::LSB1dot2 => "1.2.0",
            LibCSpec::LSB1dot3 => "1.3.0",
            LibCSpec::LSB2 => "2.0.0",
            LibCSpec::LSB2dot0dot1 => "2.0.1",
            LibCSpec::LSB2dot1 => "2.1.0",
            LibCSpec::LSB3 => "3.0.0",
            LibCSpec::LSB3dot1 => "3.1.0",
            LibCSpec::LSB3dot2 => "3.2.0",
            LibCSpec::LSB4 => "4.0.0",
            LibCSpec::LSB4dot1 => "4.1.0",
            LibCSpec::LSB5 => "5.0.0",
        };

        write!(f, "{spec_name} {spec_version}")
    }
}

impl LibCSpec {
    pub(crate) fn get_functions_with_checked_versions(self) -> &'static [&'static str] {
        match self {
            LibCSpec::LSB1
            | LibCSpec::LSB1dot1
            | LibCSpec::LSB1dot2
            | LibCSpec::LSB1dot3
            | LibCSpec::LSB2
            | LibCSpec::LSB2dot0dot1
            | LibCSpec::LSB2dot1
            | LibCSpec::LSB3
            | LibCSpec::LSB3dot1
            | LibCSpec::LSB3dot2 => &[],

            LibCSpec::LSB4 | LibCSpec::LSB4dot1 | LibCSpec::LSB5 => {
                elf::checked_functions::LSB_4_0_0_FUNCTIONS_WITH_CHECKED_VERSIONS
            }
        }
    }
}
