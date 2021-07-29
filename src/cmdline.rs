// Copyright 2018-2021 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::fmt;
use std::path::PathBuf;

use docopt::Docopt;
use serde_derive::Deserialize;

use crate::elf;

#[derive(Debug, Deserialize)]
pub struct Args {
    pub flag_verbose: bool,
    pub flag_sysroot: Option<PathBuf>,
    pub flag_libc: Option<PathBuf>,
    pub flag_libc_spec: Option<LibCSpec>,
    pub flag_color: UseColor,
    pub arg_file: Vec<PathBuf>,
}

lazy_static::lazy_static! {
    pub static ref ARGS: Args = parse_command_line();
}

static PKG_NAME: &str = env!("CARGO_PKG_NAME");
static PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
static PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
static PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

fn parse_command_line() -> Args {
    let usage = format!(
        include_str!("cmdline.docopt"),
        PKG_NAME, PKG_DESCRIPTION, PKG_VERSION, PKG_AUTHORS
    );

    let version = format!("{} version {}", PKG_NAME, PKG_VERSION);

    Docopt::new(usage)
        .and_then(|d| d.help(true).version(Some(version)).deserialize())
        .unwrap_or_else(|e| e.exit())
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Deserialize)]
pub enum UseColor {
    auto,
    always,
    never,
}

impl From<UseColor> for termcolor::ColorChoice {
    fn from(other: UseColor) -> Self {
        match other {
            UseColor::auto => termcolor::ColorChoice::Auto,
            UseColor::always => termcolor::ColorChoice::Always,
            UseColor::never => termcolor::ColorChoice::Never,
        }
    }
}

// If this changes, then update the command line reference.
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Deserialize)]
pub enum LibCSpec {
    lsb1,
    lsb1dot1,
    lsb1dot2,
    lsb1dot3,
    lsb2,
    lsb2dot0dot1,
    lsb2dot1,
    lsb3,
    lsb3dot1,
    lsb3dot2,
    lsb4,
    lsb4dot1,
    lsb5,
}

impl fmt::Display for LibCSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LibCSpec::lsb1
            | LibCSpec::lsb1dot1
            | LibCSpec::lsb1dot2
            | LibCSpec::lsb1dot3
            | LibCSpec::lsb2
            | LibCSpec::lsb2dot0dot1
            | LibCSpec::lsb2dot1
            | LibCSpec::lsb3
            | LibCSpec::lsb3dot1
            | LibCSpec::lsb3dot2
            | LibCSpec::lsb4
            | LibCSpec::lsb4dot1
            | LibCSpec::lsb5 => write!(f, "Linux Standard Base ")?,
        }

        match self {
            LibCSpec::lsb1 => write!(f, "1.0.0"),
            LibCSpec::lsb1dot1 => write!(f, "1.1.0"),
            LibCSpec::lsb1dot2 => write!(f, "1.2.0"),
            LibCSpec::lsb1dot3 => write!(f, "1.3.0"),
            LibCSpec::lsb2 => write!(f, "2.0.0"),
            LibCSpec::lsb2dot0dot1 => write!(f, "2.0.1"),
            LibCSpec::lsb2dot1 => write!(f, "2.1.0"),
            LibCSpec::lsb3 => write!(f, "3.0.0"),
            LibCSpec::lsb3dot1 => write!(f, "3.1.0"),
            LibCSpec::lsb3dot2 => write!(f, "3.2.0"),
            LibCSpec::lsb4 => write!(f, "4.0.0"),
            LibCSpec::lsb4dot1 => write!(f, "4.1.0"),
            LibCSpec::lsb5 => write!(f, "5.0.0"),
        }
    }
}

impl LibCSpec {
    pub fn get_functions_with_checked_versions(self) -> &'static [&'static str] {
        match self {
            LibCSpec::lsb1
            | LibCSpec::lsb1dot1
            | LibCSpec::lsb1dot2
            | LibCSpec::lsb1dot3
            | LibCSpec::lsb2
            | LibCSpec::lsb2dot0dot1
            | LibCSpec::lsb2dot1
            | LibCSpec::lsb3
            | LibCSpec::lsb3dot1
            | LibCSpec::lsb3dot2 => &[],

            LibCSpec::lsb4 | LibCSpec::lsb4dot1 | LibCSpec::lsb5 => {
                elf::checked_functions::LSB_4_0_0_FUNCTIONS_WITH_CHECKED_VERSIONS
            }
        }
    }
}
