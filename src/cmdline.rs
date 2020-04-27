// Copyright 2018 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use crate::elf;

use docopt::Docopt;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Args {
    pub flag_verbose: bool,
    pub flag_sysroot: Option<PathBuf>,
    pub flag_libc: Option<PathBuf>,
    pub flag_libc_spec: Option<LibCSpec>,
    pub flag_color: UseColor,
    pub arg_file: Vec<PathBuf>,
}

fn parse_command_line() -> Args {
    let usage = format!(
        "{0} version {2}.
{1}, by {3}.

Usage:
  {0} [-v] [-c COLOR] [(-s DIR | -l FILE | -i SPEC)] <file>...
  {0} (-h | --help)
  {0} --version

Options:
  -c COLOR, --color=COLOR  Use color in standard output. Either 'auto' or
                 'always' or 'never' [default: auto].
  -s DIR, --sysroot=DIR  Set system root for finding the corresponding
                 C runtime library.
  -l FILE, --libc=FILE  Set the path of the C runtime library.
  -i SPEC, --libc-spec=SPEC  Use an internal list of checked functions as
                 specified by a specification.
  -v, --verbose  Verbose logging.
  -h, --help     Show this screen.
  --version      Show version.

If specified, then SPEC can be one of the following versions of the Linux
Standard Base specifications:
- lsb1: LSB 1.0.0.
- lsb1dot1: LSB 1.1.0.
- lsb1dot2: LSB 1.2.0.
- lsb1dot3: LSB 1.3.0.
- lsb2: LSB 2.0.0.
- lsb2dot0dot1: LSB 2.0.1.
- lsb2dot1: LSB 2.1.0.
- lsb3: LSB 3.0.0.
- lsb3dot1: LSB 3.1.0.
- lsb3dot2: LSB 3.2.0.
- lsb4: LSB 4.0.0.
- lsb4dot1: LSB 4.1.0.
- lsb5: LSB 5.0.0.

By default, this tool tries to automatically locate the C library in the
following directories:
- /lib/
- /usr/lib/
- /lib64/
- /usr/lib64/
- /lib32/
- /usr/lib32/
The tools `readelf` and `ldd` can be used to help find the path of the C library
needed by the analyzed files, which is given by the --libc parameter.
",
        PKG_NAME, PKG_DESCRIPTION, PKG_VERSION, PKG_AUTHORS
    );

    let version = format!("{} version {}", PKG_NAME, PKG_VERSION);

    Docopt::new(usage)
        .and_then(|d| d.help(true).version(Some(version)).deserialize())
        .unwrap_or_else(|e| e.exit())
}

lazy_static! {
    pub static ref ARGS: Args = parse_command_line();
}

static PKG_NAME: &str = env!("CARGO_PKG_NAME");
static PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
static PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
static PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

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
