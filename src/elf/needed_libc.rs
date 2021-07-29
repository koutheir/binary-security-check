// Copyright 2018-2021 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use log::{debug, log_enabled};
use regex::{Regex, RegexBuilder};

use super::checked_functions::{function_is_checked_version, CheckedFunction};
use crate::cmdline::{LibCSpec, ARGS};
use crate::errors::{Error, Result};
use crate::parser::BinaryParser;

pub struct NeededLibC {
    checked_functions: HashSet<CheckedFunction>,
}

impl NeededLibC {
    pub fn from_spec(spec: LibCSpec) -> Self {
        let functions_with_checked_versions = spec.get_functions_with_checked_versions();

        if log_enabled!(log::Level::Debug) {
            debug!("C runtime library is assumed to conform to {}.", spec);

            let mut text = String::default();
            let mut iter = functions_with_checked_versions.iter();
            if let Some(name) = iter.next() {
                text.push_str(name);
                for name in iter {
                    text.push(' ');
                    text.push_str(name);
                }
            } else {
                text.push_str("(none)");
            }
            debug!(
                "Functions with checked versions, presumably exported by the C runtime library: {}.",
                text
            );
        }

        Self {
            checked_functions: functions_with_checked_versions
                .iter()
                .map(|name| CheckedFunction::from_unchecked_name(name))
                .collect(),
        }
    }

    pub fn find_needed_by_executable(elf: &goblin::elf::Elf) -> Result<Self> {
        if let Some(ref path) = ARGS.flag_libc {
            Self::open_elf_for_architecture(path, elf)
        } else {
            elf.libraries
                .iter()
                // Only consider libraries whose pattern is known.
                .filter(|needed_lib| KNOWN_LIBC_PATTERN.is_match(needed_lib))
                // Parse the library.
                .map(|lib| Self::open_compatible_libc(lib, elf))
                // Return the first that can be successfully parsed.
                .find(Result::is_ok)
                // Or return an error in case nothing is found or nothing can be parsed.
                .unwrap_or(Err(Error::UnrecognizedNeededLibC))
        }
    }

    fn open_compatible_libc(file_name: impl AsRef<Path>, elf: &goblin::elf::Elf) -> Result<Self> {
        KNOWN_LIBC_FILE_LOCATIONS
            .iter()
            // For each known libc file location, parse the libc file.
            .map(|known_location| {
                Self::open_elf_for_architecture(
                    &Self::get_libc_path(known_location, &file_name),
                    elf,
                )
            })
            // Return the first that can be successfully parsed.
            .find(Result::is_ok)
            // Or return an error in case nothing is found or nothing can be parsed.
            .unwrap_or_else(|| Err(Error::NotFoundNeededLibC(file_name.as_ref().into())))
    }

    fn get_libc_path(location: impl AsRef<OsStr>, file_name: impl AsRef<Path>) -> PathBuf {
        let mut path = if let Some(ref sysroot) = ARGS.flag_sysroot {
            let mut p = PathBuf::from(sysroot).into_os_string();
            p.push(location.as_ref());
            PathBuf::from(p)
        } else {
            PathBuf::from(location.as_ref())
        };

        path.push(&file_name);
        path
    }

    fn open_elf_for_architecture(
        path: impl AsRef<Path>,
        other_elf: &goblin::elf::Elf,
    ) -> Result<Self> {
        let parser = BinaryParser::open(&path)?;

        match parser.object() {
            goblin::Object::Elf(ref elf) => {
                if elf.header.e_machine == other_elf.header.e_machine {
                    debug!(
                        "C runtime library file format is 'ELF'. Resolved to '{}'.",
                        path.as_ref().display()
                    );

                    Ok(Self {
                        checked_functions: Self::get_checked_functions_elf(elf),
                    })
                } else {
                    Err(Error::UnexpectedBinaryArchitecture(path.as_ref().into()))
                }
            }

            goblin::Object::Unknown(magic) => Err(Error::UnsupportedBinaryFormat {
                format: format!("Magic: 0x{:016X}", magic),
                path: path.as_ref().into(),
            }),

            _ => Err(Error::UnexpectedBinaryFormat {
                expected: "ELF",
                name: path.as_ref().into(),
            }),
        }
    }

    fn get_checked_functions_elf(elf: &goblin::elf::Elf) -> HashSet<CheckedFunction> {
        let checked_functions = elf
            .dynsyms
            .iter()
            // Consider only named exported functions, and focus on their name.
            .filter_map(|symbol| {
                crate::elf::dynamic_symbol_is_named_exported_function(elf, &symbol)
            })
            // Consider only functions that are checked versions of libc functions.
            .filter(|name| function_is_checked_version(name))
            // Make up a new `CheckedFunction` for each found function.
            .map(CheckedFunction::from_checked_name)
            .collect::<HashSet<CheckedFunction>>();

        if log_enabled!(log::Level::Debug) {
            let mut text = String::default();
            let mut iter = checked_functions.iter();
            if let Some(name) = iter.next() {
                text.push_str(name.get_unchecked_name());
                for name in iter {
                    text.push(' ');
                    text.push_str(name.get_unchecked_name());
                }
            } else {
                text.push_str("(none)");
            }
            debug!(
                "Functions with checked versions, exported by the C runtime library: {}.",
                text
            );
        }
        checked_functions
    }

    pub fn exports_function<'t>(&'t self, checked_name: &str) -> Option<&'t str> {
        self.checked_functions
            .get(&CheckedFunction::from_checked_name(checked_name))
            .map(CheckedFunction::get_unchecked_name)
    }

    pub fn exports_checked_version_of_function<'t>(
        &'t self,
        unchecked_name: &str,
    ) -> Option<&'t str> {
        self.checked_functions
            .get(&CheckedFunction::from_unchecked_name(unchecked_name))
            .map(CheckedFunction::get_unchecked_name)
    }
}

// If this changes, then update the command line reference.
static KNOWN_LIBC_FILE_LOCATIONS: &[&str] = &[
    "/lib",
    "/usr/lib",
    "/lib64",
    "/usr/lib64",
    "/lib32",
    "/usr/lib32",
];

lazy_static::lazy_static! {
    static ref KNOWN_LIBC_PATTERN: Regex = init_known_libc_pattern();
}

fn init_known_libc_pattern() -> Regex {
    RegexBuilder::new(r#"\blib(c|bionic)\b[^/]+$"#)
        .case_insensitive(true)
        .multi_line(false)
        .dot_matches_new_line(false)
        .unicode(true)
        .build()
        .expect("Invalid static regular expression.")
}
