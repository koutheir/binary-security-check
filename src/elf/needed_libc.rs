// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use log::{debug, log_enabled};
use regex::{Regex, RegexBuilder};

use super::checked_functions::{function_is_checked_version, CheckedFunction};
use crate::cmdline::LibCSpec;
use crate::errors::{Error, Result};
use crate::parser::BinaryParser;

#[derive(Debug)]
pub(crate) struct LibCResolver {
    sys_root: PathBuf,
    ld_so_cache: Option<dynamic_loader_cache::Cache>,
}

static LIBC_RESOLVER: OnceLock<Option<LibCResolver>> = OnceLock::new();

impl LibCResolver {
    pub(crate) fn get(options: &crate::cmdline::Options) -> Result<&'static Self> {
        let mut first_err = None;

        let r = LIBC_RESOLVER.get_or_init(|| match Self::new(options) {
            Ok(r) => Some(r),

            Err(err) => {
                first_err = Some(err);
                None
            }
        });

        if let Some(err) = first_err {
            Err(err)
        } else {
            r.as_ref().ok_or_else(|| {
                let err = std::io::ErrorKind::InvalidData.into();
                Error::from_io1(err, "load linker cache", "")
            })
        }
    }

    fn new(options: &crate::cmdline::Options) -> Result<Self> {
        let ld_so_cache = if options.sysroot.is_none() {
            Some(dynamic_loader_cache::Cache::load()?)
        } else {
            None
        };

        let sys_root = options.sysroot.as_deref().unwrap_or_else(|| Path::new("/"));

        Ok(Self {
            sys_root: sys_root.into(),
            ld_so_cache,
        })
    }

    pub(crate) fn find_needed_by_executable(&self, elf: &goblin::elf::Elf) -> Result<NeededLibC> {
        elf.libraries
            .iter()
            // Only consider libraries whose pattern is known.
            .filter(|needed_lib| KNOWN_LIBC_PATTERN.is_match(needed_lib))
            // Parse the library.
            .map(|&lib| self.open_compatible_libc(elf, Path::new(lib)))
            // Return the first that can be successfully parsed.
            .find(Result::is_ok)
            // Or return an error in case nothing is found or nothing can be parsed.
            .unwrap_or(Err(Error::UnrecognizedNeededLibC))
    }

    fn open_compatible_libc(&self, elf: &goblin::elf::Elf, file_name: &Path) -> Result<NeededLibC> {
        debug!("Looking for libc '{}'.", file_name.display());

        if let Some(ld_so_cache) = self.ld_so_cache.as_ref() {
            let found_in_ld_so_cache = ld_so_cache
                .iter()?
                .filter_map(dynamic_loader_cache::Result::ok)
                .filter_map(|e| (e.file_name == file_name).then_some(e.full_path))
                // For each known libc file location, parse the libc file.
                .map(|path| NeededLibC::open_elf_for_architecture(path, elf))
                // Return the first that can be successfully parsed.
                .find(Result::is_ok);

            if let Some(libc) = found_in_ld_so_cache {
                return libc;
            }
        }

        KNOWN_LIB_DIRS
            .iter()
            .flat_map(|&lib| {
                KNOWN_PREFIXES
                    .iter()
                    .map(move |&prefix| self.sys_root.join(prefix).join(lib).join(file_name))
            })
            // For each known libc file location, parse the libc file.
            .map(|path| NeededLibC::open_elf_for_architecture(path, elf))
            // Return the first that can be successfully parsed.
            .find(Result::is_ok)
            // Or return an error in case nothing is found or nothing can be parsed.
            .unwrap_or_else(|| Err(Error::NotFoundNeededLibC(file_name.into())))
    }
}

pub(crate) struct NeededLibC {
    checked_functions: HashSet<CheckedFunction>,
}

impl NeededLibC {
    pub(crate) fn from_spec(spec: LibCSpec) -> Self {
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

    pub(crate) fn open_elf_for_architecture(
        path: impl AsRef<Path>,
        other_elf: &goblin::elf::Elf,
    ) -> Result<Self> {
        let parser = BinaryParser::open(&path)?;

        match parser.object() {
            goblin::Object::Elf(elf) => {
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
                format: format!("Magic: 0x{magic:016X}"),
                path: path.as_ref().into(),
            }),

            goblin::Object::PE(_) | goblin::Object::Mach(_) | goblin::Object::Archive(_) => {
                Err(Error::UnexpectedBinaryFormat {
                    expected: "ELF",
                    name: path.as_ref().into(),
                })
            }

            _ => Err(Error::UnsupportedBinaryFormat {
                format: "Unknown".into(),
                path: path.as_ref().into(),
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

    pub(crate) fn exports_function<'this>(&'this self, checked_name: &str) -> Option<&'this str> {
        self.checked_functions
            .get(&CheckedFunction::from_checked_name(checked_name))
            .map(CheckedFunction::get_unchecked_name)
    }

    pub(crate) fn exports_checked_version_of_function<'this>(
        &'this self,
        unchecked_name: &str,
    ) -> Option<&'this str> {
        self.checked_functions
            .get(&CheckedFunction::from_unchecked_name(unchecked_name))
            .map(CheckedFunction::get_unchecked_name)
    }
}

// If this changes, then update the command line reference.
static KNOWN_PREFIXES: &[&str] = &["", "usr"];
static KNOWN_LIB_DIRS: &[&str] = &["lib", "lib64", "lib32"];

static KNOWN_LIBC_PATTERN: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
    RegexBuilder::new(r"\blib(c|bionic)\b[^/]+$")
        .case_insensitive(true)
        .multi_line(false)
        .dot_matches_new_line(false)
        .unicode(true)
        .build()
        .expect("Invalid static regular expression.")
});
