// Copyright 2018 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::collections::HashSet;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::ptr::NonNull;

use crate::elf;
use crate::elf::needed_libc::NeededLibC;
use crate::errors::{Error, Result};

pub const MARKER_GOOD: char = '+';
pub const MARKER_BAD: char = '!';
pub const MARKER_MAYBE: char = '~';
pub const MARKER_UNKNOWN: char = '?';

pub const COLOR_GOOD: termcolor::Color = termcolor::Color::Green;
pub const COLOR_BAD: termcolor::Color = termcolor::Color::Red;
pub const COLOR_UNKNOWN: termcolor::Color = termcolor::Color::Yellow;

pub trait DisplayInColorTerm {
    fn display_in_color_term(&self, wc: &mut dyn termcolor::WriteColor) -> Result<()>;
}

pub struct YesNoUnknownStatus {
    name: &'static str,
    status: Option<bool>,
}

impl YesNoUnknownStatus {
    pub fn new(name: &'static str, yes_or_no: bool) -> Self {
        Self {
            name,
            status: Some(yes_or_no),
        }
    }

    pub fn unknown(name: &'static str) -> Self {
        Self { name, status: None }
    }
}

impl DisplayInColorTerm for YesNoUnknownStatus {
    fn display_in_color_term(&self, wc: &mut dyn termcolor::WriteColor) -> Result<()> {
        let (marker, color) = match self.status {
            Some(true) => (MARKER_GOOD, COLOR_GOOD),
            Some(false) => (MARKER_BAD, COLOR_BAD),
            None => (MARKER_UNKNOWN, COLOR_UNKNOWN),
        };

        wc.set_color(termcolor::ColorSpec::new().set_fg(Some(color)))
            .map_err(|r| {
                Error::from_io1(
                    r,
                    "termcolor::WriteColor::set_color",
                    "standard output stream",
                )
            })?;

        write!(wc, "{}{}", marker, self.name)
            .map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;
        wc.reset().map_err(|r| {
            Error::from_io1(r, "termcolor::WriteColor::reset", "standard output stream")
        })
    }
}

/// [Control Flow Guard](https://docs.microsoft.com/en-us/cpp/build/reference/guard-enable-guard-checks).
pub enum PEControlFlowGuardLevel {
    /// Control Flow Guard support is unknown.
    Unknown,
    /// Control Flow Guard is unsupported.
    Unsupported,
    /// Control Flow Guard is supported, but cannot take effect.
    /// This is usually because the executable cannot be relocated at runtime.
    Ineffective,
    /// Control Flow Guard is supported.
    Supported,
}

impl DisplayInColorTerm for PEControlFlowGuardLevel {
    fn display_in_color_term(&self, wc: &mut dyn termcolor::WriteColor) -> Result<()> {
        let (marker, color) = match self {
            PEControlFlowGuardLevel::Unknown => (MARKER_UNKNOWN, COLOR_UNKNOWN),
            PEControlFlowGuardLevel::Unsupported => (MARKER_BAD, COLOR_BAD),
            PEControlFlowGuardLevel::Ineffective => (MARKER_MAYBE, COLOR_UNKNOWN),
            PEControlFlowGuardLevel::Supported => (MARKER_GOOD, COLOR_GOOD),
        };

        wc.set_color(termcolor::ColorSpec::new().set_fg(Some(color)))
            .map_err(|r| {
                Error::from_io1(
                    r,
                    "termcolor::WriteColor::set_color",
                    "standard output stream",
                )
            })?;

        write!(wc, "{}CONTROL-FLOW-GUARD", marker)
            .map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;
        wc.reset().map_err(|r| {
            Error::from_io1(r, "termcolor::WriteColor::reset", "standard output stream")
        })
    }
}

pub enum ASLRCompatibilityLevel {
    /// Address Space Layout Randomization support is unknown.
    Unknown,
    /// Address Space Layout Randomization is unsupported.
    Unsupported,
    /// Address Space Layout Randomization is supported, but might be expensive.
    /// This usually happens when an executable has a preferred base address explicitly specified.
    Expensive,
    /// Address Space Layout Randomization is supported, but with a low entropy, and only in
    /// addresses below 2 Gigabytes.
    SupportedLowEntropyBelow2G,
    /// Address Space Layout Randomization is supported, but with a low entropy.
    SupportedLowEntropy,
    /// Address Space Layout Randomization is supported with high entropy, but only in addresses
    /// below 2 Gigabytes.
    SupportedBelow2G,
    /// Address Space Layout Randomization is supported (with high entropy for PE32/PE32+).
    Supported,
}

impl DisplayInColorTerm for ASLRCompatibilityLevel {
    fn display_in_color_term(&self, wc: &mut dyn termcolor::WriteColor) -> Result<()> {
        let (marker, color, text) = match self {
            ASLRCompatibilityLevel::Unknown => (MARKER_UNKNOWN, COLOR_UNKNOWN, "ASLR"),
            ASLRCompatibilityLevel::Unsupported => (MARKER_BAD, COLOR_BAD, "ASLR"),
            ASLRCompatibilityLevel::Expensive => (MARKER_MAYBE, COLOR_UNKNOWN, "ASLR-EXPENSIVE"),
            ASLRCompatibilityLevel::SupportedLowEntropyBelow2G => {
                (MARKER_MAYBE, COLOR_UNKNOWN, "ASLR-LOW-ENTROPY-LT-2GB")
            }
            ASLRCompatibilityLevel::SupportedLowEntropy => {
                (MARKER_MAYBE, COLOR_UNKNOWN, "ASLR-LOW-ENTROPY")
            }
            ASLRCompatibilityLevel::SupportedBelow2G => {
                (MARKER_MAYBE, COLOR_UNKNOWN, "ASLR-LT-2GB")
            }
            ASLRCompatibilityLevel::Supported => (MARKER_GOOD, COLOR_GOOD, "ASLR"),
        };

        wc.set_color(termcolor::ColorSpec::new().set_fg(Some(color)))
            .map_err(|r| {
                Error::from_io1(
                    r,
                    "termcolor::WriteColor::set_color",
                    "standard output stream",
                )
            })?;

        write!(wc, "{}{}", marker, text)
            .map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;
        wc.reset().map_err(|r| {
            Error::from_io1(r, "termcolor::WriteColor::reset", "standard output stream")
        })
    }
}

pub struct ELFFortifySourceStatus {
    libc: NeededLibC,
    protected_functions: HashSet<&'static str>,
    unprotected_functions: HashSet<&'static str>,
    _pin: PhantomPinned,
}

impl ELFFortifySourceStatus {
    pub fn new(libc: NeededLibC, elf_object: &goblin::elf::Elf) -> Result<Pin<Box<Self>>> {
        let mut result = Box::pin(Self {
            libc,
            protected_functions: HashSet::default(),
            unprotected_functions: HashSet::default(),
            _pin: PhantomPinned,
        });

        // `result` is now allocated, initialized and pinned on the heap.
        // Its location is therefore stable, and we can store references to it
        // in other places.
        //
        // Construct a reference to `result.libc` that lives for the 'static
        // life time:
        //     &ref => pointer => 'static ref
        //
        // This is safe because the `Drop` implementation drops the fields
        // `Self::protected_functions` and `Self::unprotected_functions`
        // before the field `Self::libc`.
        let libc_ref: &'static NeededLibC =
            unsafe { NonNull::from(&result.libc).as_ptr().as_ref().unwrap() };

        let (prot_fn, unprot_fn) = elf::get_libc_functions_by_protection(elf_object, libc_ref);

        // SAFETY: Storing to the field `protected_functions` does not move `result`.
        unsafe { Pin::get_unchecked_mut(result.as_mut()) }.protected_functions = prot_fn;

        // SAFETY: Storing to the field `unprotected_functions` does not move `result`.
        unsafe { Pin::get_unchecked_mut(result.as_mut()) }.unprotected_functions = unprot_fn;

        Ok(result)
    }

    fn drop_pinned(mut self: Pin<&mut Self>) {
        // SAFETY: Drop fields `protected_functions` and `unprotected_functions`
        // before field `libc` is dropped.
        let this = Pin::as_mut(&mut self);

        // SAFETY: Calling `HashSet::clear()` does not move `this`.
        let this = unsafe { Pin::get_unchecked_mut(this) };

        this.protected_functions.clear();
        this.unprotected_functions.clear();
    }
}

impl Drop for ELFFortifySourceStatus {
    fn drop(&mut self) {
        // SAFETY: All instances of `Self` are pinned.
        unsafe { Pin::new_unchecked(self) }.drop_pinned();
    }
}

impl DisplayInColorTerm for Pin<Box<ELFFortifySourceStatus>> {
    fn display_in_color_term(&self, wc: &mut dyn termcolor::WriteColor) -> Result<()> {
        let no_protected_functions = self.protected_functions.is_empty();
        let no_unprotected_functions = self.unprotected_functions.is_empty();

        let (marker, color) = match (no_protected_functions, no_unprotected_functions) {
            // Neither protected not unprotected functions are used. The binary can still be secure,
            // if it does not use these functions.
            (true, true) => (MARKER_UNKNOWN, COLOR_UNKNOWN),
            // Only unprotected functions are used.
            (true, false) => (MARKER_BAD, COLOR_BAD),
            // Only protected functions are used.
            (false, true) => (MARKER_GOOD, COLOR_GOOD),
            // Both protected and unprotected functions are used. This usually indicates a compiler
            // that, through static analysis, proves that some usage of the unprotected functions
            // is actually safe, and for those instances, does not call the protected functions.
            // It can also indicate that multiple object files have been compiled with different
            // compiler flags (with and without `FORTIFY_SOURCE`) then linked together.
            (false, false) => (MARKER_MAYBE, COLOR_UNKNOWN),
        };

        let set_color_err = |r| {
            Error::from_io1(
                r,
                "termcolor::WriteColor::set_color",
                "standard output stream",
            )
        };

        wc.set_color(termcolor::ColorSpec::new().set_fg(Some(color)))
            .map_err(set_color_err)?;

        write!(wc, "{}FORTIFY-SOURCE", marker)
            .map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;
        wc.reset().map_err(|r| {
            Error::from_io1(r, "termcolor::WriteColor::reset", "standard output stream")
        })?;

        write!(wc, "(").map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;

        wc.set_color(termcolor::ColorSpec::new().set_fg(Some(COLOR_GOOD)))
            .map_err(set_color_err)?;

        let mut separator = "";
        for name in self.protected_functions.iter() {
            write!(wc, "{}{}{}", separator, MARKER_GOOD, name)
                .map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;
            separator = ",";
        }

        wc.set_color(termcolor::ColorSpec::new().set_fg(Some(COLOR_BAD)))
            .map_err(set_color_err)?;

        for name in self.unprotected_functions.iter() {
            write!(wc, "{}{}{}", separator, MARKER_BAD, name)
                .map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;
            separator = ",";
        }

        wc.reset().map_err(|r| {
            Error::from_io1(r, "termcolor::WriteColor::reset", "standard output stream")
        })?;
        writeln!(wc, ")").map_err(|r| Error::from_io1(r, "writeln", "standard output stream"))?;
        Ok(())
    }
}
