// Copyright 2018 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate failure;

#[macro_use]
extern crate log;

extern crate docopt;
extern crate goblin;
extern crate memmap;
extern crate rayon;
extern crate regex;
extern crate scroll;
extern crate simplelog;
extern crate termcolor;

mod archive;
mod cmdline;
mod elf;
mod errors;
mod options;
mod parser;
mod pe;
mod ui;

use cmdline::*;
use errors::*;
use parser::*;
use ui::*;

use rayon::prelude::*;
use std::io::Write;
use std::iter;
use std::path::{Path, PathBuf};

fn main() {
    lazy_static::initialize(&ARGS);
    let _ = init_logging().or_else(|ref r| eprintln!("Error: {}", format_error(r)));

    let mut exit_code = 0;
    match run() {
        Ok((successes, errors)) => {
            // Print successful results.
            for (path, color_buffer) in successes {
                print!("{}: ", path.display());
                if color_buffer.print().is_err() {
                    exit_code = 1;
                    break;
                }
            }

            // Print errors related to files.
            if exit_code == 0 {
                for (path, error) in errors {
                    exit_code = 1;
                    error!("{}: {}", path.display(), format_error(&error));
                }
            }
        }

        Err(error) => {
            exit_code = 1;
            error!("{}", format_error(&error));
        }
    }

    std::process::exit(exit_code)
}

type SuccessResults<'args> = Vec<(&'args PathBuf, ColorBuffer)>;
type ErrorResults<'args> = Vec<(&'args PathBuf, Error)>;

fn run<'args>() -> Result<(SuccessResults<'args>, ErrorResults<'args>)> {
    let icb_stdout = ColorBuffer::for_stdout();

    let result: (Vec<_>, Vec<_>) = ARGS.arg_file
        .iter()
        // Zip one color buffer with each file to process.
        .zip(iter::repeat(icb_stdout))
        // Collect all inputs before starting processing.
        .collect::<Vec<_>>()
        .into_par_iter()
        // Process each file.
        .map(|(path, mut out)| {
            let r = process_file(path, &mut out.color_buffer);
            (path, out, r)
        })
        .partition_map(|(path, out, result)| match result {
            // On success, retain the path and output buffer, discard the result.
            Ok(_) => ::rayon::iter::Either::Left((path, out)),
            // On error, retain the path and error, discard the output buffer.
            Err(r) => ::rayon::iter::Either::Right((path, r)),
        });

    Ok(result)
}

fn format_error(r: &Error) -> String {
    // Format the error as a message.
    let mut text = format!("{}.", r);
    for cause in r.causes().skip(1) {
        text += &format!(" {}.", cause);
    }
    text
}

fn init_logging() -> Result<()> {
    let log_level = if ARGS.flag_verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };

    let log_config = simplelog::Config::default();

    match ARGS.flag_color {
        UseColor::never => simplelog::SimpleLogger::init(log_level, log_config)
            .context(ErrorKind::LogInitialization)?,

        UseColor::auto | UseColor::always => simplelog::TermLogger::init(log_level, log_config)
            .or_else(|_e| simplelog::SimpleLogger::init(log_level, log_config))
            .context(ErrorKind::LogInitialization)?,
    }

    debug!("{:?}", *ARGS);
    Ok(())
}

fn process_file(path: &impl AsRef<Path>, color_buffer: &mut termcolor::Buffer) -> Result<()> {
    let parser = BinaryParser::open(path.as_ref())?;

    let results = match parser.object() {
        goblin::Object::Elf(ref _elf) => {
            debug!("Binary file format is 'ELF'.");
            elf::analyze_binary(&parser)
        }

        goblin::Object::PE(ref _pe) => {
            debug!("Binary file format is 'PE'.");
            pe::analyze_binary(&parser)
        }

        goblin::Object::Mach(ref _mach) => {
            debug!("Binary file format is 'MACH'.");
            Err(Error::from(ErrorKind::UnsupportedBinaryFormat))
        }

        goblin::Object::Archive(ref _archive) => {
            debug!("Binary file format is 'Archive'.");
            archive::analyze_binary(&parser)
        }

        goblin::Object::Unknown(_magic) => Err(Error::from(ErrorKind::UnknownBinaryFormat)),
    }?;

    // Print results in the color buffer.
    let mut iter = results.into_iter();
    if let Some(first) = iter.next() {
        first.as_ref().display_in_color_term(color_buffer)?;
        for opt in iter {
            write!(color_buffer, " ").context(ErrorKind::WriteFile)?;
            opt.as_ref().display_in_color_term(color_buffer)?;
        }
    }

    writeln!(color_buffer).context(ErrorKind::WriteFile)?;
    Ok(())
}

/// **[Dangerous]** Returns two bindings for the same value, after storing the value on the heap.
///
/// This breaks the rules of Rust by allowing aliasing. It is used **only** to store sibling
/// references based on `ManuallyDrop`.
/// See `options::status::ELFFortifySourceStatus` and `parser::BinaryParser`.
pub unsafe fn create_an_alias_to_a_reference<T>(value: T) -> (Box<T>, &'static T) {
    // Move `value` to the heap to give it a stable address. Then leak the value as a static
    // mutable reference.
    let value_ref: &'static mut T = Box::leak(Box::new(value));
    // Create a `Box` that owns the value on the heap. It enables removing the value later.
    // ** Due to this, it is the responsibility of the caller to ensure that the "static" **
    // ** reference is not used after the box is dropped. **
    let value = Box::from_raw(value_ref as *mut _);
    (value, value_ref)
}
