#![allow(clippy::upper_case_acronyms, clippy::unnecessary_wraps)]

// Copyright 2018-2021 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

mod archive;
mod cmdline;
mod elf;
mod errors;
mod options;
mod parser;
mod pe;
mod ui;

use std::io::Write;
use std::iter;
use std::path::{Path, PathBuf};

use log::{debug, error};
use rayon::prelude::*;

use crate::cmdline::{UseColor, ARGS};
use crate::errors::{Error, Result};
use crate::parser::BinaryParser;
use crate::ui::ColorBuffer;

fn main() {
    lazy_static::initialize(&ARGS);
    let _ignored = init_logging().or_else(|ref r| -> Result<()> {
        eprintln!("Error: {}", format_error(r));
        Ok(())
    });

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

    let result: (Vec<_>, Vec<_>) = ARGS
        .arg_file
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

fn format_error(mut r: &dyn std::error::Error) -> String {
    // Format the error as a message.
    let mut text = format!("{}.", r);
    while let Some(source) = r.source() {
        text += &format!(" {}.", source);
        r = source;
    }
    text
}

fn init_logging() -> Result<()> {
    use simplelog::{ColorChoice, Config, LevelFilter, SimpleLogger, TermLogger, TerminalMode};

    let log_level = if ARGS.flag_verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    let log_config = Config::default();

    match ARGS.flag_color {
        UseColor::never => SimpleLogger::init(log_level, log_config)?,

        UseColor::auto | UseColor::always => TermLogger::init(
            log_level,
            log_config,
            TerminalMode::Stderr,
            ColorChoice::Auto,
        )?,
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
            Err(Error::UnsupportedBinaryFormat {
                format: "MACH".into(),
                path: path.as_ref().into(),
            })
        }

        goblin::Object::Archive(ref _archive) => {
            debug!("Binary file format is 'Archive'.");
            archive::analyze_binary(&parser)
        }

        goblin::Object::Unknown(_magic) => Err(Error::UnknownBinaryFormat(path.as_ref().into())),
    }?;

    // Print results in the color buffer.
    let mut iter = results.into_iter();
    if let Some(first) = iter.next() {
        first.as_ref().display_in_color_term(color_buffer)?;
        for opt in iter {
            write!(color_buffer, " ")
                .map_err(|r| Error::from_io1(r, "write", "standard output stream"))?;
            opt.as_ref().display_in_color_term(color_buffer)?;
        }
    }

    writeln!(color_buffer).map_err(|r| Error::from_io1(r, "writeln", "standard output stream"))?;
    Ok(())
}
