// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

#![doc = include_str!("../README.md")]
#![warn(unsafe_op_in_unsafe_fn)]
#![warn(clippy::all, clippy::pedantic)]
//#![warn(clippy::restriction)]
#![allow(
    clippy::upper_case_acronyms,
    clippy::unnecessary_wraps,
    clippy::missing_docs_in_private_items,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::implicit_return,
    clippy::separated_literal_suffix,
    clippy::question_mark_used,
    clippy::mod_module_files,
    clippy::expect_used,
    clippy::module_name_repetitions,
    clippy::unwrap_in_result,
    clippy::min_ident_chars,
    clippy::single_char_lifetime_names,
    clippy::single_call_fn,
    clippy::absolute_paths,
    clippy::similar_names
)]

mod archive;
mod cmdline;
mod elf;
mod errors;
mod options;
mod parser;
mod pe;
mod ui;

use core::iter;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use flexi_logger::{FlexiLoggerError, LoggerHandle};
use log::{debug, error, trace};
use rayon::prelude::*;

use crate::cmdline::UseColor;
use crate::errors::{Error, Result};
use crate::parser::BinaryParser;
use crate::ui::ColorBuffer;

fn main() -> ExitCode {
    let options = cmdline::Options::parse();

    let _log_handle = match init_logger(&options) {
        Ok(h) => h,

        Err(err) => {
            eprintln!("Error: {}", format_error(&err));
            return ExitCode::FAILURE;
        }
    };

    trace!("{:?}", &options);

    let mut exit_code = 0_u8;
    match run(options) {
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

    ExitCode::from(exit_code)
}

type SuccessResults = Vec<(PathBuf, ColorBuffer)>;
type ErrorResults = Vec<(PathBuf, Error)>;

fn run(mut options: cmdline::Options) -> Result<(SuccessResults, ErrorResults)> {
    use rayon::iter::Either;

    let icb_stdout = ColorBuffer::for_stdout(options.color);

    let input_files = core::mem::take(&mut options.input_files);

    let result: (Vec<_>, Vec<_>) = input_files
        .into_iter()
        // Zip one color buffer with each file to process.
        .zip(iter::repeat(icb_stdout))
        // Collect all inputs before starting processing.
        .collect::<Vec<_>>()
        .into_par_iter()
        // Process each file.
        .map(|(path, mut out)| {
            let r = process_file(&path, &mut out.color_buffer, &options);
            (path, out, r)
        })
        .partition_map(|(path, out, result)| match result {
            // On success, retain the path and output buffer, discard the result.
            Ok(()) => Either::Left((path, out)),
            // On error, retain the path and error, discard the output buffer.
            Err(r) => Either::Right((path, r)),
        });

    Ok(result)
}

fn format_error(mut r: &dyn std::error::Error) -> String {
    use core::fmt::Write;

    // Format the error as a message.
    let mut text = format!("{r}.");
    while let Some(source) = r.source() {
        let _ignored = write!(&mut text, " {source}.");
        r = source;
    }
    text
}

fn init_logger(options: &cmdline::Options) -> std::result::Result<LoggerHandle, FlexiLoggerError> {
    use flexi_logger::{
        colored_default_format, default_format, AdaptiveFormat, LogSpecification, Logger,
    };

    let log_spec = LogSpecification::builder()
        .default(if options.verbose {
            log::LevelFilter::Trace
        } else {
            log::LevelFilter::Info
        })
        .build();

    let logger = Logger::with(log_spec).use_utc();
    let logger = match options.color {
        UseColor::Auto => logger.adaptive_format_for_stderr(AdaptiveFormat::Default),
        UseColor::Always => logger.format_for_stderr(colored_default_format),
        UseColor::Never => logger.format_for_stderr(default_format),
    };

    logger.start()
}

fn process_file(
    path: &impl AsRef<Path>,
    color_buffer: &mut termcolor::Buffer,
    options: &cmdline::Options,
) -> Result<()> {
    use goblin::Object;

    let parser = BinaryParser::open(path.as_ref())?;

    let results = match parser.object() {
        Object::Elf(_elf) => {
            debug!("Binary file format is 'ELF'.");
            elf::analyze_binary(&parser, options)
        }

        Object::PE(_pe) => {
            debug!("Binary file format is 'PE'.");
            pe::analyze_binary(&parser, options)
        }

        Object::Mach(_mach) => {
            debug!("Binary file format is 'MACH'.");
            Err(Error::UnsupportedBinaryFormat {
                format: "MACH".into(),
                path: path.as_ref().into(),
            })
        }

        Object::Archive(_archive) => {
            debug!("Binary file format is 'Archive'.");
            archive::analyze_binary(&parser, options)
        }

        Object::Unknown(_magic) => Err(Error::UnknownBinaryFormat(path.as_ref().into())),

        _ => Err(Error::UnknownBinaryFormat(path.as_ref().into())),
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

    writeln!(color_buffer)
        .map_err(|r| Error::from_io1(r, "write line", "standard output stream"))?;
    Ok(())
}
