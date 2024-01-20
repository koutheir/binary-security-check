// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::sync::Arc;

use crate::cmdline::ARGS;
use crate::errors::{Error, Result};

/// A color buffer that can should be written-to from a single thread.
/// If cloned and given to another thread, then both threads can write to their own color buffer
/// without synchronizing, and later a joining thread can perform the synchronization and write
/// all cloned color buffers.
pub struct ColorBuffer {
    buffer_writer: Arc<termcolor::BufferWriter>,
    pub(crate) color_buffer: termcolor::Buffer,
}

impl ColorBuffer {
    pub fn for_stdout() -> Self {
        let buffer_writer =
            termcolor::BufferWriter::stdout(termcolor::ColorChoice::from(ARGS.flag_color));
        let color_buffer = buffer_writer.buffer();

        Self {
            buffer_writer: Arc::new(buffer_writer),
            color_buffer,
        }
    }

    pub fn print(&self) -> Result<()> {
        self.buffer_writer.print(&self.color_buffer).map_err(|r| {
            Error::from_io1(
                r,
                "termcolor::BufferWriter::print",
                "standard output stream",
            )
        })?;
        Ok(())
    }
}

impl Clone for ColorBuffer {
    fn clone(&self) -> Self {
        Self {
            // Increment the reference count of the `BufferWriter`.
            buffer_writer: Arc::clone(&self.buffer_writer),
            // Create a new buffer linked to `buffer_writer`.
            color_buffer: self.buffer_writer.buffer(),
        }
    }
}
