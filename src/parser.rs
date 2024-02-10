// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr;
use std::fs;
use std::path::Path;

use log::debug;
use memmap::{Mmap, MmapOptions};

use crate::errors::{Error, Result};

pub(crate) struct BinaryParser {
    bytes: Mmap,
    object: Option<goblin::Object<'static>>,
    _pin: PhantomPinned,
}

impl BinaryParser {
    pub fn open(path: impl AsRef<Path>) -> Result<Pin<Box<Self>>> {
        debug!("Opening binary file '{}'.", path.as_ref().display());
        let file = fs::File::open(&path)
            .map_err(|r| Error::from_io1(r, "std::fs::File::open", path.as_ref()))?;

        debug!("Mapping binary file '{}'.", path.as_ref().display());
        let bytes = unsafe { MmapOptions::new().map(&file) }
            .map_err(|r| Error::from_io1(r, "memmap::MmapOptions::map", path.as_ref()))?;

        let mut result = Box::pin(Self {
            bytes,
            object: None,
            _pin: PhantomPinned,
        });

        // SAFETY:
        // `result` is now allocated, initialized and pinned on the heap.
        // Its location is therefore stable, and we can store references to it
        // in other places.
        //
        // Construct a reference to `result.bytes` that lives for the 'static
        // life time:
        //     &ref => pointer => 'static ref
        //
        // This is safe because the `Drop` implementation drops `Self::object`
        // before `Self::bytes`.
        let bytes_ref: &'static Mmap =
            unsafe { ptr::NonNull::from(&result.bytes).as_ptr().as_ref().unwrap() };

        debug!("Parsing binary file '{}'.", path.as_ref().display());
        let object = goblin::Object::parse(bytes_ref).map_err(|source| Error::Goblin {
            operation: "goblin::Object::parse",
            source,
        })?;

        result.as_mut().set_object(Some(object));
        Ok(result)
    }

    pub(crate) fn object(&self) -> &goblin::Object {
        // SAFETY: All instances of `Self` that are created and still in scope
        // must have `Some(_)` in the `object` field.
        self.object.as_ref().unwrap()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn set_object(mut self: Pin<&mut Self>, object: Option<goblin::Object<'static>>) {
        let this = Pin::as_mut(&mut self);

        // SAFETY: Storing to the field `object` does not move `this`.
        unsafe { Pin::get_unchecked_mut(this) }.object = object;
    }

    fn drop_pinned(self: Pin<&mut Self>) {
        // SAFETY: Drop `object` before `bytes` is dropped.
        self.set_object(None);
    }
}

impl Drop for BinaryParser {
    fn drop(&mut self) {
        // SAFETY: All instances of `Self` are pinned.
        unsafe { Pin::new_unchecked(self) }.drop_pinned();
    }
}
