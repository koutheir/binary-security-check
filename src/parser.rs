// Copyright 2018 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use std::fs::File;
use std::mem::ManuallyDrop;
use std::path::Path;

use log::debug;
use memmap::{Mmap, MmapOptions};

use crate::create_an_alias_to_a_reference;
use crate::errors::{ErrorKind, Result, ResultExt};

pub struct BinaryParser<'t> {
    map: ManuallyDrop<Box<Mmap>>,
    obj: ManuallyDrop<goblin::Object<'t>>,
}

impl<'t> Drop for BinaryParser<'t> {
    fn drop(&mut self) {
        unsafe {
            // The dropping order is important.
            ManuallyDrop::drop(&mut self.obj);

            ManuallyDrop::drop(&mut self.map);
        }
    }
}

impl<'t> BinaryParser<'t> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        debug!("Opening binary file '{}'.", path.as_ref().display());
        let file = File::open(&path).context(ErrorKind::OpenFileForReading)?;

        debug!("Mapping binary file '{}'.", path.as_ref().display());
        let map = MmapOptions::new();
        let map = unsafe { map.map(&file) }.context(ErrorKind::MapReadOnlyFile)?;

        let (map, map_ref) = unsafe { create_an_alias_to_a_reference(map) };

        debug!("Parsing binary file '{}'.", path.as_ref().display());
        let obj = goblin::Object::parse(map_ref).context(ErrorKind::ParseBinary)?;

        Ok(Self {
            map: ManuallyDrop::new(map),
            obj: ManuallyDrop::new(obj),
        })
    }

    pub fn object(&self) -> &goblin::Object {
        &self.obj
    }

    pub fn bytes(&self) -> &[u8] {
        &self.map
    }
}
