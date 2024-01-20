// Copyright 2018-2023 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use log::{debug, warn};

use crate::errors::{Error, Result};
use crate::options::status::DisplayInColorTerm;
use crate::options::{BinarySecurityOption, ELFStackProtectionOption};
use crate::parser::BinaryParser;

pub fn analyze_binary(parser: &BinaryParser) -> Result<Vec<Box<dyn DisplayInColorTerm>>> {
    let has_stack_protection = ELFStackProtectionOption.check(parser)?;
    Ok(vec![has_stack_protection])
}

pub fn has_stack_protection(
    parser: &BinaryParser,
    archive: &goblin::archive::Archive,
) -> Result<bool> {
    let bytes = parser.bytes();
    for member_name in archive.members() {
        let buffer = archive
            .extract(member_name, bytes)
            .map_err(|source| Error::Goblin1 {
                operation: "goblin::archive::Archive",
                param1: member_name.into(),
                source,
            })?;

        let r = member_has_stack_protection(member_name, buffer)?;
        if r {
            return Ok(true);
        }
    }
    Ok(false)
}

/// - [`__stack_chk_fail`](http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/baselib---stack-chk-fail-1.html).
/// - `__stack_chk_fail_local` is present in `libc` when it is stack-protected.
fn member_has_stack_protection(member_name: &str, bytes: &[u8]) -> Result<bool> {
    use goblin::Object;

    let obj = Object::parse(bytes).map_err(|source| Error::Goblin {
        operation: "goblin::Object::parse",
        source,
    })?;

    if let Object::Elf(elf) = obj {
        // elf.is_object_file()
        debug!("Format of archive member '{}' is 'ELF'.", member_name);
        // `r` is `true` if any named function or an unspecified-type symbol is
        // named '__stack_chk_fail_local' or '__stack_chk_fail'.
        let r = elf
            .syms
            .iter()
            .filter_map(|symbol| crate::elf::symbol_is_named_function_or_unspecified(&elf, &symbol))
            .any(|name| name == "__stack_chk_fail" || name == "__stack_chk_fail_local");

        if r {
            debug!("Found function symbol '__stack_chk_fail_local' or '__stack_chk_fail' inside symbols section of member '{}'.", member_name);
        }
        Ok(r)
    } else {
        warn!("Format of archive member '{}' is not 'ELF'.", member_name);
        Err(Error::UnexpectedBinaryFormat {
            expected: "ELF",
            name: member_name.into(),
        })
    }
}
