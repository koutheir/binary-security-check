// Copyright 2018 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

pub mod status;

use self::status::*;
use crate::archive;
use crate::cmdline;
use crate::create_an_alias_to_a_reference;
use crate::elf;
use crate::elf::needed_libc::NeededLibC;
use crate::errors::*;
use crate::parser::*;
use crate::pe;

pub trait BinarySecurityOption<'t> {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>>;
}

struct PEDllCharacteristicsBitOption {
    name: &'static str,
    mask_name: &'static str,
    mask: u16,
    present: bool,
}

impl<'t> BinarySecurityOption<'t> for PEDllCharacteristicsBitOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        if let goblin::Object::PE(ref pe) = parser.object() {
            if let Some(bit_is_set) =
                pe::dll_characteristics_bit_is_set(pe, self.mask_name, self.mask)
            {
                return Ok(Box::new(YesNoUnknownStatus::new(
                    self.name,
                    bit_is_set == self.present,
                )));
            }
        }
        Ok(Box::new(YesNoUnknownStatus::unknown(self.name)))
    }
}

#[derive(Default)]
pub struct PEHasCheckSumOption;

impl<'t> BinarySecurityOption<'t> for PEHasCheckSumOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        let r = if let goblin::Object::PE(ref pe) = parser.object() {
            pe::has_check_sum(pe)
        } else {
            None
        };

        Ok(Box::new(
            r.map(|r| YesNoUnknownStatus::new("CHECKSUM", r))
                .unwrap_or_else(|| YesNoUnknownStatus::unknown("CHECKSUM")),
        ))
    }
}

#[derive(Default)]
pub struct DataExecutionPreventionOption;

impl<'t> BinarySecurityOption<'t> for DataExecutionPreventionOption {
    /// Returns information about support of Data Execution Prevention (DEP) in the executable.
    ///
    /// When DEP is supported, a virtual memory page can be marked as non-executable (NX), in which
    /// case trying to execute any code from that pages will raise an exception, and likely crash
    /// the application, instead of running arbitrary code.
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        if let goblin::Object::PE(_pe) = parser.object() {
            PEDllCharacteristicsBitOption {
                name: "DATA-EXEC-PREVENT",
                mask_name: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
                mask: pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                present: true,
            }
            .check(parser)
        } else {
            Ok(Box::new(YesNoUnknownStatus::unknown("DATA-EXEC-PREVENT")))
        }
    }
}

#[derive(Default)]
pub struct PERunsOnlyInAppContainerOption;

impl<'t> BinarySecurityOption<'t> for PERunsOnlyInAppContainerOption {
    /// Returns information about the requirement to run this executable inside AppContainer.
    ///
    /// This option indicates whether the executable must be run in the AppContainer
    /// process-isolation environment, such as a Universal Windows Platform (UWP) or Windows
    /// Phone 8.x app.
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        PEDllCharacteristicsBitOption {
            name: "RUNS-IN-APP-CONTAINER",
            mask_name: "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
            mask: pe::IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
            present: true,
        }
        .check(parser)
    }
}

#[derive(Default)]
pub struct RequiresIntegrityCheckOption;

impl<'t> BinarySecurityOption<'t> for RequiresIntegrityCheckOption {
    /// Returns whether the operating system must to verify the digital signature of this executable
    /// at load time.
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        if let goblin::Object::PE(_pe) = parser.object() {
            PEDllCharacteristicsBitOption {
                name: "VERIFY-DIGITAL-CERT",
                mask_name: "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
                mask: pe::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
                present: true,
            }
            .check(parser)
        } else {
            Ok(Box::new(YesNoUnknownStatus::unknown("VERIFY-DIGITAL-CERT")))
        }
    }
}

#[derive(Default)]
pub struct PEEnableManifestHandlingOption;

impl<'t> BinarySecurityOption<'t> for PEEnableManifestHandlingOption {
    /// Returns whether the operating system is allowed to consider manifest files when loading
    /// this executable.
    ///
    /// Enabling this causes the operating system to do manifest lookup and loads.
    /// When isolation is disabled for an executable, the Windows loader will not attempt to find an
    /// application manifest for the newly created process. The new process will not have a default
    /// activation context, even if there is a manifest inside the executable or placed in the same
    /// directory as the executable with name `executable-name.exe.manifest`.
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        PEDllCharacteristicsBitOption {
            name: "CONSIDER-MANIFEST",
            mask_name: "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
            mask: pe::IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
            present: false,
        }
        .check(parser)
    }
}

#[derive(Default)]
pub struct PEControlFlowGuardOption;

impl<'t> BinarySecurityOption<'t> for PEControlFlowGuardOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        let r = if let goblin::Object::PE(ref pe) = parser.object() {
            pe::supports_control_flow_guard(pe)
        } else {
            PEControlFlowGuardLevel::Unknown
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub struct PEHandlesAddressesLargerThan2GBOption;

impl<'t> BinarySecurityOption<'t> for PEHandlesAddressesLargerThan2GBOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        let r = if let goblin::Object::PE(ref pe) = parser.object() {
            YesNoUnknownStatus::new(
                "HANDLES-ADDR-GT-2GB",
                pe::handles_addresses_larger_than_2_gigabytes(pe),
            )
        } else {
            YesNoUnknownStatus::unknown("HANDLES-ADDR-GT-2GB")
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub struct AddressSpaceLayoutRandomizationOption;

impl<'t> BinarySecurityOption<'t> for AddressSpaceLayoutRandomizationOption {
    /// Returns the level of support of Address Space Layout Randomization (ASLR).
    ///
    /// When ASLR is supported, the executable should be randomly re-based at load time, enabling
    /// virtual address allocation randomization, which affects the virtual memory location of heaps,
    /// stacks, and other operating system allocations.
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        match parser.object() {
            goblin::Object::PE(ref pe) => Ok(Box::new(pe::supports_aslr(pe))),
            goblin::Object::Elf(ref elf) => Ok(Box::new(elf::supports_aslr(elf))),
            _ => Ok(Box::new(YesNoUnknownStatus::unknown("ASLR"))),
        }
    }
}

#[derive(Default)]
pub struct PESafeStructuredExceptionHandlingOption;

impl<'t> BinarySecurityOption<'t> for PESafeStructuredExceptionHandlingOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        let r = if let goblin::Object::PE(ref pe) = parser.object() {
            YesNoUnknownStatus::new(
                "SAFE-SEH",
                pe::has_safe_structured_exception_handlers(parser, pe),
            )
        } else {
            YesNoUnknownStatus::unknown("SAFE-SEH")
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub struct ELFReadOnlyAfterRelocationsOption;

impl<'t> BinarySecurityOption<'t> for ELFReadOnlyAfterRelocationsOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        let r = if let goblin::Object::Elf(ref elf) = parser.object() {
            YesNoUnknownStatus::new(
                "READ-ONLY-RELOC",
                elf::becomes_read_only_after_relocations(elf),
            )
        } else {
            YesNoUnknownStatus::unknown("READ-ONLY-RELOC")
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub struct ELFStackProtectionOption;

impl<'t> BinarySecurityOption<'t> for ELFStackProtectionOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        let r = match parser.object() {
            goblin::Object::Elf(ref elf) => {
                YesNoUnknownStatus::new("STACK-PROT", elf::has_stack_protection(elf))
            }

            goblin::Object::Archive(ref archive) => {
                let r = archive::has_stack_protection(parser, archive)?;
                YesNoUnknownStatus::new("STACK-PROT", r)
            }

            _ => YesNoUnknownStatus::unknown("STACK-PROT"),
        };
        Ok(Box::new(r))
    }
}

#[derive(Default)]
pub struct ELFImmediateBindingOption;

impl<'t> BinarySecurityOption<'t> for ELFImmediateBindingOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        let r = if let goblin::Object::Elf(ref elf) = parser.object() {
            YesNoUnknownStatus::new("IMMEDIATE-BIND", elf::requires_immediate_binding(elf))
        } else {
            YesNoUnknownStatus::unknown("IMMEDIATE-BIND")
        };
        Ok(Box::new(r))
    }
}

pub struct ELFFortifySourceOption {
    libc_spec: Option<cmdline::LibCSpec>,
}

impl ELFFortifySourceOption {
    pub fn new(libc_spec: Option<cmdline::LibCSpec>) -> Self {
        Self { libc_spec }
    }
}

impl<'t> BinarySecurityOption<'t> for ELFFortifySourceOption {
    fn check(&self, parser: &BinaryParser) -> Result<Box<dyn DisplayInColorTerm>> {
        if let goblin::Object::Elf(ref elf) = parser.object() {
            let libc = if let Some(spec) = self.libc_spec {
                NeededLibC::from_spec(spec)
            } else {
                NeededLibC::find_needed_by_executable(elf)?
            };

            let (libc, libc_ref) = unsafe { create_an_alias_to_a_reference(libc) };

            let (protected_functions, unprotected_functions) =
                elf::get_libc_functions_by_protection(elf, libc_ref);

            Ok(Box::new(ELFFortifySourceStatus::new(
                libc,
                protected_functions,
                unprotected_functions,
            )))
        } else {
            Ok(Box::new(YesNoUnknownStatus::unknown("FORTIFY-SOURCE")))
        }
    }
}
