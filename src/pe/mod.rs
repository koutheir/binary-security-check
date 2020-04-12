// Copyright 2018-2020 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

use crate::errors::*;
use crate::options::status::*;
use crate::options::*;
use crate::parser::*;

use goblin;
use goblin::pe::section_table::*;
use scroll;
use scroll::Pread;
use std::{mem, ptr};

pub fn analyze_binary(parser: &BinaryParser) -> Result<Vec<Box<dyn DisplayInColorTerm>>> {
    let has_checksum = PEHasCheckSumOption::default().check(parser)?;
    let supports_data_execution_prevention =
        DataExecutionPreventionOption::default().check(parser)?;
    let runs_only_in_app_container = PERunsOnlyInAppContainerOption::default().check(parser)?;
    let enable_manifest_handling = PEEnableManifestHandlingOption::default().check(parser)?;
    let requires_integrity_check = RequiresIntegrityCheckOption::default().check(parser)?;
    let supports_control_flow_guard = PEControlFlowGuardOption::default().check(parser)?;
    let handles_addresses_larger_than_2_gigabytes =
        PEHandlesAddressesLargerThan2GBOption::default().check(parser)?;
    let supports_address_space_layout_randomization =
        AddressSpaceLayoutRandomizationOption::default().check(parser)?;
    let supports_safe_structured_exception_handling =
        PESafeStructuredExceptionHandlingOption::default().check(parser)?;

    Ok(vec![
        has_checksum,
        supports_data_execution_prevention,
        runs_only_in_app_container,
        enable_manifest_handling,
        requires_integrity_check,
        supports_control_flow_guard,
        handles_addresses_larger_than_2_gigabytes,
        supports_address_space_layout_randomization,
        supports_safe_structured_exception_handling,
    ])
}

/// Returns the byte offset of a field in a structure.
macro_rules! offset_of {
    ($ty:ty, $field:ident) => {
        unsafe { &(*ptr::null::<$ty>()).$field as *const _ as usize }
    };
}

pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const RDATA_CHARACTERISTICS: u32 =
    IMAGE_SCN_CNT_INITIALIZED_DATA | goblin::pe::section_table::IMAGE_SCN_MEM_READ;
pub const PDATA_CHARACTERISTICS: u32 = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
#[allow(non_snake_case)]
pub struct ImageLoadConfigCodeIntegrity {
    Flags: u16,
    Catalog: u16,
    CatalogOffset: u32,
    Reserved: u32,
}

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
#[allow(non_snake_case)]
pub struct ImageLoadConfigDirectory32 {
    Size: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    GlobalFlagsClear: u32,
    GlobalFlagsSet: u32,
    CriticalSectionDefaultTimeout: u32,
    DeCommitFreeBlockThreshold: u32,
    DeCommitTotalFreeThreshold: u32,
    LockPrefixTable: u32,
    MaximumAllocationSize: u32,
    VirtualMemoryThreshold: u32,
    ProcessHeapFlags: u32,
    ProcessAffinityMask: u32,
    CSDVersion: u16,
    DependentLoadFlags: u16,
    EditList: u32,
    SecurityCookie: u32,
    SEHandlerTable: u32,
    pub SEHandlerCount: u32,
    GuardCFCheckFunctionPointer: u32,
    GuardCFDispatchFunctionPointer: u32,
    GuardCFFunctionTable: u32,
    GuardCFFunctionCount: u32,
    GuardFlags: u32,
    CodeIntegrity: ImageLoadConfigCodeIntegrity,
    GuardAddressTakenIatEntryTable: u32,
    GuardAddressTakenIatEntryCount: u32,
    GuardLongJumpTargetTable: u32,
    GuardLongJumpTargetCount: u32,
    DynamicValueRelocTable: u32,
    CHPEMetadataPointer: u32,
    GuardRFFailureRoutine: u32,
    GuardRFFailureRoutineFunctionPointer: u32,
    DynamicValueRelocTableOffset: u32,
    DynamicValueRelocTableSection: u16,
    Reserved2: u16,
    GuardRFVerifyStackPointerFunctionPointer: u32,
    HotPatchTableOffset: u32,
    Reserved3: u32,
    EnclaveConfigurationPointer: u32,
}

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone, Default)]
#[allow(non_snake_case)]
pub struct ImageLoadConfigDirectory64 {
    Size: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    GlobalFlagsClear: u32,
    GlobalFlagsSet: u32,
    CriticalSectionDefaultTimeout: u32,
    DeCommitFreeBlockThreshold: u64,
    DeCommitTotalFreeThreshold: u64,
    LockPrefixTable: u64,
    MaximumAllocationSize: u64,
    VirtualMemoryThreshold: u64,
    ProcessAffinityMask: u64,
    ProcessHeapFlags: u32,
    CSDVersion: u16,
    DependentLoadFlags: u16,
    EditList: u64,
    SecurityCookie: u64,
    SEHandlerTable: u64,
    pub SEHandlerCount: u64,
    GuardCFCheckFunctionPointer: u64,
    GuardCFDispatchFunctionPointer: u64,
    GuardCFFunctionTable: u64,
    GuardCFFunctionCount: u64,
    GuardFlags: u32,
    CodeIntegrity: ImageLoadConfigCodeIntegrity,
    GuardAddressTakenIatEntryTable: u64,
    GuardAddressTakenIatEntryCount: u64,
    GuardLongJumpTargetTable: u64,
    GuardLongJumpTargetCount: u64,
    DynamicValueRelocTable: u64,
    CHPEMetadataPointer: u64,
    GuardRFFailureRoutine: u64,
    GuardRFFailureRoutineFunctionPointer: u64,
    DynamicValueRelocTableOffset: u32,
    DynamicValueRelocTableSection: u16,
    Reserved2: u16,
    GuardRFVerifyStackPointerFunctionPointer: u64,
    HotPatchTableOffset: u32,
    Reserved3: u32,
    EnclaveConfigurationPointer: u64,
}

#[allow(non_camel_case_types)]
pub type ImageLoadConfigDirectory_Size_Type = u32;
#[allow(non_camel_case_types)]
pub type ImageLoadConfigDirectory32_SEHandlerCount_Type = u32;
#[allow(non_camel_case_types)]
pub type ImageLoadConfigDirectory64_SEHandlerCount_Type = u64;

pub fn dll_characteristics_bit_is_set(
    pe: &goblin::pe::PE,
    mask_name: &'static str,
    mask: u16,
) -> Option<bool> {
    pe.header.optional_header.map(|optional_header| {
        let r = (optional_header.windows_fields.dll_characteristics & mask) != 0;
        debug!(
            "Bit '{}' is {} in 'DllCharacteristics' inside optional Windows header.",
            mask_name,
            if r { "set" } else { "cleared" }
        );
        r
    })
}

/// Returns the level of support of Control Flow Guard (CFG).
///
/// When CFG is supported, the compiler analyzes the control flow by examining all indirect
/// calls for possible target addresses. The compiler inserts code to verify the target address
/// of an indirect call instruction is in the list of known target addresses at runtime.
/// Operating systems that support CFG stop a program that fails a CFG runtime check. This makes
/// it more difficult for an attacker to execute malicious code by using data corruption to
/// change a call target.
pub fn supports_control_flow_guard(pe: &goblin::pe::PE) -> PEControlFlowGuardLevel {
    if let Some(optional_header) = pe.header.optional_header {
        if (optional_header.windows_fields.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
            != 0
        {
            debug!("Bit 'IMAGE_DLLCHARACTERISTICS_GUARD_CF' is set in 'DllCharacteristics' inside optional Windows header.");

            if (optional_header.windows_fields.dll_characteristics
                & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                != 0
            {
                debug!("Bit 'IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE' is set in 'DllCharacteristics' inside optional Windows header.");
                PEControlFlowGuardLevel::Supported
            } else {
                PEControlFlowGuardLevel::Ineffective
            }
        } else {
            PEControlFlowGuardLevel::Unsupported
        }
    } else {
        PEControlFlowGuardLevel::Unknown
    }
}

pub fn has_check_sum(pe: &goblin::pe::PE) -> Option<bool> {
    pe.header
        .optional_header
        .map(|header| header.windows_fields.check_sum != 0)
}

/// Returns whether the executable can handle addresses larger than 2 Gigabytes.
pub fn handles_addresses_larger_than_2_gigabytes(pe: &goblin::pe::PE) -> bool {
    let r = (pe.header.coff_header.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
    if r {
        debug!(
            "Bit 'IMAGE_FILE_LARGE_ADDRESS_AWARE' is set in 'Characteristics' inside COFF header."
        );
    }
    r
}

pub fn supports_aslr(pe: &goblin::pe::PE) -> ASLRCompatibilityLevel {
    if (pe.header.coff_header.characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0 {
        // Base relocation information are absent. The loader cannot relocate the image.
        debug!("Bit 'IMAGE_FILE_RELOCS_STRIPPED' is set in 'Characteristics' inside COFF header.");
        ASLRCompatibilityLevel::Unsupported
    } else if let Some(optional_header) = pe.header.optional_header {
        if (optional_header.windows_fields.dll_characteristics
            & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
            != 0
        {
            let handles_addresses_larger_than_2_gigabytes =
                (pe.header.coff_header.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;

            if (optional_header.windows_fields.dll_characteristics
                & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
                != 0
            {
                debug!("Bit 'IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA' is set in 'DllCharacteristics' inside optional Windows header.");

                if handles_addresses_larger_than_2_gigabytes {
                    // High entropy ASLR.
                    ASLRCompatibilityLevel::Supported
                } else {
                    // High entropy ASLR, but below 2G.
                    ASLRCompatibilityLevel::SupportedBelow2G
                }
            } else if handles_addresses_larger_than_2_gigabytes {
                if pe.is_64 {
                    // Low entropy ASLR.
                    ASLRCompatibilityLevel::SupportedLowEntropy
                } else {
                    // ASLR supported in 32-bits even beyond 2G.
                    ASLRCompatibilityLevel::Supported
                }
            } else if pe.is_64 {
                // Low entropy ASLR and below 2G.
                ASLRCompatibilityLevel::SupportedLowEntropyBelow2G
            } else {
                // ASLR supported in 32-bits, but below 2G.
                ASLRCompatibilityLevel::SupportedBelow2G
            }
        } else {
            // The executable has a preferred address. ASLR will probably not be used, as it might
            // be expensive to relocate the executable.
            ASLRCompatibilityLevel::Expensive
        }
    } else {
        ASLRCompatibilityLevel::Unknown
    }
}

/// Returns information about support of Safe Structured Exception Handlers (SafeSEH).
///
/// When SafeSEH is supported, the executable has a table of safe exception handlers. This table
/// specifies for the operating system which exception handlers are valid for the image.
///
/// SafeSEH is optional only on x86 targets. Other architectures, such as x64 and ARM, always
/// store all exception handlers in the PDATA section.
pub fn has_safe_structured_exception_handlers(parser: &BinaryParser, pe: &goblin::pe::PE) -> bool {
    match has_safe_seh_handlers(parser, pe) {
        Some(true) => true,
        Some(false) | None => has_pdata_section(pe),
    }
}

/// Returns `true` if the executable has a `PDATA` (`.pdata`) section, where all exception handlers
/// are stored.
fn has_pdata_section(pe: &goblin::pe::PE) -> bool {
    pe.sections.iter().any(|section| {
        if (section.characteristics & PDATA_CHARACTERISTICS) == PDATA_CHARACTERISTICS {
            // If this section name is valid UTF-8, then `r` will be `true` if the name equals
            // `.pdata`, and false otherwise. For non UTF-8-valid names, `r` will be `false`.
            let r = section.name().map(|name| name == ".pdata").unwrap_or(false);
            if r {
                debug!("Section '.pdata' found in the executable.");
            }
            r
        } else {
            false
        }
    })
}

/// Returns `Some(true)` if the executable has an image load configuration directory, in which
/// at least one SafeSEH handler is referenced.
///
/// This returns `Some(false)` if the executable has an image load configuration directory,
/// in which no SafeSEH handlers are referenced. It returns `None` in all other cases.
fn has_safe_seh_handlers(parser: &BinaryParser, pe: &goblin::pe::PE) -> Option<bool> {
    pe.header
        .optional_header
        // If we actually have an optional header, get its load configuration table.
        .and_then(|optional_header| *optional_header.data_directories.get_load_config_table())
        // Continue only if the load configuration table has some bytes.
        .filter(|load_config_table| load_config_table.size > 0)
        .and_then(|load_config_table| {
            debug!("Reference to Image load configuration directory found in the executable.");

            let load_config_table_end = load_config_table.virtual_address + load_config_table.size;

            pe.sections
                .iter()
                // Find the `.rdata` section that has the bytes of this load configuration table.
                .find(|section| {
                    (section.characteristics & RDATA_CHARACTERISTICS) == RDATA_CHARACTERISTICS
                        && (load_config_table.virtual_address >= section.virtual_address)
                        && (load_config_table_end
                            <= (section.virtual_address + section.virtual_size))
                })
                // We still need `load_config_table`, so carry it forward to the next steps.
                .map(|section| (section, load_config_table))
        })
        // Find out if the load configuration table references some safe structured exception
        // handlers. The section is needed to read the bytes of the load configuration table.
        .and_then(|(section, load_config_table)| {
            image_load_configuration_directory_has_safe_seh_handlers(
                parser,
                pe,
                section,
                load_config_table,
            )
        })
}

fn image_load_configuration_directory_has_safe_seh_handlers(
    parser: &BinaryParser,
    pe: &goblin::pe::PE,
    section: &goblin::pe::section_table::SectionTable,
    load_config_table: goblin::pe::data_directories::DataDirectory,
) -> Option<bool> {
    debug!("Image load configuration directory found in the executable.");

    // Based on the architecture of the PE32/PE32+ file, find out relatively where and exactly
    // how large is the data representing the number of safe structured exception handlers.
    let (offset_of_se_handler_count, size_of_se_handler_count) = if pe.is_64 {
        (
            offset_of!(ImageLoadConfigDirectory64, SEHandlerCount),
            mem::size_of::<ImageLoadConfigDirectory64_SEHandlerCount_Type>(),
        )
    } else {
        (
            offset_of!(ImageLoadConfigDirectory32, SEHandlerCount),
            mem::size_of::<ImageLoadConfigDirectory32_SEHandlerCount_Type>(),
        )
    };

    // Convert virtual addresses into file offsets.
    let config_table_offset_in_section =
        load_config_table.virtual_address - section.virtual_address;
    let config_table_offset_in_file =
        (section.pointer_to_raw_data + config_table_offset_in_section) as usize;
    let se_handler_count_offset_in_file = config_table_offset_in_file + offset_of_se_handler_count;

    parser
        .bytes()
        .pread_with::<ImageLoadConfigDirectory_Size_Type>(
            config_table_offset_in_file as usize,
            scroll::LE,
        )
        .ok()
        // Only continue if the load configuration table size is big enough to read the number of
        // safe structured exception handlers.
        .filter(|load_config_directory_size| {
            (*load_config_directory_size as usize)
                >= (offset_of_se_handler_count + size_of_se_handler_count)
        })
        .and_then(|_load_config_directory_size| {
            debug!("Image load configuration directory defines 'SEHandlerCount'.");

            if pe.is_64 {
                // Read the number of safe structured exception handlers in a PE32+ executable.
                parser
                    .bytes()
                    .pread_with::<ImageLoadConfigDirectory64_SEHandlerCount_Type>(
                        se_handler_count_offset_in_file as usize,
                        scroll::LE,
                    )
            } else {
                // Read the number of safe structured exception handlers in a PE32 executable.
                parser
                    .bytes()
                    .pread_with::<ImageLoadConfigDirectory32_SEHandlerCount_Type>(
                        se_handler_count_offset_in_file as usize,
                        scroll::LE,
                    )
                    // To unify the comparison below, convert the count into the same type as in
                    // the PE32+ executable.
                    .map(ImageLoadConfigDirectory64_SEHandlerCount_Type::from)
            }
            .ok()
        })
        // Return `Some(true)` if the load configuration table references a least one safe
        // structured exception handler.
        .and_then(|se_handler_count| {
            debug!(
                "Image load configuration directory defines {} structured exceptions handlers.",
                se_handler_count
            );
            Some(se_handler_count > 0)
        })
}
