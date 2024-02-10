[![crates.io](https://img.shields.io/crates/v/binary-security-check.svg)](https://crates.io/crates/binary-security-check)
[![license](https://img.shields.io/github/license/koutheir/binary-security-check?color=black)](https://raw.githubusercontent.com/koutheir/binary-security-check/master/LICENSE.txt)

# Analyzer of security features in executable binaries

`binary-security-check` is a command line utility that analyzes executable
binaries looking for features that make the executable more secure,
or less prone to some vulnerabilities.

## Installation instructions

In order to use this tool on your computer, you need to build it from sources:

1. If you don't have a [Rust](https://www.rust-lang.org/) toolchain installed,
   then [install one](https://www.rust-lang.org/tools/install).
   I recommend installing the latest stable toolchain for your computer.

2. Install a C toolchain for your computer. For example on Debian Linux:
   ```
   sudo apt-get install build-essential
   ```

3. Build the sources:
   ```
   cargo install binary-security-check
   ```

4. You should be able to run the tool directly:
   ```
   binary-security-check -h
   ```

## Supported formats

Different executable formats are currently supported:

- `ELF` format in 32-bits and 64-bits variants.
  It is used, for instance, in Linux and BSD executable programs and shared libraries.
  These files usually have either no extension, or the `.so` extension.
- `Archive` format, used in static libraries storing object files.
  It is used, for example, in Linux and Windows static libraries.
  These files usually have one of the following extensions: `.a`, `.lib`, etc.
- `PE32` format (32-bits variant) and `PE32+` format (64-bits variant) used by
  Windows executable programs and shared libraries.
  These files usually have one of the following extensions: `.exe`, `.scr`, `.dll`, `.sys`, etc.
  16-bits executable binaries are not supported.

## Reported security features:

The list of security features analyzed by `binary-security-check` depends on the analyzed format.
Each security feature has a keyword identifying it in the report.

For the `ELF` format, the analyzed features are:

- Address Space Layout Randomization: `ASLR` option.
- Stack smashing protection: `STACK-PROT` option.
- Executable pages become read-only after relocation: `READ-ONLY-RELOC` option.
- Imported symbols are bound immediately during the loading of the binary: `IMMEDIATE-BIND` option.
- Potentially unsafe C library functions calls are replaced with more secure variants: `FORTIFY-SOURCE` option.

For the `Archive` format, the analyzed features are:

- Stack smashing protection: `STACK-PROT` option.

For `PE32` and `PE32+` formats, the analyzed features are:

- Address Space Layout Randomization: `ASLR`, `ASLR-EXPENSIVE`, `ASLR-LOW-ENTROPY-LT-2GB`, `ASLR-LOW-ENTROPY`, `ASLR-LT-2GB` options.
- Data Execution Prevention: `DATA-EXEC-PREVENT` option.
- Control Flow Guard: `CONTROL-FLOW-GUARD` option.
- Handling of addresses larger than 2 Gigabytes: `HANDLES-ADDR-GT-2GB` option.
- Executable has a check sum of its data: `CHECKSUM` option.
- Only allow running inside AppContainer: `RUNS-IN-APP-CONTAINER` option.
- Integrity verification is required based on digital signature: `VERIFY-DIGITAL-CERT` option.
- Manifest files must be considered when loading executable: `CONSIDER-MANIFEST` option.
- Safe Structured Exception Handling: `SAFE-SEH` option.

## Reporting format

The program can analyze multiple binary files.
For each file, it displays the file path, and the status of the checked security features.

The status of the security feature in the binary is indicated by a letter before the keyword:
- `+` means the feature is present/supported.
- `!` means the feature is absent/unsupported.
- `~` means the feature is probably present/supported.
- `?` means the feature status is unknown.

For example, `!ASLR` means the binary does not support Address Space Layout Randomization.

## Usage

```
Usage: binary-security-check [OPTIONS] <INPUT_FILES>...

Arguments:
  <INPUT_FILES>...
          Binary files to analyze

Options:
  -v, --verbose
          Verbose logging
  -c, --color <COLOR>
          Use color in standard output [default: auto] [possible values: auto, always, never]
  -l, --libc <LIBC>
          Path of the C runtime library file
  -s, --sysroot <SYSROOT>
          Path of the system root for finding the corresponding C runtime library
  -i, --libc-spec <LIBC_SPEC>
          Use an internal list of checked functions as specified by a specification
          [possible values: lsb1, lsb1dot1, lsb1dot2, lsb1dot3, lsb2, lsb2dot0dot1, lsb2dot1, lsb3,
          lsb3dot1, lsb3dot2, lsb4, lsb4dot1, lsb5]
  -n, --no-libc
          Assume that input files do not use any C runtime libraries
  -h, --help
          Print help
  -V, --version
          Print version

If --libc-spec is specified, then its value can be one of the following versions
of the Linux Standard Base specifications:
- lsb1: LSB 1.0.0.
- lsb1dot1: LSB 1.1.0.
- lsb1dot2: LSB 1.2.0.
- lsb1dot3: LSB 1.3.0.
- lsb2: LSB 2.0.0.
- lsb2dot0dot1: LSB 2.0.1.
- lsb2dot1: LSB 2.1.0.
- lsb3: LSB 3.0.0.
- lsb3dot1: LSB 3.1.0.
- lsb3dot2: LSB 3.2.0.
- lsb4: LSB 4.0.0.
- lsb4dot1: LSB 4.1.0.
- lsb5: LSB 5.0.0.

By default, this tool tries to automatically locate the C library in the
following directories:
- /lib/
- /usr/lib/
- /lib64/
- /usr/lib64/
- /lib32/
- /usr/lib32/

The tools "readelf" and "ldd" can be used to help find the path of the C library
needed by the analyzed files, which is given by the --libc parameter.
```

## Miscellaneous features

- Runs on multiple platforms, including Linux, FreeBSD and Windows.
- Supports all binary executable formats independently of which platform is used to run the tool.
- Operates in parallel when sensible.
- Output colored text.
- Support multiple ways to identify binary's dependent C library (if there is one),
  including Linux Standard Base (LSB) specifications.
- Designed to be easily extensible.

# License

Copyright 2018-2024 Koutheir Attouchi. See the `LICENSE.txt` file
at the top-level directory of this distribution.
Licensed under the MIT license.
This file may not be copied, modified, or distributed except according to those terms.
