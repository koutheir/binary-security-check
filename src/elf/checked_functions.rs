// Copyright 2018-2024 Koutheir Attouchi.
// See the "LICENSE.txt" file at the top-level directory of this distribution.
//
// Licensed under the MIT license. This file may not be copied, modified,
// or distributed except according to those terms.

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct CheckedFunction {
    checked_name: String,
}

impl CheckedFunction {
    pub fn from_checked_name(checked_name: &str) -> Self {
        Self {
            checked_name: String::from(checked_name),
        }
    }

    pub fn from_unchecked_name(unchecked_name: &str) -> Self {
        Self {
            checked_name: format!("__{unchecked_name}_chk"),
        }
    }

    pub fn _get_checked_name(&self) -> &str {
        &self.checked_name
    }

    pub fn get_unchecked_name(&self) -> &str {
        &self.checked_name[2..self.checked_name.len() - 4]
    }
}

/// [Functions prefixed by `__` and suffixed by `_chk`](http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/libc.html).
pub fn function_is_checked_version(name: &str) -> bool {
    name.starts_with("__") && name.ends_with("_chk")
}

/// - [LSB 4.0.0](http://refspecs.linux-foundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/libc.html).
/// - [LSB 4.1.0](http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/libc.html).
/// - [LSB 5.0.0](http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/libc.html).
pub static LSB_4_0_0_FUNCTIONS_WITH_CHECKED_VERSIONS: &[&str] = &[
    "confstr",
    "fgets",
    "fgets_unlocked",
    "fgetws",
    "fgetws_unlocked",
    "fprintf",
    "fwprintf",
    "getcwd",
    "getgroups",
    "gethostname",
    "getlogin_r",
    "mbsnrtowcs",
    "mbsrtowcs",
    "mbstowcs",
    "memcpy",
    "memmove",
    "mempcpy",
    "memset",
    "pread64",
    "pread",
    "printf",
    "read",
    "readlink",
    "realpath",
    "recv",
    "recvfrom",
    "snprintf",
    "sprintf",
    "stpcpy",
    "stpncpy",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
    "swprintf",
    "syslog",
    "ttyname_r",
    "vfprintf",
    "vfwprintf",
    "vprintf",
    "vsnprintf",
    "vsprintf",
    "vswprintf",
    "vsyslog",
    "vwprintf",
    "wcpcpy",
    "wcpncpy",
    "wcrtomb",
    "wcscat",
    "wcscpy",
    "wcsncat",
    "wcsncpy",
    "wcsnrtombs",
    "wcsrtombs",
    "wcstombs",
    "wctomb",
    "wmemcpy",
    "wmemmove",
    "wmempcpy",
    "wmemset",
    "wprintf",
];
