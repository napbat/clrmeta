//! The `#Strings` heap (II.24.2.3): UTF-8 strings that end at a zero byte.

use alloc::borrow::Cow;
use alloc::string::String;

use crate::error::{Error, HeapKind, Result};
use crate::heaps::StringIndex;

/// The `#Strings` heap over borrowed bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringsHeap<'a> {
    data: &'a [u8],
}

impl<'a> StringsHeap<'a> {
    /// Makes a view of the bytes of the heap.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the bytes of the heap.
    #[must_use]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the bytes of the string at `index`, without the zero byte.
    ///
    /// The runtime cuts the heap after its last zero byte (`CoreCLR`
    /// `CLiteWeightStgdb::InitOnMem`), so a string in the bytes after the
    /// last zero byte does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeapIndex`] when the index is outside the heap or no
    /// zero byte ends the string. Index 0 of an empty heap is the empty
    /// string.
    pub fn get_bytes(&self, index: StringIndex) -> Result<&'a [u8]> {
        let error = Error::HeapIndex {
            heap: HeapKind::Strings,
            index: index.0,
        };
        if index.0 == 0 && self.data.is_empty() {
            return Ok(&[]);
        }
        let tail = self.data.get(index.0 as usize..).ok_or(error.clone())?;
        let len = tail.iter().position(|&b| b == 0).ok_or(error)?;
        Ok(&tail[..len])
    }

    /// Returns the string at `index`.
    ///
    /// # Errors
    ///
    /// Returns an error when the index is outside the heap or the string is
    /// not UTF-8. [`StringsHeap::get_lossy`] accepts a string that is not
    /// UTF-8.
    pub fn get(&self, index: StringIndex) -> Result<&'a str> {
        let bytes = self.get_bytes(index)?;
        core::str::from_utf8(bytes).map_err(|_| Error::Malformed {
            structure: "#Strings",
            offset: index.0 as usize,
            reason: "the string is not UTF-8",
        })
    }

    /// Returns the string at `index`, and replaces each sequence of bytes
    /// that is not UTF-8 with U+FFFD. The runtime does not check the UTF-8
    /// of names: it compares their bytes, and reflection shows a name that
    /// is not UTF-8 with replacement characters. The string borrows from the
    /// heap when it is UTF-8.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeapIndex`] when the index is outside the heap or no
    /// zero byte ends the string.
    pub fn get_lossy(&self, index: StringIndex) -> Result<Cow<'a, str>> {
        Ok(String::from_utf8_lossy(self.get_bytes(index)?))
    }

    /// Iterates over the strings in heap order, the empty string at offset 0
    /// included. A last string without a zero byte is not part of the heap
    /// (the padding of the stream).
    #[must_use]
    pub fn iter(&self) -> StringsIter<'a> {
        StringsIter {
            data: self.data,
            pos: 0,
        }
    }
}

impl<'a> IntoIterator for &StringsHeap<'a> {
    type Item = (StringIndex, &'a [u8]);
    type IntoIter = StringsIter<'a>;

    fn into_iter(self) -> StringsIter<'a> {
        self.iter()
    }
}

/// The iterator over the strings of a `#Strings` heap.
#[derive(Debug, Clone)]
pub struct StringsIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for StringsIter<'a> {
    type Item = (StringIndex, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let tail = self.data.get(self.pos..)?;
        let len = tail.iter().position(|&b| b == 0)?;
        let index = StringIndex(u32::try_from(self.pos).ok()?);
        self.pos += len + 1;
        Some((index, &tail[..len]))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn a_string_is_read_from_its_offset_to_the_zero_byte() {
        let heap = StringsHeap::new(b"\0Hello\0World\0\0\0");
        assert_eq!(heap.get(StringIndex(0)).unwrap(), "");
        assert_eq!(heap.get(StringIndex(1)).unwrap(), "Hello");
        assert_eq!(heap.get(StringIndex(3)).unwrap(), "llo");
        assert_eq!(heap.get(StringIndex(7)).unwrap(), "World");
        assert!(matches!(
            heap.get(StringIndex(99)),
            Err(Error::HeapIndex { .. })
        ));
        let entries: Vec<_> = heap.iter().map(|(index, _)| index.0).collect();
        assert_eq!(entries, [0, 1, 7, 13, 14]);
    }

    #[test]
    fn a_string_that_is_not_utf8_or_not_terminated_is_an_error() {
        let heap = StringsHeap::new(b"\0\xFF\0ab");
        assert!(heap.get_bytes(StringIndex(1)).is_ok());
        assert!(matches!(
            heap.get(StringIndex(1)),
            Err(Error::Malformed { .. })
        ));
        assert!(heap.get(StringIndex(3)).is_err());
        assert_eq!(StringsHeap::default().get(StringIndex(0)).unwrap(), "");
    }

    #[test]
    fn a_name_that_is_not_utf8_reads_with_replacement_characters() {
        // CoreCLR and .NET Framework load a type named "C\xFFrcle", and
        // reflection shows "C\u{FFFD}rcle".
        let heap = StringsHeap::new(b"\0C\xFFrcle\0Circle\0tail");
        assert_eq!(heap.get_lossy(StringIndex(1)).unwrap(), "C\u{FFFD}rcle");
        let valid = heap.get_lossy(StringIndex(8)).unwrap();
        assert!(matches!(valid, Cow::Borrowed("Circle")));
        // The bytes after the last zero byte are not a string.
        assert!(heap.get_lossy(StringIndex(15)).is_err());
    }
}
