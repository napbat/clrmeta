//! The `#US` heap (II.24.2.4): UTF-16 strings with a compressed length and
//! a final flag byte.

use alloc::string::String;
use core::char::{REPLACEMENT_CHARACTER, decode_utf16};

use crate::bytes::Cursor;
use crate::error::{Error, HeapKind, Result};
use crate::token::Token;

/// A string of the `#US` heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserString<'a> {
    utf16: &'a [u8],
    flag: u8,
}

impl<'a> UserString<'a> {
    /// Returns the little-endian UTF-16 bytes.
    #[must_use]
    pub const fn utf16_bytes(&self) -> &'a [u8] {
        self.utf16
    }

    /// Returns the final byte: 1 when a character needs more than an 8-bit
    /// handling (II.24.2.4), else 0. An empty string, or an entry of an even
    /// length that has no final byte, returns 0.
    #[must_use]
    pub const fn flag(&self) -> u8 {
        self.flag
    }

    /// Returns the number of UTF-16 code units.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.utf16.len() / 2
    }

    /// Returns `true` for the empty string.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.utf16.is_empty()
    }

    /// Iterates over the UTF-16 code units.
    pub fn code_units(&self) -> impl Iterator<Item = u16> + 'a {
        let (pairs, _) = self.utf16.as_chunks::<2>();
        pairs.iter().map(|&pair| u16::from_le_bytes(pair))
    }

    /// Decodes the string. An unpaired surrogate becomes U+FFFD.
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        decode_utf16(self.code_units())
            .map(|c| c.unwrap_or(REPLACEMENT_CHARACTER))
            .collect()
    }

    /// Decodes the string.
    ///
    /// # Errors
    ///
    /// Returns an error when the string holds an unpaired surrogate.
    pub fn to_string(&self) -> Result<String> {
        decode_utf16(self.code_units())
            .collect::<core::result::Result<String, _>>()
            .map_err(|_| Error::Malformed {
                structure: "#US",
                offset: 0,
                reason: "the string holds an unpaired surrogate",
            })
    }
}

/// The `#US` heap over borrowed bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserStringsHeap<'a> {
    data: &'a [u8],
}

impl<'a> UserStringsHeap<'a> {
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

    /// Returns the string at an offset, as the runtime reads it (`CoreCLR`
    /// `MDInternalRO::GetUserString`): offset 0 is the empty string whatever
    /// the first byte of the heap holds, and an entry of an even length has
    /// no final byte, so every byte is part of the UTF-16 code units.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HeapIndex`] when the offset or the string is outside
    /// the heap, or the length is not a valid compressed integer.
    pub fn get(&self, offset: u32) -> Result<UserString<'a>> {
        let error = Error::HeapIndex {
            heap: HeapKind::UserStrings,
            index: offset,
        };
        if offset == 0 {
            return Ok(UserString {
                utf16: &[],
                flag: 0,
            });
        }
        let mut cursor =
            Cursor::at(self.data, offset as usize, "#US").map_err(|_| error.clone())?;
        read_entry(&mut cursor).ok_or(error)
    }

    /// Returns the string of a user string token (the operand of `ldstr`).
    ///
    /// # Errors
    ///
    /// Returns an error when the token is not a user string token or the
    /// string is not valid.
    pub fn get_token(&self, token: Token) -> Result<UserString<'a>> {
        if !token.is_user_string() {
            return Err(Error::Token {
                token,
                reason: "the token is not a user string token",
            });
        }
        self.get(token.row())
    }

    /// Iterates over the strings in heap order. The iteration stops at the
    /// first entry that is not valid (the padding of the stream).
    #[must_use]
    pub fn iter(&self) -> UserStringsIter<'a> {
        UserStringsIter {
            data: self.data,
            pos: 0,
        }
    }
}

fn read_entry<'a>(cursor: &mut Cursor<'a>) -> Option<UserString<'a>> {
    let len = cursor.compressed_u32().ok()? as usize;
    let bytes = cursor.bytes(len).ok()?;
    Some(match bytes.split_last() {
        Some((&flag, utf16)) if len % 2 == 1 => UserString { utf16, flag },
        _ => UserString {
            utf16: bytes,
            flag: 0,
        },
    })
}

impl<'a> IntoIterator for &UserStringsHeap<'a> {
    type Item = (u32, UserString<'a>);
    type IntoIter = UserStringsIter<'a>;

    fn into_iter(self) -> UserStringsIter<'a> {
        self.iter()
    }
}

/// The iterator over the strings of a `#US` heap.
#[derive(Debug, Clone)]
pub struct UserStringsIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for UserStringsIter<'a> {
    type Item = (u32, UserString<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let mut cursor = Cursor::at(self.data, self.pos, "#US").ok()?;
        if cursor.is_empty() {
            return None;
        }
        let offset = u32::try_from(self.pos).ok()?;
        let entry = read_entry(&mut cursor)?;
        self.pos = cursor.position();
        Some((offset, entry))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn a_user_string_decodes_its_utf16_bytes() {
        let heap = UserStringsHeap::new(&[0x00, 0x05, b'H', 0, b'i', 0, 0, 0x03, 0x3D, 0xD8, 1]);
        let hi = heap.get_token(Token(0x7000_0001)).unwrap();
        assert_eq!(hi.to_string().unwrap(), "Hi");
        assert_eq!(hi.flag(), 0);
        assert_eq!(hi.len(), 2);
        let lone = heap.get(7).unwrap();
        assert!(lone.to_string().is_err());
        assert_eq!(lone.to_string_lossy(), "\u{FFFD}");
        assert!(heap.get(20).is_err());
        assert!(heap.get_token(Token(0x0600_0001)).is_err());
        let offsets: Vec<_> = heap.iter().map(|(offset, _)| offset).collect();
        assert_eq!(offsets, [0, 1, 7]);
    }

    #[test]
    fn an_even_length_is_read_as_code_units_without_a_final_byte() {
        // The runtime takes size / 2 characters and does not require the
        // final byte.
        let heap = UserStringsHeap::new(&[0x07, 0x02, b'a', 0]);
        let even = heap.get(1).unwrap();
        assert_eq!(even.to_string().unwrap(), "a");
        assert_eq!(even.flag(), 0);
        // Offset 0 is the empty string whatever the heap holds.
        assert!(heap.get(0).unwrap().is_empty());
        assert!(UserStringsHeap::new(&[0, 0xFF]).get(1).is_err());
    }
}
