//! Checked little-endian reads and writes, and the compressed integers of
//! ECMA-335 II.23.2.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// The largest value that a compressed unsigned integer holds.
pub(crate) const MAX_COMPRESSED: u32 = 0x1FFF_FFFF;

/// A checked reader over borrowed bytes. Each read that passes the end
/// returns [`Error::Truncated`] with the name of the structure.
#[derive(Debug, Clone)]
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
    structure: &'static str,
}

impl<'a> Cursor<'a> {
    /// Makes a reader at the start of `data`.
    pub(crate) const fn new(data: &'a [u8], structure: &'static str) -> Self {
        Self {
            data,
            pos: 0,
            structure,
        }
    }

    /// Makes a reader at `pos` of `data`.
    pub(crate) fn at(data: &'a [u8], pos: usize, structure: &'static str) -> Result<Self> {
        if pos > data.len() {
            return Err(Error::Truncated {
                structure,
                offset: pos,
                needed: 0,
            });
        }
        Ok(Self {
            data,
            pos,
            structure,
        })
    }

    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Returns the bytes from the position to the end.
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Returns an error of this structure at the current position.
    pub(crate) const fn malformed(&self, reason: &'static str) -> Error {
        Error::Malformed {
            structure: self.structure,
            offset: self.pos,
            reason,
        }
    }

    /// Returns an error of this structure at `offset`.
    pub(crate) const fn malformed_at(&self, offset: usize, reason: &'static str) -> Error {
        Error::Malformed {
            structure: self.structure,
            offset,
            reason,
        }
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or(Error::Truncated {
                structure: self.structure,
                offset: self.pos,
                needed: len,
            })?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    pub(crate) fn skip(&mut self, len: usize) -> Result<()> {
        self.bytes(len).map(|_| ())
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn peek_u8(&self) -> Result<u8> {
        self.data.get(self.pos).copied().ok_or(Error::Truncated {
            structure: self.structure,
            offset: self.pos,
            needed: 1,
        })
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_le_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_le_bytes)
    }

    /// Reads a compressed unsigned integer (ECMA-335 II.23.2).
    pub(crate) fn compressed_u32(&mut self) -> Result<u32> {
        let start = self.pos;
        let first = self.u8()?;
        if first & 0x80 == 0 {
            Ok(u32::from(first))
        } else if first & 0xC0 == 0x80 {
            Ok((u32::from(first & 0x3F) << 8) | u32::from(self.u8()?))
        } else if first & 0xE0 == 0xC0 {
            let rest = self.array::<3>()?;
            Ok((u32::from(first & 0x1F) << 24)
                | (u32::from(rest[0]) << 16)
                | (u32::from(rest[1]) << 8)
                | u32::from(rest[2]))
        } else {
            Err(self.malformed_at(start, "the first byte of a compressed integer is not valid"))
        }
    }

    /// Reads a compressed signed integer (ECMA-335 II.23.2). The encoder
    /// rotates the two's complement value of 7, 14 or 29 bits left by one,
    /// so the sign bit is the lowest bit.
    pub(crate) fn compressed_i32(&mut self) -> Result<i32> {
        let start = self.pos;
        let raw = self.compressed_u32()?;
        let bits = match self.pos - start {
            1 => 7,
            2 => 14,
            _ => 29,
        };
        let magnitude = raw >> 1;
        let value = if raw & 1 == 0 {
            magnitude
        } else {
            magnitude | (u32::MAX << (bits - 1))
        };
        Ok(value.cast_signed())
    }

    /// Reads the bytes up to a zero byte, and the zero byte.
    pub(crate) fn zero_terminated_bytes(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        let len = self
            .rest()
            .iter()
            .position(|&b| b == 0)
            .ok_or(Error::Truncated {
                structure: self.structure,
                offset: start,
                needed: self.remaining() + 1,
            })?;
        let bytes = self.bytes(len)?;
        self.pos += 1;
        Ok(bytes)
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Writes an index of 2 or 4 bytes. A value that does not fit 2 bytes
/// returns [`Error::Overflow`].
pub(crate) fn put_index(
    out: &mut Vec<u8>,
    value: u32,
    width: u8,
    structure: &'static str,
) -> Result<()> {
    if width == 4 {
        put_u32(out, value);
    } else {
        let narrow = u16::try_from(value).map_err(|_| Error::Overflow {
            structure,
            value: u64::from(value),
        })?;
        put_u16(out, narrow);
    }
    Ok(())
}

/// Writes a compressed unsigned integer in its shortest form.
pub(crate) fn put_compressed_u32(
    out: &mut Vec<u8>,
    value: u32,
    structure: &'static str,
) -> Result<()> {
    let bytes = value.to_be_bytes();
    if value < 0x80 {
        out.push(bytes[3]);
    } else if value < 0x4000 {
        out.extend_from_slice(&[bytes[2] | 0x80, bytes[3]]);
    } else if value <= MAX_COMPRESSED {
        out.extend_from_slice(&[bytes[0] | 0xC0, bytes[1], bytes[2], bytes[3]]);
    } else {
        return Err(Error::Overflow {
            structure,
            value: u64::from(value),
        });
    }
    Ok(())
}

/// Writes a compressed signed integer in its shortest form.
pub(crate) fn put_compressed_i32(
    out: &mut Vec<u8>,
    value: i32,
    structure: &'static str,
) -> Result<()> {
    let bits: u32 = if (-(1 << 6)..1 << 6).contains(&value) {
        7
    } else if (-(1 << 13)..1 << 13).contains(&value) {
        14
    } else if (-(1 << 28)..1 << 28).contains(&value) {
        29
    } else {
        return Err(Error::Overflow {
            structure,
            value: u64::from(value.cast_unsigned()),
        });
    };
    let mask = (1u32 << bits) - 1;
    let raw = value.cast_unsigned() & mask;
    let rotated = ((raw << 1) & mask) | (raw >> (bits - 1));
    let start = out.len();
    put_compressed_u32(out, rotated, structure)?;
    // A small rotated value takes the short form, but its width must match
    // the width of the signed value, so widen it when it is too short.
    let written = out.len() - start;
    let wanted = match bits {
        7 => 1,
        14 => 2,
        _ => 4,
    };
    if written != wanted {
        out.truncate(start);
        let bytes = rotated.to_be_bytes();
        if wanted == 2 {
            out.extend_from_slice(&[bytes[2] | 0x80, bytes[3]]);
        } else {
            out.extend_from_slice(&[bytes[0] | 0xC0, bytes[1], bytes[2], bytes[3]]);
        }
    }
    Ok(())
}

/// Pads `out` with zero bytes to a multiple of 4.
pub(crate) fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn compressed_unsigned_integers_match_the_examples_of_the_standard() {
        let cases: [(u32, &[u8]); 8] = [
            (0x03, &[0x03]),
            (0x7F, &[0x7F]),
            (0x80, &[0x80, 0x80]),
            (0x2E57, &[0xAE, 0x57]),
            (0x3FFF, &[0xBF, 0xFF]),
            (0x4000, &[0xC0, 0x00, 0x40, 0x00]),
            (0x1FFF_FFFF, &[0xDF, 0xFF, 0xFF, 0xFF]),
            (0, &[0]),
        ];
        for (value, encoded) in cases {
            let mut out = Vec::new();
            put_compressed_u32(&mut out, value, "test").unwrap();
            assert_eq!(out, encoded);
            assert_eq!(
                Cursor::new(encoded, "test").compressed_u32().unwrap(),
                value
            );
        }
        assert!(put_compressed_u32(&mut Vec::new(), 0x2000_0000, "test").is_err());
        assert!(Cursor::new(&[0xE0], "test").compressed_u32().is_err());
    }

    #[test]
    fn compressed_signed_integers_match_the_examples_of_the_standard() {
        let cases: [(i32, &[u8]); 9] = [
            (3, &[0x06]),
            (-3, &[0x7B]),
            (64, &[0x80, 0x80]),
            (-64, &[0x01]),
            (8192, &[0xC0, 0x00, 0x40, 0x00]),
            (-8192, &[0x80, 0x01]),
            (268_435_455, &[0xDF, 0xFF, 0xFF, 0xFE]),
            (-268_435_456, &[0xC0, 0x00, 0x00, 0x01]),
            (-1, &[0x7F]),
        ];
        for (value, encoded) in cases {
            let mut out = Vec::new();
            put_compressed_i32(&mut out, value, "test").unwrap();
            assert_eq!(out, encoded, "{value}");
            assert_eq!(
                Cursor::new(encoded, "test").compressed_i32().unwrap(),
                value
            );
        }
    }

    #[test]
    fn a_read_past_the_end_names_the_structure_and_the_offset() {
        let mut cursor = Cursor::new(&[1, 2, 3], "sample");
        assert_eq!(cursor.u16().unwrap(), 0x0201);
        assert_eq!(
            cursor.u32(),
            Err(Error::Truncated {
                structure: "sample",
                offset: 2,
                needed: 4
            })
        );
        assert!(Cursor::new(b"abc", "s").zero_terminated_bytes().is_err());
        let mut names = Cursor::new(b"a\xFF\0b", "s");
        assert_eq!(names.zero_terminated_bytes().unwrap(), b"a\xFF");
        assert_eq!(names.position(), 3);
        let mut out = vec![1];
        pad4(&mut out);
        assert_eq!(out.len(), 4);
        assert!(put_index(&mut out, 0x1_0000, 2, "s").is_err());
    }
}
