//! Method bodies (ECMA-335 II.25.4): the tiny and fat headers, the code, and
//! the extra data sections with their exception handling clauses.
//!
//! The reader takes bytes, not a PE image. [`MethodBody::parse`] takes the
//! bytes from the first byte of the header, and [`MethodBody::at_rva`] takes
//! a closure that returns the bytes at a relative virtual address.

use alloc::vec::Vec;

pub use clrmeta_model::{ExceptionClause, ExceptionClauseKind};

use crate::bytes::Cursor;
use crate::error::{Error, Result};
use crate::token::Token;

mod encode;
mod sections;

/// The header flag of a tiny header.
pub const TINY_FORMAT: u8 = 0x2;
/// The header flag of a fat header.
pub const FAT_FORMAT: u16 = 0x3;
/// The fat header flag: data sections follow the code.
pub const MORE_SECTS: u16 = 0x8;
/// The fat header flag: the runtime zeroes the local variables.
pub const INIT_LOCALS: u16 = 0x10;

/// The section kind bit: exception handling clauses.
pub const SECTION_EH_TABLE: u8 = 0x1;
/// The section kind bit: reserved optional IL table.
pub const SECTION_OPT_IL_TABLE: u8 = 0x2;
/// The section kind bit: the section uses the fat format.
pub const SECTION_FAT_FORMAT: u8 = 0x40;
/// The section kind bit: another section follows.
pub const SECTION_MORE_SECTS: u8 = 0x80;

/// The format of a method header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderFormat {
    /// One byte: up to 63 bytes of code, a stack of 8, no locals, no
    /// sections.
    Tiny,
    /// Twelve bytes (or more): every field.
    Fat,
}

/// A data section after the code, in file order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataSection<'a> {
    /// A section of exception handling clauses: the next `count` clauses of
    /// [`MethodBody::clauses`].
    ExceptionClauses {
        /// `true` for 24-byte clauses and a 3-byte size.
        fat: bool,
        /// The number of clauses.
        count: usize,
    },
    /// A section of another kind, kept as bytes.
    Other {
        /// The kind byte without [`SECTION_MORE_SECTS`].
        kind: u8,
        /// The bytes after the section header.
        data: &'a [u8],
    },
}

/// A method body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodBody<'a> {
    /// The header format.
    pub format: HeaderFormat,
    /// The 12 flag bits of a fat header ([`FAT_FORMAT`], [`MORE_SECTS`],
    /// [`INIT_LOCALS`]), or [`TINY_FORMAT`].
    pub flags: u16,
    /// The size of the header in bytes (1 for a tiny header, 12 for a
    /// standard fat header).
    pub header_size: usize,
    /// The largest number of items on the evaluation stack.
    pub max_stack: u16,
    /// The `StandAloneSig` token of the local variables, or a null token.
    pub local_var_sig: Token,
    /// The code.
    pub code: &'a [u8],
    /// The exception handling clauses of every section, in file order.
    pub clauses: Vec<ExceptionClause>,
    /// The data sections in file order.
    pub sections: Vec<DataSection<'a>>,
    /// The size of the body in bytes, from the header to the end of the
    /// last section.
    pub size: usize,
}

impl<'a> MethodBody<'a> {
    /// Parses a body from the first byte of its header. `data` can run past
    /// the end of the body.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is not valid, the body runs past
    /// `data`, or a clause is not valid or lies outside the code.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data, "method body");
        let first = cursor.peek_u8()?;
        match first & 0x3 {
            TINY_FORMAT => {
                cursor.skip(1)?;
                let code = cursor.bytes(usize::from(first >> 2))?;
                Ok(Self {
                    format: HeaderFormat::Tiny,
                    flags: u16::from(TINY_FORMAT),
                    header_size: 1,
                    max_stack: 8,
                    local_var_sig: Token::NULL,
                    code,
                    clauses: Vec::new(),
                    sections: Vec::new(),
                    size: cursor.position(),
                })
            }
            0x3 => Self::parse_fat(&mut cursor),
            _ => Err(cursor.malformed("the header is neither tiny nor fat")),
        }
    }

    fn parse_fat(cursor: &mut Cursor<'a>) -> Result<Self> {
        let flags_and_size = cursor.u16()?;
        let flags = flags_and_size & 0x0FFF;
        let header_size = usize::from(flags_and_size >> 12) * 4;
        if header_size < 12 {
            return Err(cursor.malformed_at(0, "a fat header is shorter than 12 bytes"));
        }
        let max_stack = cursor.u16()?;
        let code_size = cursor.u32()? as usize;
        let local_var_sig = Token(cursor.u32()?);
        cursor.skip(header_size - 12)?;
        let code = cursor.bytes(code_size)?;
        let mut body = Self {
            format: HeaderFormat::Fat,
            flags,
            header_size,
            max_stack,
            local_var_sig,
            code,
            clauses: Vec::new(),
            sections: Vec::new(),
            size: cursor.position(),
        };
        if flags & MORE_SECTS != 0 {
            sections::parse(cursor, &mut body)?;
            body.size = cursor.position();
        }
        Ok(body)
    }

    /// Reads a body at a relative virtual address. `read(rva, len)` returns
    /// `len` bytes at `rva`, or `None` when the image does not hold them.
    /// The reader asks for the header first and then for the whole body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] with the offset of the read from `rva`
    /// when `read` returns `None`, and the errors of [`MethodBody::parse`].
    pub fn at_rva<F>(rva: u32, read: F) -> Result<Self>
    where
        F: Fn(u32, usize) -> Option<&'a [u8]>,
    {
        let fetch = |len: usize| {
            read(rva, len)
                .filter(|bytes| bytes.len() >= len)
                .ok_or(Error::Truncated {
                    structure: "method body",
                    offset: 0,
                    needed: len,
                })
        };
        let size = sections::probe_size(fetch)?;
        Self::parse(fetch(size)?)
    }

    /// Returns `true` when the runtime zeroes the local variables.
    #[must_use]
    pub const fn init_locals(&self) -> bool {
        self.flags & INIT_LOCALS != 0
    }

    /// Returns the offset of the code from the start of the header.
    #[must_use]
    pub const fn code_offset(&self) -> usize {
        self.header_size
    }

    /// Encodes the body: the header in its format, the code, and the
    /// sections. A body without [`MethodBody::sections`] but with clauses
    /// gets one section, small when every clause fits the small format.
    ///
    /// # Errors
    ///
    /// Returns an error when a value does not fit its field: a tiny header
    /// with more than 63 bytes of code, a stack other than 8, locals or
    /// clauses; a small clause with a large offset; or sections whose clause
    /// counts do not add up to the clauses.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode::encode(self)
    }
}

#[cfg(test)]
mod tests;
