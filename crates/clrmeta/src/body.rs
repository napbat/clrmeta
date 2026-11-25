//! Method bodies (ECMA-335 II.25.4): the tiny and fat headers, the code, and
//! the extra data sections with their exception handling clauses.
//!
//! The reader takes bytes, not a PE image. [`MethodBody::parse`] takes the
//! bytes from the first byte of the header, and [`MethodBody::at_rva`] takes
//! a closure that returns the bytes at a relative virtual address.

use alloc::vec::Vec;

pub use clrmeta_model::{ExceptionClause, ExceptionClauseKind};
pub use operands::{map_tokens, token_operands};

use crate::bytes::Cursor;
use crate::error::{Error, Result};
use crate::token::Token;

mod encode;
mod operands;
mod sections;
mod validate;

/// The header flag of a tiny header.
pub const TINY_FORMAT: u8 = 0x2;
/// The header flag of a fat header.
pub const FAT_FORMAT: u16 = 0x3;
/// The bits of the first header byte that hold [`FAT_FORMAT`] in a fat
/// header (`CoreCLR` `CorILMethod_FormatMask`). A first byte whose low 3 bits
/// are 7 starts no header that the runtime reads.
pub const FORMAT_MASK: u16 = 0x7;
/// The fat header flag: data sections follow the code.
pub const MORE_SECTS: u16 = 0x8;
/// The fat header flag: the runtime zeroes the local variables.
pub const INIT_LOCALS: u16 = 0x10;

/// The section kind bit: exception handling clauses.
pub const SECTION_EH_TABLE: u8 = 0x1;
/// The section kind bit: reserved optional IL table.
pub const SECTION_OPT_IL_TABLE: u8 = 0x2;
/// The bits of the section kind without the format bits. The runtime reads
/// the clauses of a section whose kind under this mask is
/// [`SECTION_EH_TABLE`] alone.
pub const SECTION_KIND_MASK: u8 = 0x3F;
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
    /// The section of exception handling clauses that the runtime reads:
    /// the next `count` clauses of [`MethodBody::clauses`].
    ExceptionClauses {
        /// `true` for 24-byte clauses and a 3-byte size.
        fat: bool,
        /// The number of clauses.
        count: usize,
        /// The bytes of the section as the parser read them: the header and
        /// the clauses. [`MethodBody::validate`] checks them. The encoder
        /// encodes [`MethodBody::clauses`] instead, and a section that the
        /// encoder makes has no bytes.
        raw: &'a [u8],
    },
    /// A section of another kind, or a section of clauses that the runtime
    /// does not read, kept as bytes.
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
    /// The bytes of a fat header after its first 12 bytes, which the
    /// runtime skips. Empty for a standard header. The encoder writes them,
    /// and zeros up to [`MethodBody::header_size`].
    pub extra_header: &'a [u8],
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
    /// The parser reads the body as the runtime reads it (`CoreCLR`
    /// `DecoderInit` and `CheckILMethod`):
    ///
    /// - The low 2 bits 2 make a tiny header, and the low 3 bits 3 a fat
    ///   header. A fat header of more than 3 dwords has more bytes before
    ///   the code; the flags that the runtime does not know stay in
    ///   [`MethodBody::flags`].
    /// - Each section starts at a multiple of 4. A section of clauses has
    ///   `DataSize / 12` (or `/ 24`) clauses, also when `DataSize` omits the
    ///   4 bytes of the section header, as old compilers wrote it. Its next
    ///   section starts after those clauses.
    /// - Only the first section can hold the clauses that the runtime uses,
    ///   and only when its kind under [`SECTION_KIND_MASK`] is
    ///   [`SECTION_EH_TABLE`]. Every other section is
    ///   [`DataSection::Other`].
    /// - The kind of a clause follows the bits of its flags as the JIT reads
    ///   them: fault, then finally, then filter, else catch. A clause can
    ///   lie outside the code; the JIT rejects the method when it compiles
    ///   it. [`MethodBody::validate`] reports these clauses.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is neither tiny nor fat, a fat
    /// header is shorter than 12 bytes, a section has a size of zero, or
    /// the body runs past `data`. The runtime rejects these bodies.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data, "method body");
        let first = cursor.peek_u8()?;
        if first & 0x3 == TINY_FORMAT {
            cursor.skip(1)?;
            let code = cursor.bytes(usize::from(first >> 2))?;
            Ok(Self {
                format: HeaderFormat::Tiny,
                flags: u16::from(TINY_FORMAT),
                header_size: 1,
                extra_header: &[],
                max_stack: 8,
                local_var_sig: Token::NULL,
                code,
                clauses: Vec::new(),
                sections: Vec::new(),
                size: cursor.position(),
            })
        } else if u16::from(first) & FORMAT_MASK == FAT_FORMAT {
            Self::parse_fat(&mut cursor)
        } else {
            Err(cursor.malformed("the header is neither tiny nor fat"))
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
        let extra_header = cursor.bytes(header_size - 12)?;
        let code = cursor.bytes(code_size)?;
        let mut body = Self {
            format: HeaderFormat::Fat,
            flags,
            header_size,
            extra_header,
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
