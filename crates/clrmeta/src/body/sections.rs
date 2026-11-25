//! The data sections of a method body (II.25.4.5) and their exception
//! handling clauses (II.25.4.6), as the runtime reads them.

use core::ops::Range;

use crate::body::{
    DataSection, ExceptionClause, ExceptionClauseKind, MORE_SECTS, MethodBody, SECTION_EH_TABLE,
    SECTION_FAT_FORMAT, SECTION_KIND_MASK, SECTION_MORE_SECTS, TINY_FORMAT,
};
use crate::bytes::Cursor;
use crate::error::{Error, Result};
use crate::token::Token;

/// The size of a small clause.
pub(crate) const SMALL_CLAUSE: usize = 12;
/// The size of a fat clause.
pub(crate) const FAT_CLAUSE: usize = 24;

/// The header of a data section.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SectionHeader {
    /// The kind byte.
    pub(crate) kind: u8,
    /// The `DataSize` field: the size of the section with its header.
    pub(crate) data_size: usize,
}

impl SectionHeader {
    /// Reads the 4 bytes of a section header.
    pub(crate) fn read(bytes: [u8; 4]) -> Self {
        let kind = bytes[0];
        let data_size = if kind & SECTION_FAT_FORMAT != 0 {
            u32::from_le_bytes([bytes[1], bytes[2], bytes[3], 0]) as usize
        } else {
            usize::from(bytes[1])
        };
        Self { kind, data_size }
    }

    pub(crate) const fn is_fat(self) -> bool {
        self.kind & SECTION_FAT_FORMAT != 0
    }

    /// Returns `true` when the runtime reads the section as clauses.
    pub(crate) const fn is_clauses(self) -> bool {
        self.kind & SECTION_KIND_MASK == SECTION_EH_TABLE
    }

    pub(crate) const fn clause_size(self) -> usize {
        if self.is_fat() {
            FAT_CLAUSE
        } else {
            SMALL_CLAUSE
        }
    }

    /// Returns the number of clauses of a section of clauses: `DataSize`
    /// over the size of a clause (`CoreCLR` `COR_ILMETHOD_SECT_EH::EHCount`).
    pub(crate) const fn clause_count(self) -> usize {
        self.data_size / self.clause_size()
    }

    /// Returns the size of the section in bytes, as the runtime walks the
    /// sections (`CoreCLR` `COR_ILMETHOD_SECT::DataSize`): a section of
    /// clauses holds the header and its clauses whatever `DataSize` says,
    /// because some compilers left the header out of `DataSize`. A section
    /// of another kind holds `DataSize` bytes, and the next section starts
    /// after its header at least.
    pub(crate) const fn extent(self) -> usize {
        if self.is_clauses() {
            4 + self.clause_count() * self.clause_size()
        } else if self.data_size < 4 {
            4
        } else {
            self.data_size
        }
    }

    /// Returns `true` for a section that the runtime rejects: a section of
    /// another kind whose `DataSize` is zero (`CoreCLR` `CheckILMethod`).
    pub(crate) const fn is_empty(self) -> bool {
        !self.is_clauses() && self.data_size == 0
    }
}

/// Returns the error of a section of size zero, which the runtime rejects
/// (`CoreCLR` `CheckILMethod`).
const fn empty_section(offset: usize) -> Error {
    Error::Malformed {
        structure: "method body",
        offset,
        reason: "a section has a size of zero",
    }
}

/// Reads the sections that follow the code, from the cursor at the end of
/// the code.
pub(crate) fn parse<'a>(cursor: &mut Cursor<'a>, body: &mut MethodBody<'a>) -> Result<()> {
    loop {
        let aligned = cursor.position().next_multiple_of(4);
        cursor.skip(aligned - cursor.position())?;
        let start = cursor.position();
        let rest = cursor.rest();
        let header = SectionHeader::read(cursor.array()?);
        if header.is_empty() {
            return Err(empty_section(start));
        }
        let data = cursor.bytes(header.extent() - 4)?;
        if header.is_clauses() && body.sections.is_empty() {
            let size = header.clause_size();
            body.clauses.extend(
                data.chunks_exact(size)
                    .map(|raw| read_clause(raw, header.is_fat())),
            );
            body.sections.push(DataSection::ExceptionClauses {
                fat: header.is_fat(),
                count: header.clause_count(),
                raw: rest.get(..header.extent()).unwrap_or_default(),
            });
        } else {
            body.sections.push(DataSection::Other {
                kind: header.kind & !SECTION_MORE_SECTS,
                data,
            });
        }
        if header.kind & SECTION_MORE_SECTS == 0 {
            return Ok(());
        }
    }
}

/// Reads the fields of a clause of `raw`, which holds a whole clause.
pub(crate) fn clause_fields(raw: &[u8], fat: bool) -> [u32; 6] {
    let mut cursor = Cursor::new(raw, "exception clause");
    let mut field = |wide: bool, narrow: usize| {
        let read = if wide {
            cursor.u32()
        } else if narrow == 2 {
            cursor.u16().map(u32::from)
        } else {
            cursor.u8().map(u32::from)
        };
        read.unwrap_or_default()
    };
    let flags = field(fat, 2);
    let try_offset = field(fat, 2);
    let try_length = field(fat, 1);
    let handler_offset = field(fat, 2);
    let handler_length = field(fat, 1);
    let operand = field(true, 4);
    [
        flags,
        try_offset,
        try_length,
        handler_offset,
        handler_length,
        operand,
    ]
}

/// Reads a clause. The kind follows the bits of the flags as the JIT reads
/// them (`CoreCLR` `ToEHHandlerType`): fault, then finally, then filter, else
/// catch; it ignores the other bits. A block whose end passes 4 GiB wraps,
/// as the 32-bit arithmetic of the JIT wraps.
fn read_clause(raw: &[u8], fat: bool) -> ExceptionClause {
    let [
        flags,
        try_offset,
        try_length,
        handler_offset,
        handler_length,
        operand,
    ] = clause_fields(raw, fat);
    let kind = if flags & ExceptionClauseKind::FLAG_FAULT != 0 {
        ExceptionClauseKind::Fault
    } else if flags & ExceptionClauseKind::FLAG_FINALLY != 0 {
        ExceptionClauseKind::Finally
    } else if flags & ExceptionClauseKind::FLAG_FILTER != 0 {
        ExceptionClauseKind::Filter(operand)
    } else {
        ExceptionClauseKind::Catch(Token(operand))
    };
    ExceptionClause {
        kind,
        try_range: range(try_offset, try_length),
        handler_range: range(handler_offset, handler_length),
    }
}

const fn range(offset: u32, length: u32) -> Range<u32> {
    offset..offset.wrapping_add(length)
}

/// Returns the size of the body that starts at the first byte of `fetch`.
/// `fetch(len)` returns at least `len` bytes or an error. The walk matches
/// [`parse`].
pub(crate) fn probe_size<'a>(fetch: impl Fn(usize) -> Result<&'a [u8]>) -> Result<usize> {
    let first = Cursor::new(fetch(1)?, "method body").u8()?;
    if first & 0x3 == TINY_FORMAT {
        return Ok(1 + usize::from(first >> 2));
    }
    let mut header = Cursor::new(fetch(12)?, "method body");
    let flags_and_size = header.u16()?;
    header.skip(2)?;
    let code_size = header.u32()? as usize;
    let mut end = (usize::from(flags_and_size >> 12) * 4)
        .checked_add(code_size)
        .ok_or_else(|| too_large(code_size))?;
    if flags_and_size & MORE_SECTS == 0 {
        return Ok(end);
    }
    loop {
        let start = end.next_multiple_of(4);
        let mut bytes = Cursor::at(fetch(start + 4)?, start, "method body")?;
        let section = SectionHeader::read(bytes.array()?);
        if section.is_empty() {
            return Err(empty_section(start));
        }
        end = start + section.extent();
        if section.kind & SECTION_MORE_SECTS == 0 {
            return Ok(end);
        }
    }
}

const fn too_large(size: usize) -> Error {
    Error::Overflow {
        structure: "method body",
        value: size as u64,
    }
}
