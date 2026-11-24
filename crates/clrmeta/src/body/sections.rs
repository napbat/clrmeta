//! The data sections of a method body (II.25.4.5) and their exception
//! handling clauses (II.25.4.6).

use core::ops::Range;

use crate::body::{
    DataSection, ExceptionClause, ExceptionClauseKind, MORE_SECTS, MethodBody, SECTION_EH_TABLE,
    SECTION_FAT_FORMAT, SECTION_MORE_SECTS, TINY_FORMAT,
};
use crate::bytes::Cursor;
use crate::error::{Error, Result};
use crate::token::Token;

/// The size of a small clause.
pub(crate) const SMALL_CLAUSE: usize = 12;
/// The size of a fat clause.
pub(crate) const FAT_CLAUSE: usize = 24;

/// Reads the sections that follow the code, from the cursor at the end of
/// the code.
pub(crate) fn parse<'a>(cursor: &mut Cursor<'a>, body: &mut MethodBody<'a>) -> Result<()> {
    loop {
        let aligned = cursor.position().next_multiple_of(4);
        cursor.skip(aligned - cursor.position())?;
        let start = cursor.position();
        let kind = cursor.u8()?;
        let fat = kind & SECTION_FAT_FORMAT != 0;
        let data_size = if fat {
            let size = cursor.array::<3>()?;
            u32::from_le_bytes([size[0], size[1], size[2], 0]) as usize
        } else {
            let size = usize::from(cursor.u8()?);
            cursor.skip(2)?;
            size
        };
        let Some(payload) = data_size.checked_sub(4) else {
            return Err(cursor.malformed_at(start, "a section is shorter than its header"));
        };
        let data = cursor.bytes(payload)?;
        if kind & SECTION_EH_TABLE != 0 {
            let clause_size = if fat { FAT_CLAUSE } else { SMALL_CLAUSE };
            let count = payload / clause_size;
            for (position, raw) in data.chunks_exact(clause_size).enumerate() {
                let clause = read_clause(raw, fat).ok_or_else(|| {
                    cursor.malformed_at(
                        start + 4 + position * clause_size,
                        "the clause flags are not valid",
                    )
                })?;
                check_clause(&clause, body.code.len()).map_err(|reason| {
                    cursor.malformed_at(start + 4 + position * clause_size, reason)
                })?;
                body.clauses.push(clause);
            }
            body.sections
                .push(DataSection::ExceptionClauses { fat, count });
        } else {
            body.sections.push(DataSection::Other {
                kind: kind & !SECTION_MORE_SECTS,
                data,
            });
        }
        if kind & SECTION_MORE_SECTS == 0 {
            return Ok(());
        }
    }
}

fn read_clause(raw: &[u8], fat: bool) -> Option<ExceptionClause> {
    let mut cursor = Cursor::new(raw, "exception clause");
    let field = |cursor: &mut Cursor<'_>, wide: bool| {
        if wide {
            cursor.u32()
        } else {
            cursor.u16().map(u32::from)
        }
    };
    let byte_or_u32 = |cursor: &mut Cursor<'_>| {
        if fat {
            cursor.u32()
        } else {
            cursor.u8().map(u32::from)
        }
    };
    let flags = field(&mut cursor, fat).ok()?;
    let try_offset = field(&mut cursor, fat).ok()?;
    let try_length = byte_or_u32(&mut cursor).ok()?;
    let handler_offset = field(&mut cursor, fat).ok()?;
    let handler_length = byte_or_u32(&mut cursor).ok()?;
    let operand = cursor.u32().ok()?;
    let kind = match flags {
        ExceptionClauseKind::FLAG_EXCEPTION => ExceptionClauseKind::Catch(Token(operand)),
        ExceptionClauseKind::FLAG_FILTER => ExceptionClauseKind::Filter(operand),
        ExceptionClauseKind::FLAG_FINALLY => ExceptionClauseKind::Finally,
        ExceptionClauseKind::FLAG_FAULT => ExceptionClauseKind::Fault,
        _ => return None,
    };
    Some(ExceptionClause {
        kind,
        try_range: range(try_offset, try_length)?,
        handler_range: range(handler_offset, handler_length)?,
    })
}

fn range(offset: u32, length: u32) -> Option<Range<u32>> {
    Some(offset..offset.checked_add(length)?)
}

/// Checks that the blocks of a clause lie in the code.
fn check_clause(
    clause: &ExceptionClause,
    code_size: usize,
) -> core::result::Result<(), &'static str> {
    let fits = |range: &Range<u32>| range.end as usize <= code_size;
    if !fits(&clause.try_range) {
        return Err("the protected block ends after the code");
    }
    if !fits(&clause.handler_range) {
        return Err("the handler ends after the code");
    }
    if let Some(filter) = clause.filter_range()
        && filter.start >= filter.end
    {
        return Err("the filter does not start before its handler");
    }
    Ok(())
}

/// Returns the size of the body that starts at the first byte of `fetch`.
/// `fetch(len)` returns at least `len` bytes or an error.
pub(crate) fn probe_size<'a>(fetch: impl Fn(usize) -> Result<&'a [u8]>) -> Result<usize> {
    let first = fetch(1)?[0];
    if first & 0x3 == TINY_FORMAT {
        return Ok(1 + usize::from(first >> 2));
    }
    let mut header = Cursor::new(fetch(12)?, "method body");
    let flags_and_size = header.u16()?;
    header.skip(2)?;
    let code_size = header.u32()? as usize;
    let mut end = usize::from(flags_and_size >> 12) * 4 + code_size;
    if flags_and_size & MORE_SECTS == 0 {
        return Ok(end);
    }
    loop {
        let start = end.next_multiple_of(4);
        let bytes = fetch(start + 4)?;
        let kind = bytes[start];
        let data_size = if kind & SECTION_FAT_FORMAT != 0 {
            u32::from_le_bytes([bytes[start + 1], bytes[start + 2], bytes[start + 3], 0]) as usize
        } else {
            usize::from(bytes[start + 1])
        };
        if data_size < 4 {
            return Err(Error::Malformed {
                structure: "method body",
                offset: start,
                reason: "a section is shorter than its header",
            });
        }
        end = start + data_size;
        if kind & SECTION_MORE_SECTS == 0 {
            return Ok(end);
        }
    }
}
