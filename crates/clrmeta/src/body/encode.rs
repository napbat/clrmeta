//! The writer of method bodies.

use alloc::vec::Vec;

use crate::body::sections::{FAT_CLAUSE, SMALL_CLAUSE};
use crate::body::{
    DataSection, ExceptionClause, ExceptionClauseKind, HeaderFormat, MORE_SECTS, MethodBody,
    SECTION_EH_TABLE, SECTION_FAT_FORMAT, SECTION_MORE_SECTS, TINY_FORMAT,
};
use crate::bytes::{pad4, put_u16, put_u32};
use crate::error::{Error, Result};

const STRUCTURE: &str = "method body";

fn overflow(value: usize) -> Error {
    Error::Overflow {
        structure: STRUCTURE,
        value: value as u64,
    }
}

fn narrow<T: TryFrom<u32>>(value: u32) -> Result<T> {
    T::try_from(value).map_err(|_| overflow(value as usize))
}

pub(crate) fn encode(body: &MethodBody<'_>) -> Result<Vec<u8>> {
    let sections = sections_to_write(body)?;
    let mut out = Vec::with_capacity(body.header_size + body.code.len());
    match body.format {
        HeaderFormat::Tiny => {
            let fits = body.code.len() < 64
                && body.max_stack == 8
                && body.local_var_sig.0 == 0
                && sections.is_empty();
            if !fits {
                return Err(overflow(body.code.len()));
            }
            let size = u8::try_from(body.code.len()).map_err(|_| overflow(body.code.len()))?;
            out.push((size << 2) | TINY_FORMAT);
        }
        HeaderFormat::Fat => {
            let dwords = body.header_size / 4;
            if !body.header_size.is_multiple_of(4) || !(3..16).contains(&dwords) {
                return Err(overflow(body.header_size));
            }
            let mut flags = body.flags & 0x0FFF & !MORE_SECTS;
            if !sections.is_empty() {
                flags |= MORE_SECTS;
            }
            let dwords = u16::try_from(dwords).map_err(|_| overflow(dwords))?;
            put_u16(&mut out, flags | (dwords << 12));
            put_u16(&mut out, body.max_stack);
            put_u32(
                &mut out,
                u32::try_from(body.code.len()).map_err(|_| overflow(body.code.len()))?,
            );
            put_u32(&mut out, body.local_var_sig.0);
            out.resize(body.header_size, 0);
        }
    }
    out.extend_from_slice(body.code);
    let mut clauses = body.clauses.iter();
    let last = sections.len().saturating_sub(1);
    for (position, section) in sections.iter().enumerate() {
        pad4(&mut out);
        let more = if position == last {
            0
        } else {
            SECTION_MORE_SECTS
        };
        match *section {
            DataSection::ExceptionClauses { fat, count } => {
                let clause_size = if fat { FAT_CLAUSE } else { SMALL_CLAUSE };
                let kind = SECTION_EH_TABLE | more | if fat { SECTION_FAT_FORMAT } else { 0 };
                section_header(&mut out, kind, fat, 4 + count * clause_size)?;
                for clause in clauses.by_ref().take(count) {
                    write_clause(&mut out, clause, fat)?;
                }
            }
            DataSection::Other { kind, data } => {
                let fat = kind & SECTION_FAT_FORMAT != 0;
                section_header(&mut out, kind | more, fat, 4 + data.len())?;
                out.extend_from_slice(data);
            }
        }
    }
    Ok(out)
}

/// Returns the sections to write: the sections of the body, or one section
/// of every clause when the body names none.
fn sections_to_write<'a>(body: &MethodBody<'a>) -> Result<Vec<DataSection<'a>>> {
    if body.sections.is_empty() {
        if body.clauses.is_empty() {
            return Ok(Vec::new());
        }
        let fat =
            !body.clauses.iter().all(fits_small) || 4 + body.clauses.len() * SMALL_CLAUSE > 0xFF;
        return Ok(alloc::vec![DataSection::ExceptionClauses {
            fat,
            count: body.clauses.len()
        }]);
    }
    let counted: usize = body
        .sections
        .iter()
        .map(|section| match section {
            DataSection::ExceptionClauses { count, .. } => *count,
            DataSection::Other { .. } => 0,
        })
        .sum();
    if counted != body.clauses.len() {
        return Err(Error::Malformed {
            structure: STRUCTURE,
            offset: 0,
            reason: "the sections do not hold every clause",
        });
    }
    Ok(body.sections.clone())
}

fn fits_small(clause: &ExceptionClause) -> bool {
    let offset = |value: u32| u16::try_from(value).is_ok();
    let length = |range: &core::ops::Range<u32>| range.len() <= 0xFF;
    offset(clause.try_range.start)
        && offset(clause.handler_range.start)
        && length(&clause.try_range)
        && length(&clause.handler_range)
}

fn section_header(out: &mut Vec<u8>, kind: u8, fat: bool, size: usize) -> Result<()> {
    out.push(kind);
    if fat {
        let size = u32::try_from(size)
            .ok()
            .filter(|&size| size < 1 << 24)
            .ok_or_else(|| overflow(size))?;
        out.extend_from_slice(&size.to_le_bytes()[..3]);
    } else {
        out.push(u8::try_from(size).map_err(|_| overflow(size))?);
        put_u16(out, 0);
    }
    Ok(())
}

fn write_clause(out: &mut Vec<u8>, clause: &ExceptionClause, fat: bool) -> Result<()> {
    let operand = match clause.kind {
        ExceptionClauseKind::Catch(token) => token.0,
        ExceptionClauseKind::Filter(offset) => offset,
        ExceptionClauseKind::Finally | ExceptionClauseKind::Fault => 0,
    };
    let length = |range: &core::ops::Range<u32>| {
        range
            .end
            .checked_sub(range.start)
            .ok_or_else(|| overflow(range.start as usize))
    };
    let try_length = length(&clause.try_range)?;
    let handler_length = length(&clause.handler_range)?;
    if fat {
        for value in [
            clause.kind.flags(),
            clause.try_range.start,
            try_length,
            clause.handler_range.start,
            handler_length,
        ] {
            put_u32(out, value);
        }
    } else {
        put_u16(out, narrow(clause.kind.flags())?);
        put_u16(out, narrow(clause.try_range.start)?);
        out.push(narrow(try_length)?);
        put_u16(out, narrow(clause.handler_range.start)?);
        out.push(narrow(handler_length)?);
    }
    put_u32(out, operand);
    Ok(())
}
