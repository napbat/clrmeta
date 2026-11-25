//! The operands of the instructions of a method body (ECMA-335 III.1.2 and
//! the opcode table of Partition III), as far as a writer of metadata needs
//! them: the length of each instruction, and the place of each metadata
//! token.
//!
//! A writer that gives rows new numbers must write the new tokens into the
//! code. [`token_operands`] finds each token operand, and [`map_tokens`]
//! writes the tokens again in place: a token has 4 bytes in each form, so
//! no instruction moves.

use alloc::vec::Vec;

use crate::bytes::Cursor;
use crate::error::{Error, Result};
use crate::token::Token;

/// The prefix byte of the two-byte opcodes.
const TWO_BYTE: u8 = 0xFE;

/// The opcode of `switch`, whose operand is a count and a table.
const SWITCH: u8 = 0x45;

/// The operand of an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    /// No operand.
    None,
    /// A number or a branch displacement of this many bytes.
    Bytes(usize),
    /// A metadata token (`InlineField`, `InlineMethod`, `InlineSig`,
    /// `InlineString`, `InlineTok`, `InlineType`).
    Token,
    /// The table of `switch`.
    Switch,
}

/// Returns the operand of the one-byte opcode `opcode`, or `None` for a
/// byte that is no opcode.
const fn one_byte(opcode: u8) -> Option<Operand> {
    Some(match opcode {
        // ldarg.s, ldarga.s, starg.s, ldloc.s, ldloca.s, stloc.s,
        // ldc.i4.s, the short branches and leave.s.
        0x0E..=0x13 | 0x1F | 0x2B..=0x37 | 0xDE => Operand::Bytes(1),
        // ldc.i4, ldc.r4, the long branches and leave.
        0x20 | 0x22 | 0x38..=0x44 | 0xDD => Operand::Bytes(4),
        // ldc.i8 and ldc.r8.
        0x21 | 0x23 => Operand::Bytes(8),
        // jmp, call, calli, callvirt, cpobj, ldobj, ldstr, newobj,
        // castclass, isinst, unbox, the field instructions, stobj, box,
        // newarr, ldelema, ldelem, stelem, unbox.any, refanyval, mkrefany,
        // ldtoken.
        0x27..=0x29
        | 0x6F..=0x75
        | 0x79
        | 0x7B..=0x81
        | 0x8C
        | 0x8D
        | 0x8F
        | 0xA3..=0xA5
        | 0xC2
        | 0xC6
        | 0xD0 => Operand::Token,
        SWITCH => Operand::Switch,
        0x24 | 0x77 | 0x78 | 0xA6..=0xB2 | 0xBB..=0xC1 | 0xC4 | 0xC5 | 0xC7..=0xCF | 0xE1.. => {
            return None;
        }
        _ => Operand::None,
    })
}

/// Returns the operand of the two-byte opcode `0xFE opcode`, or `None` for
/// a byte that completes no opcode.
const fn two_byte(opcode: u8) -> Option<Operand> {
    Some(match opcode {
        // ldftn, ldvirtftn, initobj, constrained., sizeof.
        0x06 | 0x07 | 0x15 | 0x16 | 0x1C => Operand::Token,
        // ldarg, ldarga, starg, ldloc, ldloca, stloc.
        0x09..=0x0E => Operand::Bytes(2),
        // unaligned. and no.
        0x12 | 0x19 => Operand::Bytes(1),
        // arglist, the comparisons, localloc, endfilter, volatile., tail.,
        // cpblk, initblk, rethrow, refanytype, readonly.
        0x00..=0x05 | 0x0F | 0x11 | 0x13 | 0x14 | 0x17 | 0x18 | 0x1A | 0x1D | 0x1E => Operand::None,
        _ => return None,
    })
}

/// Returns the offset in `code` of the first byte of each token operand, in
/// ascending order.
///
/// # Errors
///
/// Returns an error when a byte is no opcode or an operand runs past the
/// end of the code.
pub fn token_operands(code: &[u8]) -> Result<Vec<usize>> {
    let mut cursor = Cursor::new(code, "method code");
    let mut offsets = Vec::new();
    while !cursor.is_empty() {
        let start = cursor.position();
        let first = cursor.u8()?;
        let operand = if first == TWO_BYTE {
            two_byte(cursor.u8()?)
        } else {
            one_byte(first)
        }
        .ok_or_else(|| cursor.malformed_at(start, "the byte is no opcode"))?;
        match operand {
            Operand::None => {}
            Operand::Bytes(count) => {
                cursor.bytes(count)?;
            }
            Operand::Token => {
                offsets.push(cursor.position());
                cursor.bytes(4)?;
            }
            Operand::Switch => {
                let count = cursor.u32()? as usize;
                let table = count.checked_mul(4).ok_or(Error::Malformed {
                    structure: "method code",
                    offset: start,
                    reason: "the table of the switch is too large",
                })?;
                cursor.bytes(table)?;
            }
        }
    }
    Ok(offsets)
}

/// Writes `map(token)` over each token operand of `code` and returns
/// whether a token changed.
///
/// # Errors
///
/// Returns the errors of [`token_operands`]; the code then stays as it was.
pub fn map_tokens(code: &mut [u8], mut map: impl FnMut(Token) -> Token) -> Result<bool> {
    let mut changed = false;
    for offset in token_operands(code)? {
        let field = &mut code[offset..offset + 4];
        let token = Token(u32::from_le_bytes([field[0], field[1], field[2], field[3]]));
        let mapped = map(token);
        if mapped != token {
            field.copy_from_slice(&mapped.0.to_le_bytes());
            changed = true;
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{map_tokens, token_operands};
    use crate::token::Token;

    /// `ldc.i4.s 5; ldc.i8 0; ldstr; call; switch (2); ldftn; ldarg 1;
    /// ldtoken; ret`.
    fn code() -> alloc::vec::Vec<u8> {
        let mut code = vec![0x1F, 5, 0x21, 0, 0, 0, 0, 0, 0, 0, 0];
        code.extend([0x72, 1, 0, 0, 0x70]);
        code.extend([0x28, 2, 0, 0, 0x06]);
        code.extend([0x45, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        code.extend([0xFE, 0x06, 3, 0, 0, 0x06]);
        code.extend([0xFE, 0x09, 1, 0]);
        code.extend([0xD0, 4, 0, 0, 0x0A]);
        code.push(0x2A);
        code
    }

    #[test]
    fn each_token_operand_is_found_past_the_other_operands() {
        assert_eq!(token_operands(&code()).unwrap(), [12, 17, 36, 45]);
    }

    #[test]
    fn a_map_writes_the_tokens_in_place() {
        let mut code = code();
        let before = code.clone();
        let renumber = |token: Token| {
            if token.0 >> 24 == 0x06 && token.row() >= 3 {
                Token(token.0 + 1)
            } else {
                token
            }
        };
        assert!(map_tokens(&mut code, renumber).unwrap());
        assert_eq!(code.len(), before.len());
        assert_eq!(
            &code[16..21],
            &[0x28, 2, 0, 0, 0x06],
            "row 2 keeps its number"
        );
        assert_eq!(&code[36..40], &[4, 0, 0, 0x06], "row 3 becomes row 4");
        assert_eq!(
            &code[45..49],
            &[4, 0, 0, 0x0A],
            "a MemberRef keeps its token"
        );
        assert!(!map_tokens(&mut code, |token| token).unwrap());
    }

    #[test]
    fn a_byte_that_is_no_opcode_or_a_short_operand_is_refused() {
        assert!(token_operands(&[0x24]).is_err());
        assert!(token_operands(&[0xFE, 0x08]).is_err());
        assert!(token_operands(&[0x28, 1, 0]).is_err());
        assert!(token_operands(&[0x45, 0xFF, 0xFF, 0xFF, 0xFF]).is_err());
        let mut code = [0x28, 1, 0, 0, 0x06, 0x24];
        assert!(map_tokens(&mut code, |token| Token(token.0 + 1)).is_err());
        assert_eq!(code, [0x28, 1, 0, 0, 0x06, 0x24], "a refused code stays");
    }
}
