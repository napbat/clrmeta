//! The rewrite of the type indices of a signature blob.
//!
//! A writer that adds rows to the type tables can receive a blob whose
//! `TypeDefOrRefOrSpecEncoded` indices (II.23.2.8) name rows that do not
//! exist yet, by a tag that a caller defines. [`map_type_indices`] walks the
//! grammar of the blob, gives each such index to a closure, and writes the
//! blob again with the values that the closure returns. Every other byte
//! stays as it is.

use alloc::vec::Vec;

use crate::bytes::{Cursor, put_compressed_u32};
use crate::error::Result;
use crate::signature::{calling_convention as cc, element_type as et};

/// The deepest nesting of types that the rewrite follows, as the parser.
const MAX_DEPTH: u32 = 64;

/// The grammar of a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobGrammar {
    /// A type (II.23.2.14), the blob of a `TypeSpec` row.
    Type,
    /// A signature that its first byte states: a method (II.23.2.1 to
    /// II.23.2.3), a field (II.23.2.4), a property (II.23.2.5), local
    /// variables (II.23.2.6) or a method instantiation (II.23.2.15).
    Signature,
}

/// Returns `blob` with each `TypeDefOrRefOrSpecEncoded` index replaced by
/// `map(index)`. The closure receives the raw value: the row shifted left
/// by 2 and the tag in the low 2 bits, the tag 3 included.
///
/// # Errors
///
/// Returns an error when the blob does not follow its grammar, when bytes
/// follow its end, when it nests deeper than the parser reads, or when the
/// closure fails or returns a value that has no compressed form.
pub fn map_type_indices(
    blob: &[u8],
    grammar: BlobGrammar,
    map: impl FnMut(u32) -> Result<u32>,
) -> Result<Vec<u8>> {
    let mut rewrite = Rewrite {
        blob,
        cursor: Cursor::new(blob, "signature"),
        out: Vec::with_capacity(blob.len()),
        map,
        depth: 0,
    };
    match grammar {
        BlobGrammar::Type => rewrite.type_sig()?,
        BlobGrammar::Signature => rewrite.signature()?,
    }
    if !rewrite.cursor.is_empty() {
        return Err(rewrite
            .cursor
            .malformed("bytes follow the end of the signature"));
    }
    Ok(rewrite.out)
}

struct Rewrite<'a, F> {
    blob: &'a [u8],
    cursor: Cursor<'a>,
    out: Vec<u8>,
    map: F,
    depth: u32,
}

impl<F: FnMut(u32) -> Result<u32>> Rewrite<'_, F> {
    fn byte(&mut self) -> Result<u8> {
        let value = self.cursor.u8()?;
        self.out.push(value);
        Ok(value)
    }

    fn uint(&mut self) -> Result<u32> {
        let value = self.cursor.compressed_u32()?;
        put_compressed_u32(&mut self.out, value, "signature")?;
        Ok(value)
    }

    /// Copies a signed compressed integer (a lower bound) byte for byte.
    fn int(&mut self) -> Result<()> {
        let start = self.cursor.position();
        self.cursor.compressed_i32()?;
        self.out
            .extend_from_slice(&self.blob[start..self.cursor.position()]);
        Ok(())
    }

    fn type_index(&mut self) -> Result<()> {
        let value = self.cursor.compressed_u32()?;
        let mapped = (self.map)(value)?;
        put_compressed_u32(&mut self.out, mapped, "signature")
    }

    fn signature(&mut self) -> Result<()> {
        let first = self.cursor.peek_u8()?;
        match first & cc::KIND_MASK {
            cc::FIELD => {
                self.byte()?;
                self.type_sig()
            }
            cc::LOCAL_SIG | cc::GENERICINST => {
                self.byte()?;
                let count = self.uint()?;
                (0..count).try_for_each(|_| self.type_sig())
            }
            cc::PROPERTY => {
                self.byte()?;
                let count = self.uint()?;
                self.type_sig()?;
                (0..count).try_for_each(|_| self.type_sig())
            }
            _ => self.method_sig(),
        }
    }

    fn method_sig(&mut self) -> Result<()> {
        let calling_convention = self.byte()?;
        if calling_convention & cc::GENERIC != 0 {
            self.uint()?;
        }
        let count = self.uint()?;
        self.type_sig()?;
        for _ in 0..count {
            if self.cursor.peek_u8()? == et::SENTINEL {
                self.byte()?;
            }
            self.type_sig()?;
        }
        Ok(())
    }

    fn type_sig(&mut self) -> Result<()> {
        if self.depth >= MAX_DEPTH {
            return Err(self.cursor.malformed("the types nest too deep"));
        }
        self.depth += 1;
        let start = self.cursor.position();
        let element = self.byte()?;
        match element {
            et::PTR | et::BYREF | et::SZARRAY | et::PINNED => self.type_sig()?,
            et::VALUETYPE | et::CLASS => self.type_index()?,
            et::VAR | et::MVAR => {
                self.uint()?;
            }
            et::CMOD_REQD | et::CMOD_OPT => {
                self.type_index()?;
                self.type_sig()?;
            }
            et::ARRAY => {
                self.type_sig()?;
                self.uint()?;
                let sizes = self.uint()?;
                (0..sizes).try_for_each(|_| self.uint().map(drop))?;
                let bounds = self.uint()?;
                (0..bounds).try_for_each(|_| self.int())?;
            }
            et::GENERICINST => {
                let kind = self.byte()?;
                if kind != et::CLASS && kind != et::VALUETYPE {
                    return Err(self
                        .cursor
                        .malformed_at(start, "a generic instantiation needs CLASS or VALUETYPE"));
                }
                self.type_index()?;
                let count = self.uint()?;
                (0..count).try_for_each(|_| self.type_sig())?;
            }
            et::FNPTR => self.method_sig()?,
            et::VOID
            | et::BOOLEAN
            | et::CHAR
            | et::I1
            | et::U1
            | et::I2
            | et::U2
            | et::I4
            | et::U4
            | et::I8
            | et::U8
            | et::R4
            | et::R8
            | et::STRING
            | et::TYPEDBYREF
            | et::I
            | et::U
            | et::OBJECT => {}
            _ => {
                return Err(self
                    .cursor
                    .malformed_at(start, "the element type is not valid in a type"));
            }
        }
        self.depth -= 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{BlobGrammar, map_type_indices};
    use crate::signature::{LocalSig, MethodSig, Signature as _, TypeSig};
    use crate::tables::TableId;
    use crate::token::Token;

    /// Maps the tag 3 with row `n` to the `TypeRef` row `n + 10`.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the closure of map_type_indices returns a Result"
    )]
    fn resolve(value: u32) -> crate::Result<u32> {
        Ok(if value & 3 == 3 {
            (((value >> 2) + 10) << 2) | 1
        } else {
            value
        })
    }

    #[test]
    fn a_tag_3_index_becomes_a_row_in_each_place_of_a_type() {
        // LOCAL_SIG, 3 locals: class (tag 3, 1); valuetype TypeRef 2;
        // generic instance of (tag 3, 2) with argument int32[0...].
        let blob = vec![
            0x07, 0x03, 0x12, 0x07, 0x11, 0x09, 0x15, 0x12, 0x0B, 0x01, 0x14, 0x08, 0x01, 0x00,
            0x01, 0x7F,
        ];
        let written = map_type_indices(&blob, BlobGrammar::Signature, resolve).unwrap();
        let locals = LocalSig::parse(&written).unwrap();
        assert_eq!(
            locals.locals[0],
            TypeSig::Class(Token::new(TableId::TypeRef, 11))
        );
        assert_eq!(
            locals.locals[1],
            TypeSig::ValueType(Token::new(TableId::TypeRef, 2))
        );
        let TypeSig::GenericInst { generic, .. } = &locals.locals[2] else {
            panic!("a generic instance: {:?}", locals.locals[2]);
        };
        assert_eq!(*generic, Token::new(TableId::TypeRef, 12));
    }

    #[test]
    fn a_blob_without_tag_3_is_written_byte_for_byte() {
        // A method with a sentinel, a modifier, a pointer to a method and a
        // generic parameter.
        let blob = vec![
            0x05, 0x03, 0x01, 0x1F, 0x05, 0x08, 0x1B, 0x00, 0x00, 0x01, 0x41, 0x13, 0x00,
        ];
        assert!(MethodSig::parse(&blob).is_ok());
        assert_eq!(
            map_type_indices(&blob, BlobGrammar::Signature, resolve).unwrap(),
            blob
        );
        let field = vec![0x06, 0x1D, 0x0E];
        assert_eq!(
            map_type_indices(&field, BlobGrammar::Signature, resolve).unwrap(),
            field
        );
        let spec = vec![0x15, 0x11, 0x05, 0x01, 0x1E, 0x00];
        assert_eq!(
            map_type_indices(&spec, BlobGrammar::Type, resolve).unwrap(),
            spec
        );
        let instantiation = vec![0x0A, 0x01, 0x12, 0x0F];
        assert_eq!(
            map_type_indices(&instantiation, BlobGrammar::Signature, resolve).unwrap(),
            vec![0x0A, 0x01, 0x12, 0x35]
        );
    }

    #[test]
    fn a_blob_that_breaks_its_grammar_is_refused() {
        assert!(map_type_indices(&[0x07, 0x01], BlobGrammar::Signature, resolve).is_err());
        assert!(map_type_indices(&[0x08, 0x08], BlobGrammar::Type, resolve).is_err());
        assert!(map_type_indices(&[0x42], BlobGrammar::Type, resolve).is_err());
        assert!(map_type_indices(&[0x15, 0x08], BlobGrammar::Type, resolve).is_err());
        let deep = vec![0x0F; 100];
        assert!(map_type_indices(&deep, BlobGrammar::Type, resolve).is_err());
        let failing = |_| {
            Err(crate::Error::Overflow {
                structure: "test",
                value: 0,
            })
        };
        assert!(map_type_indices(&[0x12, 0x07], BlobGrammar::Type, failing).is_err());
    }
}
