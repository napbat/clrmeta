//! The reader of signature blobs.

use alloc::boxed::Box;
use alloc::vec::Vec;

use clrmeta_model::{
    ArrayShape, FieldSig, LocalSig, MethodSig, MethodSpecSig, PropertySig, TableId, Token, TypeSig,
    calling_convention as cc, element_type as et,
};

use crate::bytes::Cursor;
use crate::error::Result;

/// The deepest nesting of types that the reader accepts. A deeper blob is
/// malformed or hostile, and recursion without a limit could exhaust the
/// stack.
const MAX_DEPTH: u32 = 128;

pub(crate) struct SigReader<'a> {
    pub(crate) cursor: Cursor<'a>,
    depth: u32,
}

impl<'a> SigReader<'a> {
    pub(crate) const fn new(blob: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(blob, "signature"),
            depth: 0,
        }
    }

    /// Returns an error when bytes follow the signature.
    pub(crate) fn finish(&self) -> Result<()> {
        if self.cursor.is_empty() {
            Ok(())
        } else {
            Err(self
                .cursor
                .malformed("bytes follow the end of the signature"))
        }
    }

    fn count(&mut self) -> Result<usize> {
        let count = self.cursor.compressed_u32()? as usize;
        // Each item takes at least one byte, so a larger count is not valid.
        if count > self.cursor.remaining() {
            return Err(self
                .cursor
                .malformed("the count is larger than the signature"));
        }
        Ok(count)
    }

    /// Reads a `TypeDefOrRefOrSpecEncoded` token (II.23.2.8).
    pub(crate) fn type_token(&mut self) -> Result<Token> {
        let start = self.cursor.position();
        let value = self.cursor.compressed_u32()?;
        let table = match value & 3 {
            0 => TableId::TypeDef,
            1 => TableId::TypeRef,
            2 => TableId::TypeSpec,
            _ => return Err(self.cursor.malformed_at(start, "the type token has tag 3")),
        };
        Ok(Token::new(table, value >> 2))
    }

    fn boxed(&mut self) -> Result<Box<TypeSig>> {
        self.type_sig().map(Box::new)
    }

    /// Reads a type (II.23.2.12) with its custom modifiers and constraints.
    pub(crate) fn type_sig(&mut self) -> Result<TypeSig> {
        let start = self.cursor.position();
        if self.depth >= MAX_DEPTH {
            return Err(self.cursor.malformed("the types nest too deep"));
        }
        self.depth += 1;
        let element = self.cursor.u8()?;
        let ty = match element {
            et::PTR => TypeSig::Ptr(self.boxed()?),
            et::BYREF => TypeSig::ByRef(self.boxed()?),
            et::SZARRAY => TypeSig::SzArray(self.boxed()?),
            et::PINNED => TypeSig::Pinned(self.boxed()?),
            et::VALUETYPE => TypeSig::ValueType(self.type_token()?),
            et::CLASS => TypeSig::Class(self.type_token()?),
            et::VAR => TypeSig::Var(self.cursor.compressed_u32()?),
            et::MVAR => TypeSig::MVar(self.cursor.compressed_u32()?),
            et::CMOD_REQD | et::CMOD_OPT => TypeSig::Modified {
                required: element == et::CMOD_REQD,
                modifier: self.type_token()?,
                inner: self.boxed()?,
            },
            et::ARRAY => {
                let element = self.boxed()?;
                TypeSig::Array(element, self.array_shape()?)
            }
            et::GENERICINST => self.generic_inst()?,
            et::FNPTR => TypeSig::FnPtr(Box::new(self.method_sig()?)),
            other => TypeSig::from_primitive_element_type(other).ok_or_else(|| {
                self.cursor
                    .malformed_at(start, "the element type is not valid in a type")
            })?,
        };
        self.depth -= 1;
        Ok(ty)
    }

    fn generic_inst(&mut self) -> Result<TypeSig> {
        let kind_offset = self.cursor.position();
        let value_type = match self.cursor.u8()? {
            et::VALUETYPE => true,
            et::CLASS => false,
            _ => {
                return Err(self.cursor.malformed_at(
                    kind_offset,
                    "a generic instantiation needs CLASS or VALUETYPE",
                ));
            }
        };
        let generic = self.type_token()?;
        let count = self.count()?;
        let arguments = (0..count)
            .map(|_| self.type_sig())
            .collect::<Result<Vec<_>>>()?;
        Ok(TypeSig::GenericInst {
            value_type,
            generic,
            arguments,
        })
    }

    fn array_shape(&mut self) -> Result<ArrayShape> {
        let rank = self.cursor.compressed_u32()?;
        let size_count = self.count()?;
        let sizes = (0..size_count)
            .map(|_| self.cursor.compressed_u32())
            .collect::<Result<Vec<_>>>()?;
        let bound_count = self.count()?;
        let lower_bounds = (0..bound_count)
            .map(|_| self.cursor.compressed_i32())
            .collect::<Result<Vec<_>>>()?;
        Ok(ArrayShape {
            rank,
            sizes,
            lower_bounds,
        })
    }

    /// Reads a method signature (II.23.2.1 to II.23.2.3).
    pub(crate) fn method_sig(&mut self) -> Result<MethodSig> {
        let start = self.cursor.position();
        let calling_convention = self.cursor.u8()?;
        let kind = calling_convention & cc::KIND_MASK;
        if matches!(
            kind,
            cc::FIELD | cc::LOCAL_SIG | cc::PROPERTY | cc::GENERICINST
        ) || kind > cc::NATIVE_VARARG
        {
            return Err(self
                .cursor
                .malformed_at(start, "the calling convention is not one of a method"));
        }
        let generic_param_count = if calling_convention & cc::GENERIC != 0 {
            self.cursor.compressed_u32()?
        } else {
            0
        };
        let count = self.count()?;
        let return_type = self.type_sig()?;
        let mut params = Vec::with_capacity(count);
        let mut sentinel = None;
        while params.len() < count {
            if self.cursor.peek_u8()? == et::SENTINEL {
                if sentinel.is_some() {
                    return Err(self.cursor.malformed("the signature has two sentinels"));
                }
                self.cursor.skip(1)?;
                sentinel = Some(params.len());
            }
            params.push(self.type_sig()?);
        }
        Ok(MethodSig {
            calling_convention,
            generic_param_count,
            return_type,
            params,
            sentinel,
        })
    }

    /// Reads a field signature (II.23.2.4).
    pub(crate) fn field_sig(&mut self) -> Result<FieldSig> {
        self.expect_kind(cc::FIELD, 0, "a field signature starts with FIELD")?;
        Ok(FieldSig {
            field_type: self.type_sig()?,
        })
    }

    /// Reads a property signature (II.23.2.5).
    pub(crate) fn property_sig(&mut self) -> Result<PropertySig> {
        let calling_convention = self.expect_kind(
            cc::PROPERTY,
            cc::HAS_THIS,
            "a property signature starts with PROPERTY",
        )?;
        let count = self.count()?;
        let property_type = self.type_sig()?;
        let params = (0..count)
            .map(|_| self.type_sig())
            .collect::<Result<Vec<_>>>()?;
        Ok(PropertySig {
            calling_convention,
            property_type,
            params,
        })
    }

    /// Reads a local variable signature (II.23.2.6).
    pub(crate) fn local_sig(&mut self) -> Result<LocalSig> {
        self.expect_kind(cc::LOCAL_SIG, 0, "a local signature starts with LOCAL_SIG")?;
        let count = self.count()?;
        let locals = (0..count)
            .map(|_| self.type_sig())
            .collect::<Result<Vec<_>>>()?;
        Ok(LocalSig { locals })
    }

    /// Reads a method instantiation (II.23.2.15).
    pub(crate) fn method_spec_sig(&mut self) -> Result<MethodSpecSig> {
        self.expect_kind(
            cc::GENERICINST,
            0,
            "a method instantiation starts with GENERICINST",
        )?;
        let count = self.count()?;
        let arguments = (0..count)
            .map(|_| self.type_sig())
            .collect::<Result<Vec<_>>>()?;
        Ok(MethodSpecSig { arguments })
    }

    /// Reads the first byte and checks it: `kind` plus any of `allowed`.
    fn expect_kind(&mut self, kind: u8, allowed: u8, reason: &'static str) -> Result<u8> {
        let start = self.cursor.position();
        let value = self.cursor.u8()?;
        if value & !allowed == kind {
            Ok(value)
        } else {
            Err(self.cursor.malformed_at(start, reason))
        }
    }
}
