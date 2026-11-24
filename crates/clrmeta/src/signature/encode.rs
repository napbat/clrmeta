//! The writer of signature blobs.

use alloc::vec::Vec;

use clrmeta_model::{
    ArrayShape, FieldSig, LocalSig, MethodSig, MethodSpecSig, PropertySig, TableId, Token, TypeSig,
    calling_convention as cc, element_type as et,
};

use crate::bytes::{put_compressed_i32, put_compressed_u32};
use crate::error::{Error, Result};

const STRUCTURE: &str = "signature";

pub(crate) struct SigWriter {
    pub(crate) out: Vec<u8>,
}

impl SigWriter {
    pub(crate) const fn new() -> Self {
        Self { out: Vec::new() }
    }

    fn uint(&mut self, value: u32) -> Result<()> {
        put_compressed_u32(&mut self.out, value, STRUCTURE)
    }

    fn count(&mut self, value: usize) -> Result<()> {
        let value = u32::try_from(value).map_err(|_| Error::Overflow {
            structure: STRUCTURE,
            value: value as u64,
        })?;
        self.uint(value)
    }

    /// Writes a `TypeDefOrRefOrSpecEncoded` token (II.23.2.8).
    pub(crate) fn type_token(&mut self, token: Token) -> Result<()> {
        let tag = match token.table() {
            Some(TableId::TypeDef) => 0,
            Some(TableId::TypeRef) => 1,
            Some(TableId::TypeSpec) => 2,
            _ => {
                return Err(Error::Token {
                    token,
                    reason: "a type in a signature must be a TypeDef, TypeRef or TypeSpec",
                });
            }
        };
        self.uint((token.row() << 2) | tag)
    }

    /// Writes a type (II.23.2.12).
    pub(crate) fn type_sig(&mut self, ty: &TypeSig) -> Result<()> {
        if let Some(element) = ty.primitive_element_type() {
            self.out.push(element);
            return Ok(());
        }
        match ty {
            TypeSig::Ptr(inner) => self.prefixed(et::PTR, inner),
            TypeSig::ByRef(inner) => self.prefixed(et::BYREF, inner),
            TypeSig::SzArray(inner) => self.prefixed(et::SZARRAY, inner),
            TypeSig::Pinned(inner) => self.prefixed(et::PINNED, inner),
            TypeSig::Class(token) => {
                self.out.push(et::CLASS);
                self.type_token(*token)
            }
            TypeSig::ValueType(token) => {
                self.out.push(et::VALUETYPE);
                self.type_token(*token)
            }
            TypeSig::Var(number) => {
                self.out.push(et::VAR);
                self.uint(*number)
            }
            TypeSig::MVar(number) => {
                self.out.push(et::MVAR);
                self.uint(*number)
            }
            TypeSig::Modified {
                required,
                modifier,
                inner,
            } => {
                self.out.push(if *required {
                    et::CMOD_REQD
                } else {
                    et::CMOD_OPT
                });
                self.type_token(*modifier)?;
                self.type_sig(inner)
            }
            TypeSig::Array(element, shape) => {
                self.prefixed(et::ARRAY, element)?;
                self.array_shape(shape)
            }
            TypeSig::GenericInst {
                value_type,
                generic,
                arguments,
            } => {
                self.out.push(et::GENERICINST);
                self.out.push(if *value_type {
                    et::VALUETYPE
                } else {
                    et::CLASS
                });
                self.type_token(*generic)?;
                self.types(arguments)
            }
            TypeSig::FnPtr(method) => {
                self.out.push(et::FNPTR);
                self.method_sig(method)
            }
            _ => Err(Error::Malformed {
                structure: STRUCTURE,
                offset: self.out.len(),
                reason: "the type has no encoding",
            }),
        }
    }

    fn prefixed(&mut self, element: u8, inner: &TypeSig) -> Result<()> {
        self.out.push(element);
        self.type_sig(inner)
    }

    fn types(&mut self, types: &[TypeSig]) -> Result<()> {
        self.count(types.len())?;
        types.iter().try_for_each(|ty| self.type_sig(ty))
    }

    fn array_shape(&mut self, shape: &ArrayShape) -> Result<()> {
        self.uint(shape.rank)?;
        self.count(shape.sizes.len())?;
        for &size in &shape.sizes {
            self.uint(size)?;
        }
        self.count(shape.lower_bounds.len())?;
        for &bound in &shape.lower_bounds {
            put_compressed_i32(&mut self.out, bound, STRUCTURE)?;
        }
        Ok(())
    }

    /// Writes a method signature.
    pub(crate) fn method_sig(&mut self, sig: &MethodSig) -> Result<()> {
        self.out.push(sig.calling_convention);
        if sig.calling_convention & cc::GENERIC != 0 {
            self.uint(sig.generic_param_count)?;
        }
        self.count(sig.params.len())?;
        self.type_sig(&sig.return_type)?;
        for (position, param) in sig.params.iter().enumerate() {
            if sig.sentinel == Some(position) {
                self.out.push(et::SENTINEL);
            }
            self.type_sig(param)?;
        }
        Ok(())
    }

    pub(crate) fn field_sig(&mut self, sig: &FieldSig) -> Result<()> {
        self.out.push(cc::FIELD);
        self.type_sig(&sig.field_type)
    }

    pub(crate) fn property_sig(&mut self, sig: &PropertySig) -> Result<()> {
        self.out.push(sig.calling_convention);
        self.count(sig.params.len())?;
        self.type_sig(&sig.property_type)?;
        sig.params.iter().try_for_each(|ty| self.type_sig(ty))
    }

    pub(crate) fn local_sig(&mut self, sig: &LocalSig) -> Result<()> {
        self.out.push(cc::LOCAL_SIG);
        self.types(&sig.locals)
    }

    pub(crate) fn method_spec_sig(&mut self, sig: &MethodSpecSig) -> Result<()> {
        self.out.push(cc::GENERICINST);
        self.types(&sig.arguments)
    }
}
