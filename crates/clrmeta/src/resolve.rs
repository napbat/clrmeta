//! The resolution of the tokens of IL instructions to their entities.
//!
//! Each method checks the kind of entity: a `MemberRef` whose signature is a
//! field signature never resolves as a method, and a `MemberRef` with a
//! method signature never resolves as a field (ECMA-335 III.4).

use clrmeta_model::{FieldSig, LocalSig, MethodSig, MethodSpecSig, TableId, Token, TypeSig};

use crate::body::MethodBody;
use crate::error::{Error, Result};
use crate::heaps::{BlobIndex, UserString};
use crate::metadata::{Metadata, TypeName};
use crate::signature::{MemberSignature, Signature, StandAloneSignature};
use crate::tables::{
    FieldRow, MemberRefRow, MethodDefRow, MethodSpecRow, StandAloneSigRow, TypeSpecRow,
};
use crate::token::Rid;

/// A resolved method: a `MethodDef`, a `MemberRef` with a method signature,
/// or a `MethodSpec` of one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRef<'a> {
    /// The token that the resolver received.
    pub token: Token,
    /// The `MethodDef` or `MemberRef` of the method (the generic method of
    /// a `MethodSpec`).
    pub definition: Token,
    /// The owner: a `TypeDef` for a `MethodDef`; the `TypeDef`, `TypeRef`,
    /// `TypeSpec`, `ModuleRef` or (for a vararg call site) `MethodDef` of a
    /// `MemberRef`.
    pub owner: Token,
    /// The name.
    pub name: &'a str,
    /// The signature.
    pub signature: MethodSig,
    /// The type arguments of a `MethodSpec`.
    pub instantiation: Option<MethodSpecSig>,
}

/// A resolved field: a `Field` or a `MemberRef` with a field signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef<'a> {
    /// The token that the resolver received.
    pub token: Token,
    /// The owner: a `TypeDef` for a `Field`; the parent of a `MemberRef`.
    pub owner: Token,
    /// The name.
    pub name: &'a str,
    /// The signature.
    pub signature: FieldSig,
}

/// A resolved type operand (`newarr`, `box`, `castclass`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRef<'a> {
    /// A `TypeDef` or a `TypeRef` with its name.
    Named {
        /// The token.
        token: Token,
        /// The name.
        name: TypeName<'a>,
    },
    /// A `TypeSpec` with its signature.
    Spec {
        /// The token.
        token: Token,
        /// The signature.
        signature: TypeSig,
    },
}

/// The operand of `ldtoken`: a type, a method or a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Member<'a> {
    /// A type.
    Type(TypeRef<'a>),
    /// A method.
    Method(MethodRef<'a>),
    /// A field.
    Field(FieldRef<'a>),
}

/// Resolves the tokens of IL instructions against one module.
#[derive(Debug, Clone, Copy)]
pub struct Resolver<'m, 'a> {
    metadata: &'m Metadata<'a>,
}

impl<'m, 'a> Resolver<'m, 'a> {
    /// Makes a resolver over the metadata of a module.
    #[must_use]
    pub const fn new(metadata: &'m Metadata<'a>) -> Self {
        Self { metadata }
    }

    fn blob(self, index: BlobIndex) -> Result<&'a [u8]> {
        self.metadata.blobs().get(index)
    }

    fn kind_error(token: Token, reason: &'static str) -> Error {
        Error::Token { token, reason }
    }

    /// Resolves the operand of `call`, `callvirt`, `newobj`, `ldftn`,
    /// `ldvirtftn` or `jmp`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] for a token that is not a method (a field
    /// `MemberRef` included), and an error when a row, a name or a
    /// signature is not valid.
    pub fn method(&self, token: Token) -> Result<MethodRef<'a>> {
        match token.table() {
            Some(TableId::MethodDef) => {
                let rid = Rid::<MethodDefRow>::new(token.row());
                let row = self.metadata.tables().row(rid)?;
                let owner = self
                    .metadata
                    .method_owner(rid)
                    .ok_or_else(|| Self::kind_error(token, "no type owns the method"))?;
                Ok(MethodRef {
                    token,
                    definition: token,
                    owner: owner.token(),
                    name: self.metadata.strings().get(row.name)?,
                    signature: MethodSig::parse(self.blob(row.signature)?)?,
                    instantiation: None,
                })
            }
            Some(TableId::MemberRef) => {
                let row = self
                    .metadata
                    .tables()
                    .row(Rid::<MemberRefRow>::new(token.row()))?;
                match MemberSignature::parse(self.blob(row.signature)?)? {
                    MemberSignature::Method(signature) => Ok(MethodRef {
                        token,
                        definition: token,
                        owner: row.class,
                        name: self.metadata.strings().get(row.name)?,
                        signature,
                        instantiation: None,
                    }),
                    MemberSignature::Field(_) => Err(Self::kind_error(
                        token,
                        "the MemberRef names a field, not a method",
                    )),
                }
            }
            Some(TableId::MethodSpec) => {
                let row = self
                    .metadata
                    .tables()
                    .row(Rid::<MethodSpecRow>::new(token.row()))?;
                if matches!(row.method.table(), Some(TableId::MethodSpec)) {
                    return Err(Self::kind_error(token, "a MethodSpec names a MethodSpec"));
                }
                let mut method = self.method(row.method)?;
                method.token = token;
                method.instantiation = Some(MethodSpecSig::parse(self.blob(row.instantiation)?)?);
                Ok(method)
            }
            _ => Err(Self::kind_error(token, "the token is not a method")),
        }
    }

    /// Resolves the operand of `ldfld`, `stfld`, `ldsfld`, `stsfld`,
    /// `ldflda` or `ldsflda`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] for a token that is not a field (a method
    /// `MemberRef` included), and an error when a row, a name or a
    /// signature is not valid.
    pub fn field(&self, token: Token) -> Result<FieldRef<'a>> {
        match token.table() {
            Some(TableId::Field) => {
                let rid = Rid::<FieldRow>::new(token.row());
                let row = self.metadata.tables().row(rid)?;
                let owner = self
                    .metadata
                    .field_owner(rid)
                    .ok_or_else(|| Self::kind_error(token, "no type owns the field"))?;
                Ok(FieldRef {
                    token,
                    owner: owner.token(),
                    name: self.metadata.strings().get(row.name)?,
                    signature: FieldSig::parse(self.blob(row.signature)?)?,
                })
            }
            Some(TableId::MemberRef) => {
                let row = self
                    .metadata
                    .tables()
                    .row(Rid::<MemberRefRow>::new(token.row()))?;
                match MemberSignature::parse(self.blob(row.signature)?)? {
                    MemberSignature::Field(signature) => Ok(FieldRef {
                        token,
                        owner: row.class,
                        name: self.metadata.strings().get(row.name)?,
                        signature,
                    }),
                    MemberSignature::Method(_) => Err(Self::kind_error(
                        token,
                        "the MemberRef names a method, not a field",
                    )),
                }
            }
            _ => Err(Self::kind_error(token, "the token is not a field")),
        }
    }

    /// Resolves a type operand: a `TypeDef`, a `TypeRef` or a `TypeSpec`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] for a token of another table, and an error
    /// when a row, a name or a signature is not valid.
    pub fn type_ref(&self, token: Token) -> Result<TypeRef<'a>> {
        match token.table() {
            Some(TableId::TypeDef | TableId::TypeRef) => Ok(TypeRef::Named {
                token,
                name: self.metadata.type_name(token)?,
            }),
            Some(TableId::TypeSpec) => {
                let row = self
                    .metadata
                    .tables()
                    .row(Rid::<TypeSpecRow>::new(token.row()))?;
                Ok(TypeRef::Spec {
                    token,
                    signature: TypeSig::parse(self.blob(row.signature)?)?,
                })
            }
            _ => Err(Self::kind_error(token, "the token is not a type")),
        }
    }

    /// Resolves the operand of `ldtoken`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Resolver::type_ref`], [`Resolver::method`]
    /// and [`Resolver::field`].
    pub fn member(&self, token: Token) -> Result<Member<'a>> {
        match token.table() {
            Some(TableId::Field) => self.field(token).map(Member::Field),
            Some(TableId::MethodDef | TableId::MethodSpec) => {
                self.method(token).map(Member::Method)
            }
            Some(TableId::MemberRef) => {
                let row = self
                    .metadata
                    .tables()
                    .row(Rid::<MemberRefRow>::new(token.row()))?;
                if self.blob(row.signature)?.first()
                    == Some(&crate::signature::calling_convention::FIELD)
                {
                    self.field(token).map(Member::Field)
                } else {
                    self.method(token).map(Member::Method)
                }
            }
            _ => self.type_ref(token).map(Member::Type),
        }
    }

    /// Resolves the operand of `ldstr`. A .NET string can hold an unpaired
    /// surrogate, so the result keeps the UTF-16 code units;
    /// [`UserString::to_string`] decodes it when it is valid UTF-16.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is not a user string token or the
    /// string is outside the heap.
    pub fn user_string(&self, token: Token) -> Result<UserString<'a>> {
        self.metadata.user_strings().get_token(token)
    }

    /// Resolves a `StandAloneSig` token: the operand of `calli` or the local
    /// variable signature of a method body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] for a token of another table, and an error
    /// when the row or the signature is not valid.
    pub fn stand_alone(&self, token: Token) -> Result<StandAloneSignature> {
        let rid = Rid::<StandAloneSigRow>::from_token(token)
            .ok_or_else(|| Self::kind_error(token, "the token is not a StandAloneSig"))?;
        let row = self.metadata.tables().row(rid)?;
        StandAloneSignature::parse(self.blob(row.signature)?)
    }
}

impl<'a> Metadata<'a> {
    /// Returns a resolver over this metadata.
    #[must_use]
    pub const fn resolver(&self) -> Resolver<'_, 'a> {
        Resolver::new(self)
    }

    /// Parses the signature of a method definition.
    ///
    /// # Errors
    ///
    /// Returns an error when the row or the signature is not valid.
    pub fn method_signature(&self, method: Rid<MethodDefRow>) -> Result<MethodSig> {
        let row = self.tables().row(method)?;
        MethodSig::parse(self.blobs().get(row.signature)?)
    }

    /// Parses the signature of a field definition.
    ///
    /// # Errors
    ///
    /// Returns an error when the row or the signature is not valid.
    pub fn field_signature(&self, field: Rid<FieldRow>) -> Result<FieldSig> {
        let row = self.tables().row(field)?;
        FieldSig::parse(self.blobs().get(row.signature)?)
    }

    /// Parses the local variables of a method body: an empty list when the
    /// body has no `StandAloneSig` token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is not a `StandAloneSig` of a local
    /// variable signature, or the row or the signature is not valid.
    pub fn locals_of(&self, body: &MethodBody<'_>) -> Result<LocalSig> {
        if body.local_var_sig.is_null() {
            return Ok(LocalSig::default());
        }
        match self.resolver().stand_alone(body.local_var_sig)? {
            StandAloneSignature::Locals(locals) => Ok(locals),
            _ => Err(Error::Token {
                token: body.local_var_sig,
                reason: "the signature of the locals is not a local variable signature",
            }),
        }
    }

    /// Reads the body of a method definition. `read(rva, len)` returns `len`
    /// bytes at a relative virtual address; see [`MethodBody::at_rva`].
    /// Returns `None` for a method without a body (RVA zero).
    ///
    /// # Errors
    ///
    /// Returns an error when the row or the body is not valid.
    pub fn method_body<'b, F>(
        &self,
        method: Rid<MethodDefRow>,
        read: F,
    ) -> Result<Option<MethodBody<'b>>>
    where
        F: Fn(u32, usize) -> Option<&'b [u8]>,
    {
        let row = self.tables().row(method)?;
        if row.rva == 0 {
            return Ok(None);
        }
        MethodBody::at_rva(row.rva, read).map(Some)
    }
}
