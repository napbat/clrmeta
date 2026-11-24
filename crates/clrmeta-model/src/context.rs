//! The method context of one module: the data that gives meaning to the
//! instructions of its method bodies.
//!
//! A Common Intermediate Language (CIL) instruction names its operands with
//! metadata tokens, and its method states the argument, local and stack
//! limits in metadata. A consumer that decodes or lifts the instructions
//! needs these facts, but it must not parse metadata itself. A loader reads
//! the metadata of one module, fills a [`MethodTable`], and sends it to the
//! consumer, for example as `postcard` bytes under the encoding identifier
//! [`ENCODING`].
//!
//! Each list of a [`MethodTable`] is in ascending token order, so a consumer
//! finds an entry with a binary search on its token. A relative virtual
//! address (RVA) is an offset from the load base of the module: the consumer
//! adds the base.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::body::ExceptionClause;
use crate::signature::{FieldSig, LocalSig, MethodSig, TypeSig};
use crate::token::Token;

/// The identifier of the method-context encoding: a [`MethodTable`] in the
/// `postcard` format, version 1.
///
/// A change of a type of this module that changes the encoded bytes needs a
/// new version number.
pub const ENCODING: &str = "cil.methods/1";

/// The method context of one module.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MethodTable {
    /// The `MethodDef` token of the managed entry point, or `None` when the
    /// module has no managed entry point in its own methods.
    pub entry: Option<Token>,
    /// Every method definition (`MethodDef`) of the module.
    pub methods: Vec<Method>,
    /// Every method reference: each `MemberRef` that names a method and each
    /// `MethodSpec`.
    pub method_references: Vec<MethodReference>,
    /// Every field: each `Field` definition and each `MemberRef` that names a
    /// field.
    pub fields: Vec<Field>,
    /// Every type: each `TypeDef`, `TypeRef` and `TypeSpec`.
    pub types: Vec<Type>,
    /// Every stand-alone signature (`StandAloneSig`). The `calli`
    /// instruction names a method signature of this list.
    pub signatures: Vec<StandAloneSignature>,
    /// Every user string of the `#US` heap, by its `ldstr` token.
    pub strings: Vec<UserString>,
}

impl MethodTable {
    /// Returns the method definition of `token`.
    #[must_use]
    pub fn method(&self, token: Token) -> Option<&Method> {
        find(&self.methods, token, |method| method.token)
    }

    /// Returns the method reference of `token`.
    #[must_use]
    pub fn method_reference(&self, token: Token) -> Option<&MethodReference> {
        find(&self.method_references, token, |reference| reference.token)
    }

    /// Returns the field of `token`.
    #[must_use]
    pub fn field(&self, token: Token) -> Option<&Field> {
        find(&self.fields, token, |field| field.token)
    }

    /// Returns the type of `token`.
    #[must_use]
    pub fn type_entry(&self, token: Token) -> Option<&Type> {
        find(&self.types, token, |entry| entry.token)
    }

    /// Returns the stand-alone signature of `token`.
    #[must_use]
    pub fn signature(&self, token: Token) -> Option<&StandAloneSignature> {
        find(&self.signatures, token, |signature| signature.token)
    }

    /// Returns the user string of the `ldstr` token `token`.
    #[must_use]
    pub fn string(&self, token: Token) -> Option<&UserString> {
        find(&self.strings, token, |string| string.token)
    }
}

/// Finds the entry of `token` in a list in ascending token order.
fn find<T>(entries: &[T], token: Token, key: impl Fn(&T) -> Token) -> Option<&T> {
    entries
        .binary_search_by(|entry| key(entry).cmp(&token))
        .ok()
        .map(|index| &entries[index])
}

/// One method definition.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Method {
    /// The `MethodDef` token.
    pub token: Token,
    /// The `TypeDef` token of the type that declares the method.
    pub owner: Token,
    /// The managed name: the full name of the type, `::`, and the method
    /// name, for example `System.Text.StringBuilder::Append`.
    pub name: String,
    /// The `MethodAttributes` flags.
    pub flags: u16,
    /// The `MethodImplAttributes` flags.
    pub impl_flags: u16,
    /// The method signature.
    pub signature: MethodSig,
    /// The body of a method with Common Intermediate Language code, or
    /// `None` for a method without such a body (abstract, runtime, internal
    /// call, platform invoke or native code).
    pub body: Option<MethodBody>,
}

/// The body of one method with Common Intermediate Language code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MethodBody {
    /// The RVA of the method header.
    pub header_rva: u32,
    /// The RVA of the first instruction.
    pub code_rva: u32,
    /// The length of the code in bytes.
    pub code_size: u32,
    /// The maximum number of items on the evaluation stack.
    pub max_stack: u16,
    /// Whether the runtime sets each local variable to zero at entry.
    pub init_locals: bool,
    /// The `StandAloneSig` token of the local variables, or the null token.
    pub local_signature: Token,
    /// The types of the local variables. The list is empty when the method
    /// has no local variables.
    pub locals: Vec<TypeSig>,
    /// The exception handling clauses, in the order of the body. The ranges
    /// are byte offsets from the first instruction.
    pub clauses: Vec<ExceptionClause>,
}

/// One method reference: a `MemberRef` that names a method, or a
/// `MethodSpec`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MethodReference {
    /// The `MemberRef` or `MethodSpec` token.
    pub token: Token,
    /// The parent of the method: a `TypeDef`, `TypeRef`, `TypeSpec`,
    /// `ModuleRef` or `MethodDef` token.
    pub owner: Token,
    /// The managed name: the full name of the parent type, `::`, and the
    /// method name.
    pub name: String,
    /// The signature at the call site. A `vararg` call holds its extra
    /// arguments after the sentinel.
    pub signature: MethodSig,
    /// The `MethodDef` token of the definition when this module defines the
    /// method.
    pub definition: Option<Token>,
    /// The type arguments of a `MethodSpec`. The list is empty for a
    /// `MemberRef`.
    pub instantiation: Vec<TypeSig>,
}

/// One field: a `Field` definition or a `MemberRef` that names a field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Field {
    /// The `Field` or `MemberRef` token.
    pub token: Token,
    /// The type that holds the field: a `TypeDef`, `TypeRef` or `TypeSpec`
    /// token.
    pub owner: Token,
    /// The managed name: the full name of the type, `::`, and the field
    /// name.
    pub name: String,
    /// The field signature.
    pub signature: FieldSig,
    /// Whether the field is static. A `MemberRef` does not state it, so the
    /// value is `false` for a field of another module.
    pub is_static: bool,
}

/// One type: a `TypeDef`, `TypeRef` or `TypeSpec`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Type {
    /// The `TypeDef`, `TypeRef` or `TypeSpec` token.
    pub token: Token,
    /// The managed full name: the namespace, `.`, and the name, with `/`
    /// before the name of a nested type.
    pub name: String,
    /// The kind of type and its kind-specific data.
    pub kind: TypeKind,
}

/// The kind of a [`Type`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TypeKind {
    /// A type definition of this module.
    Definition {
        /// The `TypeAttributes` flags.
        flags: u32,
        /// The base type, or the null token.
        extends: Token,
        /// The number of generic parameters.
        generic_param_count: u32,
    },
    /// A reference to a type of another scope.
    Reference,
    /// A type specification with its signature.
    Specification(TypeSig),
}

/// The signature of one `StandAloneSig` row.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StandAloneSignature {
    /// The `StandAloneSig` token.
    pub token: Token,
    /// The signature.
    pub signature: StandAloneKind,
}

/// The kind of a stand-alone signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StandAloneKind {
    /// A method signature, which `calli` names.
    Method(MethodSig),
    /// The local variables of a method body.
    Locals(LocalSig),
    /// A field signature. Compilers write it for debug data only.
    Field(FieldSig),
}

/// One user string of the `#US` heap.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserString {
    /// The `ldstr` token: `0x70` and the heap offset.
    pub token: Token,
    /// The UTF-16 code units of the string, exactly as the heap holds them.
    /// A string literal can hold an unpaired surrogate, so the units are not
    /// always valid UTF-16.
    pub code_units: Vec<u16>,
}

impl UserString {
    /// Decodes the string. An unpaired surrogate becomes U+FFFD.
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(&self.code_units)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{MethodTable, UserString};
    use crate::token::{TableId, Token};

    #[test]
    fn a_lookup_finds_an_entry_by_its_token() {
        let table = MethodTable {
            strings: vec![
                UserString {
                    token: Token::user_string(1),
                    code_units: "first".encode_utf16().collect(),
                },
                UserString {
                    token: Token::user_string(13),
                    code_units: vec![0x0073, 0xD800],
                },
            ],
            ..MethodTable::default()
        };

        assert_eq!(
            table
                .string(Token::user_string(1))
                .map(UserString::to_string_lossy)
                .as_deref(),
            Some("first")
        );
        assert_eq!(
            table
                .string(Token::user_string(13))
                .map(UserString::to_string_lossy)
                .as_deref(),
            Some("s\u{FFFD}"),
            "an unpaired surrogate stays in the units and decodes to U+FFFD"
        );
        assert_eq!(table.string(Token::user_string(2)), None);
        assert_eq!(table.method(Token::new(TableId::MethodDef, 1)), None);
    }
}
