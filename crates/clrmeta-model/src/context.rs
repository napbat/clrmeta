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
//! finds an entry with a binary search on its token. The types of other
//! assemblies ([`MethodTable::referenced_types`]) are in ascending name
//! order. A relative virtual address (RVA) is an offset from the load base
//! of the module: the consumer adds the base.

mod referenced;

pub use referenced::{
    NamedMethodSig, NamedSig, ReferencedField, ReferencedMethod, ReferencedParameter,
    ReferencedType, UnresolvedAssembly,
};

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::body::ExceptionClause;
use crate::signature::{FieldSig, LocalSig, MethodSig, TypeSig};
use crate::token::Token;

/// The identifier of the method-context encoding: a [`MethodTable`] in the
/// `postcard` format, version 4.
///
/// A change of a type of this module that changes the encoded bytes, or the
/// meaning of a field, needs a new version number.
pub const ENCODING: &str = "cil.methods/4";

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
    /// The types of other assemblies that the loader found: each type that
    /// a `TypeRef` of the module names, and each base type and interface
    /// of such a type, also of each base type and interface of those. The
    /// list is in ascending order of the name, with one entry for each
    /// name. A `TypeRef` whose type the list does not hold names a type of
    /// an assembly that the loader did not find or did not search.
    pub referenced_types: Vec<ReferencedType>,
    /// Each assembly that the module references and that the loader did not
    /// find, in token order.
    pub unresolved_assemblies: Vec<UnresolvedAssembly>,
    /// The simple name of the assembly that the module belongs to, as the
    /// first `Assembly` row states it, or empty for a module without one.
    /// A runtime that runs the code of several assemblies tells their types
    /// apart by it.
    pub assembly: String,
    /// The relative virtual address (RVA) of the initial data of each field
    /// definition that the `FieldRVA` table names, by field token, in token
    /// order: the bytes of a static field such as the initial data of an
    /// array (`RuntimeHelpers.InitializeArray`).
    pub field_rvas: Vec<(Token, u32)>,
}

impl MethodTable {
    /// Returns the method definition of `token`.
    #[must_use]
    pub fn method(&self, token: Token) -> Option<&Method> {
        find(&self.methods, token, |method| method.token)
    }

    /// Returns the RVA of the initial data of the field definition `token`,
    /// when the `FieldRVA` table names it.
    #[must_use]
    pub fn field_rva(&self, token: Token) -> Option<u32> {
        self.field_rvas
            .binary_search_by_key(&token.0, |(field, _)| field.0)
            .ok()
            .map(|position| self.field_rvas[position].1)
    }

    /// Returns the method reference of `token`.
    #[must_use]
    pub fn method_reference(&self, token: Token) -> Option<&MethodReference> {
        find(&self.method_references, token, |reference| reference.token)
    }

    /// Returns the method reference that the loader states at `address`
    /// ([`MethodReference::address`]), or `None` when no reference lies
    /// there.
    #[must_use]
    pub fn reference_at(&self, address: u64) -> Option<&MethodReference> {
        self.method_references
            .iter()
            .find(|reference| reference.address == Some(address))
    }

    /// Returns the method definition that the loader states at `address`
    /// ([`Method::address`]), or `None` when no method lies there.
    #[must_use]
    pub fn method_at(&self, address: u64) -> Option<&Method> {
        self.methods
            .iter()
            .find(|method| method.address == Some(address))
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

    /// Returns the type of another assembly of the full name `name`
    /// ([`ReferencedType::name`]).
    #[must_use]
    pub fn referenced_type(&self, name: &str) -> Option<&ReferencedType> {
        self.referenced_types
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .ok()
            .map(|index| &self.referenced_types[index])
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
    /// The generic parameters of a generic method, in the order of their
    /// numbers. The list is empty for a method that is not generic.
    pub generic_parameters: Vec<GenericParameter>,
    /// The body of a method with Common Intermediate Language code, or
    /// `None` for a method without such a body (abstract, runtime, internal
    /// call, platform invoke or native code).
    pub body: Option<MethodBody>,
    /// The address at which the loader of the module states a method
    /// without a CIL body that code can call: a platform invoke method is
    /// an import of its native function, and a method that the runtime
    /// implements (an internal call or a runtime method) is an import of the
    /// runtime. A call names its callee by that address. The metadata holds
    /// no such address, so a reader of the metadata states `None`, and the
    /// loader that states the imports fills it.
    pub address: Option<u64>,
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
    /// The address at which the loader of the module states the method that
    /// the reference calls, when no method definition of this module is
    /// that callee as it stands: the import of a method of another scope,
    /// or the instantiation of a generic method, or of a method of a generic
    /// type instance, that this module defines. A call names its callee by
    /// that address, so the instantiation stays known. The metadata holds
    /// no such address, so a reader of the metadata states `None`, and the
    /// loader that states the references fills it.
    pub address: Option<u64>,
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
    /// Whether the field is static. A `MemberRef` does not state it: a
    /// `MemberRef` of a type definition of the module, or of an
    /// instantiation of one, takes the flag of the `Field` definition of
    /// that type with the same name and signature. A `MemberRef` of a type
    /// of another assembly is `false` until the resolution of the
    /// references of the module finds the assembly that defines the type and
    /// takes the flag of the field with the same name and field type. A field that no
    /// resolution finds is `false`.
    pub is_static: bool,
    /// The offset in bytes that the `FieldLayout` table states for a `Field`
    /// definition, from the start of the fields of its type, or `None` when
    /// the table has no row for it and for a `MemberRef`. A type with
    /// explicit layout states an offset for each instance field.
    pub offset: Option<u32>,
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
        /// The interfaces that the type implements (`InterfaceImpl`), each
        /// a `TypeDef`, `TypeRef` or `TypeSpec` token, in table order.
        interfaces: Vec<Token>,
        /// The generic parameters of a generic type, in the order of their
        /// numbers. The list is empty for a type that is not generic.
        generic_parameters: Vec<GenericParameter>,
        /// The explicit method implementations of the type (`MethodImpl`),
        /// in table order.
        method_impls: Vec<MethodImpl>,
        /// The packing size and the class size that the `ClassLayout` table
        /// states for the type, or `None` when the table has no row for it.
        /// The layout kind (automatic, sequential or explicit) is in
        /// `flags`.
        layout: Option<ClassLayout>,
    },
    /// A reference to a type of another scope.
    Reference,
    /// A type specification with its signature.
    Specification(TypeSig),
}

/// One `ClassLayout` row (ECMA-335 Partition II, 22.8): the packing size
/// and the class size of a type with sequential or explicit layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ClassLayout {
    /// The packing size: the largest alignment of a field in bytes, or zero
    /// for the default alignment of each field.
    pub packing: u16,
    /// The size of an instance in bytes, or zero when the row does not
    /// state it. The size of an instance is at least this size.
    pub class_size: u32,
}

/// One explicit method implementation of a type definition (`MethodImpl`,
/// ECMA-335 Partition II, 22.27): the method of the type that implements a
/// virtual method of a base type or of an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MethodImpl {
    /// The method that implements the declaration: a `MethodDef` or a
    /// `MemberRef` token.
    pub body: Token,
    /// The virtual method that the body implements: a `MethodDef` or a
    /// `MemberRef` token.
    pub declaration: Token,
}

/// One generic parameter of a type or a method definition (`GenericParam`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GenericParameter {
    /// The name of the parameter.
    pub name: String,
    /// The `GenericParamAttributes` flags: the variance and the special
    /// constraints (reference type, value type, default constructor).
    pub flags: u16,
    /// The types that constrain the parameter (`GenericParamConstraint`),
    /// each a `TypeDef`, `TypeRef` or `TypeSpec` token, in table order. A
    /// type that the parameter must derive from and an interface that it
    /// must implement are both constraints.
    pub constraints: Vec<Token>,
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
    use alloc::borrow::ToOwned;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{MethodTable, NamedSig, ReferencedType, UserString};
    use crate::token::{TableId, Token};

    #[test]
    fn a_lookup_finds_a_referenced_type_by_its_name() {
        let row = |name: &str, extends: Option<&str>| ReferencedType {
            name: name.to_owned(),
            assembly: "System.Private.CoreLib".to_owned(),
            flags: 0,
            extends: extends.map(|base| NamedSig::Named {
                name: base.to_owned(),
                value_type: false,
                arguments: Vec::new(),
            }),
            interfaces: Vec::new(),
            generic_parameters: Vec::new(),
            underlying: None,
            virtual_methods: Vec::new(),
            fields: Vec::new(),
            layout: None,
        };
        let table = MethodTable {
            referenced_types: vec![
                row("System.Exception", Some("System.Object")),
                row("System.FormatException", Some("System.SystemException")),
                row("System.SystemException", Some("System.Exception")),
            ],
            ..MethodTable::default()
        };

        let found = table
            .referenced_type("System.FormatException")
            .expect("the row is in the list");
        assert_eq!(found.name, "System.FormatException");
        assert_eq!(table.referenced_type("System.ArgumentException"), None);
    }

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
