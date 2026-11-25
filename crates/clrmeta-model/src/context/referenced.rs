//! The types of other assemblies that a module names, as rows without
//! tokens.
//!
//! The metadata of a module names a type of another assembly only by a
//! `TypeRef`: its scope and its name. It does not state the base type, the
//! interfaces or the kind of such a type. A loader that finds the assembly
//! that defines the type reads these facts there and states them as a
//! [`ReferencedType`]. A token of that assembly has no meaning in the
//! module, so each type of such a row is a [`NamedSig`]: a signature that
//! names each type by its full name.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::signature::{ArrayShape, TypeSig};
use crate::token::Token;

/// One type of another assembly, with the rows of its hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReferencedType {
    /// The full name in the form of metadata: the namespace, `.`, and the
    /// name with its arity suffix (``System.Collections.Generic.IEnumerable`1``),
    /// with `/` before the name of a nested type. A `TypeRef` of the module
    /// that resolves to the type has the same name
    /// ([`Type::name`](super::Type::name)).
    pub name: String,
    /// The simple name of the assembly that defines the type, after each
    /// forwarder (`ExportedType`).
    pub assembly: String,
    /// The `TypeAttributes` flags.
    pub flags: u32,
    /// The base type, or `None` for an interface and for `System.Object`.
    pub extends: Option<NamedSig>,
    /// The interfaces that the type implements (`InterfaceImpl`), in table
    /// order.
    pub interfaces: Vec<NamedSig>,
    /// The generic parameters of a generic type, in the order of their
    /// numbers.
    pub generic_parameters: Vec<ReferencedParameter>,
    /// The type of the `value__` field of an enumeration, or `None` for
    /// another type.
    pub underlying: Option<NamedSig>,
    /// The virtual methods that the type defines, in table order: the
    /// facts of the slots that a type of the module can override or that a
    /// virtual call can reach (ECMA-335 Partition II, 10.3).
    pub virtual_methods: Vec<ReferencedMethod>,
}

/// One virtual method of a [`ReferencedType`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReferencedMethod {
    /// The name of the method, without the name of its type.
    pub name: String,
    /// The `MethodAttributes` flags.
    pub flags: u16,
    /// The signature.
    pub signature: NamedMethodSig,
}

/// A method signature of another assembly, with each type named by its
/// full name in place of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NamedMethodSig {
    /// The first byte: the calling convention kind and its flags.
    pub calling_convention: u8,
    /// The number of generic parameters.
    pub generic_param_count: u32,
    /// The return type.
    pub return_type: NamedSig,
    /// The parameters.
    pub params: Vec<NamedSig>,
}

/// One generic parameter of a [`ReferencedType`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReferencedParameter {
    /// The name of the parameter.
    pub name: String,
    /// The `GenericParamAttributes` flags.
    pub flags: u16,
    /// The types that constrain the parameter, in table order.
    pub constraints: Vec<NamedSig>,
}

/// A type of a signature of another assembly, with each type named by its
/// full name in place of a token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NamedSig {
    /// A type that names no type definition: a built-in element type, such
    /// as `int32`, `string` or `object`, or a generic parameter (`Var`,
    /// `MVar`). The signature holds no token.
    Element(TypeSig),
    /// A class or a value type, with its type arguments for an
    /// instantiation of a generic type.
    Named {
        /// The full name in the form of metadata
        /// ([`ReferencedType::name`]).
        name: String,
        /// `true` when the signature names a value type.
        value_type: bool,
        /// The type arguments. The list is empty for a type that is not an
        /// instantiation.
        arguments: Vec<NamedSig>,
    },
    /// An unmanaged pointer.
    Ptr(Box<NamedSig>),
    /// A managed pointer.
    ByRef(Box<NamedSig>),
    /// A single-dimension array with a lower bound of zero.
    SzArray(Box<NamedSig>),
    /// An array with a shape.
    Array(Box<NamedSig>, ArrayShape),
    /// A function pointer. The row does not state its signature.
    FnPtr,
}

/// One assembly that the module references and that the loader did not
/// find.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnresolvedAssembly {
    /// The `AssemblyRef` token.
    pub token: Token,
    /// The simple name of the assembly.
    pub name: String,
    /// The major, minor, build and revision numbers of the version.
    pub version: [u16; 4],
}
