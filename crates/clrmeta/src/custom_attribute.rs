//! Custom attribute values (ECMA-335 II.23.3).
//!
//! The value blob holds no types for the fixed arguments: the types come
//! from the signature of the constructor. An enum argument stores only its
//! underlying value, so the reader asks an [`EnumResolver`] for the
//! underlying type of each enum. [`MetadataResolver`] answers from an
//! [`EnumIndex`] of the type definitions of one or more modules.

use alloc::boxed::Box;
use alloc::vec::Vec;

use clrmeta_model::{MethodSig, Token};

use crate::error::Result;

mod decode;
mod encode;
mod resolver;

pub use resolver::{EnumIndex, MetadataResolver};

/// The prolog of a value blob.
pub const PROLOG: u16 = 0x0001;

/// Answers the questions of the reader about the types of arguments.
pub trait EnumResolver {
    /// Returns the underlying element type (`ELEMENT_TYPE_I4`, …) of the
    /// enum of a `TypeDef` or `TypeRef` token, or `None` when the type is
    /// not a known enum.
    fn underlying_type_of_token(&self, token: Token) -> Option<u8>;

    /// Returns the underlying element type of an enum named by a
    /// serialized type name (`Namespace.Type+Nested, Assembly, …`), or
    /// `None` when the name is not a known enum.
    fn underlying_type_of_name(&self, name: &str) -> Option<u8>;

    /// Returns `true` when a `TypeDef` or `TypeRef` token is `System.Type`,
    /// whose values are serialized type names.
    fn is_system_type(&self, token: Token) -> bool;
}

/// The enum type of an argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EnumType<'a> {
    /// A fixed argument: the type token of the constructor signature.
    Token(Token),
    /// A named or boxed argument: the serialized type name.
    Name(&'a str),
}

/// The type of an argument (the `FieldOrPropType` of II.23.3 and the types
/// of constructor parameters that a value blob can hold).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArgumentType<'a> {
    /// `bool`.
    Boolean,
    /// `char`.
    Char,
    /// `int8`.
    I1,
    /// `unsigned int8`.
    U1,
    /// `int16`.
    I2,
    /// `unsigned int16`.
    U2,
    /// `int32`.
    I4,
    /// `unsigned int32`.
    U4,
    /// `int64`.
    I8,
    /// `unsigned int64`.
    U8,
    /// `float32`.
    R4,
    /// `float64`.
    R8,
    /// `string`.
    String,
    /// `System.Type`, serialized as a type name.
    Type,
    /// `object`: a boxed value that states its own type.
    Object,
    /// An enum and its underlying element type.
    Enum {
        /// The enum type.
        ty: EnumType<'a>,
        /// The underlying element type.
        underlying: u8,
    },
    /// A single-dimension array.
    SzArray(Box<ArgumentType<'a>>),
}

/// A value of an argument.
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    /// A `bool`.
    Boolean(bool),
    /// A `char`.
    Char(u16),
    /// An `int8`.
    I1(i8),
    /// An `unsigned int8`.
    U1(u8),
    /// An `int16`.
    I2(i16),
    /// An `unsigned int16`.
    U2(u16),
    /// An `int32`.
    I4(i32),
    /// An `unsigned int32`.
    U4(u32),
    /// An `int64`.
    I8(i64),
    /// An `unsigned int64`.
    U8(u64),
    /// A `float32`.
    R4(f32),
    /// A `float64`.
    R8(f64),
    /// A string, or `None` for a null string.
    String(Option<&'a str>),
    /// A type name, or `None` for a null type.
    Type(Option<&'a str>),
    /// A boxed value of an `object` argument with its type.
    Boxed(Box<Argument<'a>>),
    /// The elements of an array, or `None` for a null array.
    Array(Option<Vec<Value<'a>>>),
}

/// An argument: its type and its value. The value of an enum is the value
/// of its underlying type.
#[derive(Debug, Clone, PartialEq)]
pub struct Argument<'a> {
    /// The type.
    pub ty: ArgumentType<'a>,
    /// The value.
    pub value: Value<'a>,
}

/// The target of a named argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamedTarget {
    /// A field (`0x53`).
    Field,
    /// A property (`0x54`).
    Property,
}

/// A named argument: a field or a property that the attribute sets.
#[derive(Debug, Clone, PartialEq)]
pub struct NamedArgument<'a> {
    /// A field or a property.
    pub target: NamedTarget,
    /// The name of the field or the property.
    pub name: &'a str,
    /// The type and the value.
    pub argument: Argument<'a>,
}

/// A custom attribute value blob.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomAttributeValue<'a> {
    /// The constructor arguments, one for each parameter.
    pub fixed: Vec<Argument<'a>>,
    /// The named arguments.
    pub named: Vec<NamedArgument<'a>>,
}

impl<'a> CustomAttributeValue<'a> {
    /// Parses a value blob with the signature of its constructor.
    ///
    /// # Errors
    ///
    /// Returns an error when the blob is not valid, a parameter type cannot
    /// hold an attribute argument, or the resolver does not know an enum
    /// ([`Error::UnresolvedEnum`](crate::Error::UnresolvedEnum)).
    pub fn parse(
        blob: &'a [u8],
        constructor: &MethodSig,
        resolver: &dyn EnumResolver,
    ) -> Result<Self> {
        decode::parse(blob, constructor, resolver)
    }

    /// Parses the named arguments of a security attribute (II.23.3, as
    /// [`security`](crate::security) uses them): a compressed count and the
    /// arguments.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`CustomAttributeValue::parse`].
    pub fn parse_named(
        blob: &'a [u8],
        resolver: &dyn EnumResolver,
    ) -> Result<Vec<NamedArgument<'a>>> {
        decode::parse_named(blob, resolver)
    }

    /// Encodes the value blob.
    ///
    /// # Errors
    ///
    /// Returns an error when a value does not match its type or a count
    /// does not fit its field.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode::encode(self)
    }

    /// Encodes named arguments with a compressed count, as
    /// [`CustomAttributeValue::parse_named`] reads them.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`CustomAttributeValue::encode`].
    pub fn encode_named(named: &[NamedArgument<'_>]) -> Result<Vec<u8>> {
        encode::encode_named(named)
    }
}

#[cfg(test)]
mod tests;
