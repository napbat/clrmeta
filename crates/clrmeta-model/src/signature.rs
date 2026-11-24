//! Owned signatures (ECMA-335 II.23.2).

use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::token::Token;

/// The `ELEMENT_TYPE_*` constants (II.23.1.16).
pub mod element_type {
    /// Marks the end of a list.
    pub const END: u8 = 0x00;
    /// `void`.
    pub const VOID: u8 = 0x01;
    /// `bool`.
    pub const BOOLEAN: u8 = 0x02;
    /// `char`.
    pub const CHAR: u8 = 0x03;
    /// `int8`.
    pub const I1: u8 = 0x04;
    /// `unsigned int8`.
    pub const U1: u8 = 0x05;
    /// `int16`.
    pub const I2: u8 = 0x06;
    /// `unsigned int16`.
    pub const U2: u8 = 0x07;
    /// `int32`.
    pub const I4: u8 = 0x08;
    /// `unsigned int32`.
    pub const U4: u8 = 0x09;
    /// `int64`.
    pub const I8: u8 = 0x0A;
    /// `unsigned int64`.
    pub const U8: u8 = 0x0B;
    /// `float32`.
    pub const R4: u8 = 0x0C;
    /// `float64`.
    pub const R8: u8 = 0x0D;
    /// `string`.
    pub const STRING: u8 = 0x0E;
    /// An unmanaged pointer, followed by a type.
    pub const PTR: u8 = 0x0F;
    /// A managed pointer, followed by a type.
    pub const BYREF: u8 = 0x10;
    /// A value type, followed by a `TypeDefOrRefOrSpecEncoded` token.
    pub const VALUETYPE: u8 = 0x11;
    /// A reference type, followed by a `TypeDefOrRefOrSpecEncoded` token.
    pub const CLASS: u8 = 0x12;
    /// A generic parameter of a type, followed by its number.
    pub const VAR: u8 = 0x13;
    /// An array with a shape.
    pub const ARRAY: u8 = 0x14;
    /// A generic instantiation.
    pub const GENERICINST: u8 = 0x15;
    /// `typedref`.
    pub const TYPEDBYREF: u8 = 0x16;
    /// `native int`.
    pub const I: u8 = 0x18;
    /// `native unsigned int`.
    pub const U: u8 = 0x19;
    /// A function pointer, followed by a method signature.
    pub const FNPTR: u8 = 0x1B;
    /// `object`.
    pub const OBJECT: u8 = 0x1C;
    /// A single-dimension array with a lower bound of zero.
    pub const SZARRAY: u8 = 0x1D;
    /// A generic parameter of a method, followed by its number.
    pub const MVAR: u8 = 0x1E;
    /// A required custom modifier, followed by a token.
    pub const CMOD_REQD: u8 = 0x1F;
    /// An optional custom modifier, followed by a token.
    pub const CMOD_OPT: u8 = 0x20;
    /// A type of the runtime; not in metadata files.
    pub const INTERNAL: u8 = 0x21;
    /// Bit that marks a modifier.
    pub const MODIFIER: u8 = 0x40;
    /// The start of the vararg arguments of a call site.
    pub const SENTINEL: u8 = 0x41;
    /// A pinned local variable.
    pub const PINNED: u8 = 0x45;
    /// `System.Type` in a custom attribute value.
    pub const SYSTEM_TYPE: u8 = 0x50;
    /// A boxed value in a custom attribute value.
    pub const BOXED: u8 = 0x51;
    /// Reserved.
    pub const RESERVED: u8 = 0x52;
    /// A field of a custom attribute named argument.
    pub const FIELD: u8 = 0x53;
    /// A property of a custom attribute named argument.
    pub const PROPERTY: u8 = 0x54;
    /// An enum in a custom attribute value.
    pub const ENUM: u8 = 0x55;
}

/// The calling convention constants of the first byte of a signature
/// (II.23.2.1 to II.23.2.6, II.15.3).
pub mod calling_convention {
    /// The managed calling convention.
    pub const DEFAULT: u8 = 0x00;
    /// The unmanaged C convention.
    pub const C: u8 = 0x01;
    /// The unmanaged `stdcall` convention.
    pub const STDCALL: u8 = 0x02;
    /// The unmanaged `thiscall` convention.
    pub const THISCALL: u8 = 0x03;
    /// The unmanaged `fastcall` convention.
    pub const FASTCALL: u8 = 0x04;
    /// The managed convention with a variable argument list.
    pub const VARARG: u8 = 0x05;
    /// A field signature.
    pub const FIELD: u8 = 0x06;
    /// A local variable signature.
    pub const LOCAL_SIG: u8 = 0x07;
    /// A property signature.
    pub const PROPERTY: u8 = 0x08;
    /// An unmanaged convention that modifiers name (function pointers).
    pub const UNMANAGED: u8 = 0x09;
    /// A generic method instantiation.
    pub const GENERICINST: u8 = 0x0A;
    /// The unmanaged convention with a variable argument list.
    pub const NATIVE_VARARG: u8 = 0x0B;
    /// The mask of the kind in the low 4 bits.
    pub const KIND_MASK: u8 = 0x0F;
    /// The method has generic parameters.
    pub const GENERIC: u8 = 0x10;
    /// The method has a `this` argument.
    pub const HAS_THIS: u8 = 0x20;
    /// The `this` argument is the first parameter of the signature.
    pub const EXPLICIT_THIS: u8 = 0x40;
}

/// A type in a signature (II.23.2.12). Custom modifiers and the `pinned`
/// constraint wrap the type that follows them, in the order of the blob.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TypeSig {
    /// `void` (return types and pointers only).
    Void,
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
    /// `object`.
    Object,
    /// `typedref`.
    TypedByRef,
    /// `native int`.
    I,
    /// `native unsigned int`.
    U,
    /// A reference type: a `TypeDef`, `TypeRef` or `TypeSpec` token.
    Class(Token),
    /// A value type: a `TypeDef`, `TypeRef` or `TypeSpec` token.
    ValueType(Token),
    /// An unmanaged pointer.
    Ptr(Box<TypeSig>),
    /// A managed pointer.
    ByRef(Box<TypeSig>),
    /// A single-dimension array with a lower bound of zero.
    SzArray(Box<TypeSig>),
    /// An array with a shape.
    Array(Box<TypeSig>, ArrayShape),
    /// A generic instantiation.
    GenericInst {
        /// `true` for `valuetype`, `false` for `class`.
        value_type: bool,
        /// The generic type: a `TypeDef` or `TypeRef` token.
        generic: Token,
        /// The type arguments.
        arguments: Vec<TypeSig>,
    },
    /// A generic parameter of the enclosing type.
    Var(u32),
    /// A generic parameter of the enclosing method.
    MVar(u32),
    /// A function pointer.
    FnPtr(Box<MethodSig>),
    /// A type with a custom modifier.
    Modified {
        /// `true` for `modreq`, `false` for `modopt`.
        required: bool,
        /// The modifier type: a `TypeDef`, `TypeRef` or `TypeSpec` token.
        modifier: Token,
        /// The modified type.
        inner: Box<TypeSig>,
    },
    /// A pinned local variable.
    Pinned(Box<TypeSig>),
}

impl TypeSig {
    /// Returns the type without its custom modifiers and `pinned` constraint.
    #[must_use]
    pub fn unmodified(&self) -> &Self {
        let mut ty = self;
        while let Self::Modified { inner, .. } | Self::Pinned(inner) = ty {
            ty = inner;
        }
        ty
    }

    /// Returns the element type constant of a type without operands, or
    /// `None` for a type with operands.
    #[must_use]
    pub const fn primitive_element_type(&self) -> Option<u8> {
        use element_type as e;
        Some(match self {
            Self::Void => e::VOID,
            Self::Boolean => e::BOOLEAN,
            Self::Char => e::CHAR,
            Self::I1 => e::I1,
            Self::U1 => e::U1,
            Self::I2 => e::I2,
            Self::U2 => e::U2,
            Self::I4 => e::I4,
            Self::U4 => e::U4,
            Self::I8 => e::I8,
            Self::U8 => e::U8,
            Self::R4 => e::R4,
            Self::R8 => e::R8,
            Self::String => e::STRING,
            Self::Object => e::OBJECT,
            Self::TypedByRef => e::TYPEDBYREF,
            Self::I => e::I,
            Self::U => e::U,
            _ => return None,
        })
    }

    /// Returns the type without operands of an element type constant.
    #[must_use]
    pub const fn from_primitive_element_type(value: u8) -> Option<Self> {
        use element_type as e;
        Some(match value {
            e::VOID => Self::Void,
            e::BOOLEAN => Self::Boolean,
            e::CHAR => Self::Char,
            e::I1 => Self::I1,
            e::U1 => Self::U1,
            e::I2 => Self::I2,
            e::U2 => Self::U2,
            e::I4 => Self::I4,
            e::U4 => Self::U4,
            e::I8 => Self::I8,
            e::U8 => Self::U8,
            e::R4 => Self::R4,
            e::R8 => Self::R8,
            e::STRING => Self::String,
            e::OBJECT => Self::Object,
            e::TYPEDBYREF => Self::TypedByRef,
            e::I => Self::I,
            e::U => Self::U,
            _ => return None,
        })
    }
}

/// The shape of an array (II.23.2.13).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArrayShape {
    /// The number of dimensions.
    pub rank: u32,
    /// The sizes of the first dimensions.
    pub sizes: Vec<u32>,
    /// The lower bounds of the first dimensions.
    pub lower_bounds: Vec<i32>,
}

/// A method signature: `MethodDefSig`, `MethodRefSig` or
/// `StandAloneMethodSig` (II.23.2.1 to II.23.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MethodSig {
    /// The first byte: the calling convention kind and the
    /// [`calling_convention`] flags.
    pub calling_convention: u8,
    /// The number of generic parameters (zero without
    /// [`calling_convention::GENERIC`]).
    pub generic_param_count: u32,
    /// The return type.
    pub return_type: TypeSig,
    /// The parameters, the vararg arguments of a call site included.
    pub params: Vec<TypeSig>,
    /// The position in `params` of the first vararg argument of a call site:
    /// the place of the `SENTINEL`.
    pub sentinel: Option<usize>,
}

impl MethodSig {
    /// Returns the calling convention kind (the low 4 bits).
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.calling_convention & calling_convention::KIND_MASK
    }

    /// Returns `true` when the method has a `this` argument.
    #[must_use]
    pub const fn has_this(&self) -> bool {
        self.calling_convention & calling_convention::HAS_THIS != 0
    }

    /// Returns `true` when the `this` argument is the first parameter.
    #[must_use]
    pub const fn explicit_this(&self) -> bool {
        self.calling_convention & calling_convention::EXPLICIT_THIS != 0
    }

    /// Returns `true` when the method has generic parameters.
    #[must_use]
    pub const fn is_generic(&self) -> bool {
        self.calling_convention & calling_convention::GENERIC != 0
    }

    /// Returns `true` for a managed or native vararg signature.
    #[must_use]
    pub const fn is_vararg(&self) -> bool {
        matches!(
            self.kind(),
            calling_convention::VARARG | calling_convention::NATIVE_VARARG
        )
    }

    /// Returns the fixed parameters: the parameters before the sentinel.
    #[must_use]
    pub fn fixed_params(&self) -> &[TypeSig] {
        &self.params[..self.sentinel.unwrap_or(self.params.len())]
    }

    /// Returns the number of arguments that a call pops from the stack:
    /// the parameters and the `this` argument when it is not explicit.
    #[must_use]
    pub fn stack_argument_count(&self) -> usize {
        self.params.len() + usize::from(self.has_this() && !self.explicit_this())
    }
}

/// A field signature (II.23.2.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FieldSig {
    /// The type of the field, with its custom modifiers.
    pub field_type: TypeSig,
}

/// A property signature (II.23.2.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PropertySig {
    /// The first byte: [`calling_convention::PROPERTY`] and optionally
    /// [`calling_convention::HAS_THIS`].
    pub calling_convention: u8,
    /// The type of the property, with its custom modifiers.
    pub property_type: TypeSig,
    /// The parameters of an indexed property.
    pub params: Vec<TypeSig>,
}

impl PropertySig {
    /// Returns `true` for an instance property.
    #[must_use]
    pub const fn has_this(&self) -> bool {
        self.calling_convention & calling_convention::HAS_THIS != 0
    }
}

/// A local variable signature (II.23.2.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LocalSig {
    /// The types of the local variables, in slot order.
    pub locals: Vec<TypeSig>,
}

/// The instantiation of a generic method (II.23.2.15).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MethodSpecSig {
    /// The type arguments.
    pub arguments: Vec<TypeSig>,
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;

    #[test]
    fn the_primitive_element_types_map_both_ways() {
        for value in 0..=0xFF {
            if let Some(ty) = TypeSig::from_primitive_element_type(value) {
                assert_eq!(ty.primitive_element_type(), Some(value));
            }
        }
        assert_eq!(
            TypeSig::Class(Token(0x0100_0001)).primitive_element_type(),
            None
        );
    }

    #[test]
    fn a_method_signature_counts_its_stack_arguments() {
        let sig = MethodSig {
            calling_convention: calling_convention::HAS_THIS | calling_convention::VARARG,
            generic_param_count: 0,
            return_type: TypeSig::Void,
            params: vec![TypeSig::I4, TypeSig::String],
            sentinel: Some(1),
        };
        assert!(sig.has_this() && sig.is_vararg() && !sig.is_generic());
        assert_eq!(sig.fixed_params(), &[TypeSig::I4]);
        assert_eq!(sig.stack_argument_count(), 3);
        let pinned = TypeSig::Pinned(Box::new(TypeSig::Modified {
            required: false,
            modifier: Token(0x0100_0002),
            inner: Box::new(TypeSig::I),
        }));
        assert_eq!(pinned.unmodified(), &TypeSig::I);
    }
}
