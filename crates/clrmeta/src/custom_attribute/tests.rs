use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use clrmeta_model::{MethodSig, TableId, Token, TypeSig, calling_convention, element_type as et};

use super::*;
use crate::error::Error;

struct Fake;

const ENUM_TOKEN: Token = Token::new(TableId::TypeRef, 1);
const TYPE_TOKEN: Token = Token::new(TableId::TypeRef, 2);

impl EnumResolver for Fake {
    fn underlying_type_of_token(&self, token: Token) -> Option<u8> {
        (token == ENUM_TOKEN).then_some(et::I4)
    }

    fn underlying_type_of_name(&self, name: &str) -> Option<u8> {
        (name == "E, A").then_some(et::U1)
    }

    fn is_system_type(&self, token: Token) -> bool {
        token == TYPE_TOKEN
    }
}

fn constructor(params: Vec<TypeSig>) -> MethodSig {
    MethodSig {
        calling_convention: calling_convention::HAS_THIS,
        generic_param_count: 0,
        return_type: TypeSig::Void,
        params,
        sentinel: None,
    }
}

#[test]
fn fixed_arguments_of_every_kind_read_and_write() {
    let ctor = constructor(vec![
        TypeSig::Boolean,
        TypeSig::String,
        TypeSig::String,
        TypeSig::ValueType(ENUM_TOKEN),
        TypeSig::Class(TYPE_TOKEN),
        TypeSig::Object,
        TypeSig::SzArray(Box::new(TypeSig::I2)),
        TypeSig::SzArray(Box::new(TypeSig::R8)),
        TypeSig::Char,
    ]);
    let mut blob = vec![0x01, 0x00, 0x01, 0x02, b'h', b'i', 0xFF, 0x07, 0, 0, 0];
    blob.extend_from_slice(&[0x03, b'S', b'.', b'T']);
    blob.extend_from_slice(&[0x08, 0xFE, 0xFF, 0xFF, 0xFF]);
    blob.extend_from_slice(&[0x02, 0, 0, 0, 0x05, 0, 0xFA, 0xFF]);
    blob.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    blob.extend_from_slice(&[0x41, 0x00, 0x00, 0x00]);
    let value = CustomAttributeValue::parse(&blob, &ctor, &Fake).unwrap();
    let values: Vec<_> = value.fixed.iter().map(|a| a.value.clone()).collect();
    assert_eq!(
        values,
        [
            Value::Boolean(true),
            Value::String(Some("hi")),
            Value::String(None),
            Value::I4(7),
            Value::Type(Some("S.T")),
            Value::Boxed(Box::new(Argument {
                ty: ArgumentType::I4,
                value: Value::I4(-2)
            })),
            Value::Array(Some(vec![Value::I2(5), Value::I2(-6)])),
            Value::Array(None),
            Value::Char(0x41),
        ]
    );
    assert_eq!(
        value.fixed[3].ty,
        ArgumentType::Enum {
            ty: EnumType::Token(ENUM_TOKEN),
            underlying: et::I4
        }
    );
    assert_eq!(value.named, Vec::new());
    assert_eq!(value.encode().unwrap(), blob);
}

#[test]
fn named_arguments_read_their_types_and_names() {
    let ctor = constructor(Vec::new());
    let mut blob = vec![0x01, 0x00, 0x02, 0x00];
    // FIELD enum "E, A" "F" = 3
    blob.extend_from_slice(&[0x53, 0x55, 0x04, b'E', b',', b' ', b'A', 0x01, b'F', 0x03]);
    // PROPERTY string[] "P" = { "x" }
    blob.extend_from_slice(&[0x54, 0x1D, 0x0E, 0x01, b'P', 1, 0, 0, 0, 0x01, b'x']);
    let value = CustomAttributeValue::parse(&blob, &ctor, &Fake).unwrap();
    assert_eq!(value.named.len(), 2);
    assert_eq!(value.named[0].target, NamedTarget::Field);
    assert_eq!(value.named[0].name, "F");
    assert_eq!(value.named[0].argument.value, Value::U1(3));
    assert_eq!(value.named[1].target, NamedTarget::Property);
    assert_eq!(
        value.named[1].argument.value,
        Value::Array(Some(vec![Value::String(Some("x"))]))
    );
    assert_eq!(value.encode().unwrap(), blob);

    let compressed = CustomAttributeValue::encode_named(&value.named).unwrap();
    assert_eq!(compressed[0], 2);
    assert_eq!(&compressed[1..], &blob[4..]);
    let named = CustomAttributeValue::parse_named(&compressed, &Fake).unwrap();
    assert_eq!(named, value.named);
}

#[test]
fn malformed_values_and_unknown_enums_are_errors() {
    let ctor = constructor(vec![TypeSig::I4]);
    assert!(CustomAttributeValue::parse(&[0x02, 0x00], &ctor, &Fake).is_err());
    assert!(matches!(
        CustomAttributeValue::parse(&[0x01, 0x00, 0x01], &ctor, &Fake),
        Err(Error::Truncated { .. })
    ));
    let unknown = constructor(vec![TypeSig::ValueType(Token::new(TableId::TypeRef, 9))]);
    assert_eq!(
        CustomAttributeValue::parse(&[0x01, 0x00, 0, 0, 0, 0, 0, 0], &unknown, &Fake),
        Err(Error::UnresolvedEnum { offset: 2 })
    );
    // Trailing bytes after the named arguments.
    let empty = constructor(Vec::new());
    assert!(CustomAttributeValue::parse(&[0x01, 0x00, 0x00, 0x00, 0x00], &empty, &Fake).is_err());
    // A pointer parameter cannot hold an argument.
    let pointer = constructor(vec![TypeSig::Ptr(Box::new(TypeSig::I4))]);
    assert!(CustomAttributeValue::parse(&[0x01, 0x00, 0, 0, 0, 0], &pointer, &Fake).is_err());
}
