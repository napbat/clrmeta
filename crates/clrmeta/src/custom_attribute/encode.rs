//! The writer of custom attribute value blobs.

use alloc::vec::Vec;

use clrmeta_model::{TypeSig, element_type as et};

use crate::bytes::{put_compressed_u32, put_u16, put_u32};
use crate::custom_attribute::{
    ArgumentType, CustomAttributeValue, EnumType, NamedArgument, NamedTarget, PROLOG, Value,
};
use crate::error::{Error, Result};

const STRUCTURE: &str = "custom attribute value";

pub(crate) fn encode(value: &CustomAttributeValue<'_>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_u16(&mut out, PROLOG);
    for argument in &value.fixed {
        write_value(&mut out, &argument.ty, &argument.value)?;
    }
    let count = u16::try_from(value.named.len()).map_err(|_| overflow(value.named.len()))?;
    put_u16(&mut out, count);
    for named in &value.named {
        write_named(&mut out, named)?;
    }
    Ok(out)
}

pub(crate) fn encode_named(named: &[NamedArgument<'_>]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let count = u32::try_from(named.len()).map_err(|_| overflow(named.len()))?;
    put_compressed_u32(&mut out, count, STRUCTURE)?;
    for argument in named {
        write_named(&mut out, argument)?;
    }
    Ok(out)
}

fn overflow(value: usize) -> Error {
    Error::Overflow {
        structure: STRUCTURE,
        value: value as u64,
    }
}

fn mismatch() -> Error {
    Error::Malformed {
        structure: STRUCTURE,
        offset: 0,
        reason: "a value does not match its type",
    }
}

fn write_named(out: &mut Vec<u8>, named: &NamedArgument<'_>) -> Result<()> {
    out.push(match named.target {
        NamedTarget::Field => et::FIELD,
        NamedTarget::Property => et::PROPERTY,
    });
    write_type(out, &named.argument.ty)?;
    write_string(out, Some(named.name))?;
    write_value(out, &named.argument.ty, &named.argument.value)
}

/// Writes a `FieldOrPropType`.
fn write_type(out: &mut Vec<u8>, ty: &ArgumentType<'_>) -> Result<()> {
    match ty {
        ArgumentType::Type => out.push(et::SYSTEM_TYPE),
        ArgumentType::Object => out.push(et::BOXED),
        ArgumentType::SzArray(element) => {
            out.push(et::SZARRAY);
            write_type(out, element)?;
        }
        ArgumentType::Enum {
            ty: EnumType::Name(name),
            ..
        } => {
            out.push(et::ENUM);
            write_string(out, Some(name))?;
        }
        ArgumentType::Enum {
            ty: EnumType::Token(_),
            ..
        } => {
            return Err(Error::Malformed {
                structure: STRUCTURE,
                offset: out.len(),
                reason: "a named or boxed enum argument needs the name of its type",
            });
        }
        primitive => out.push(primitive_element(primitive).ok_or_else(mismatch)?),
    }
    Ok(())
}

fn primitive_element(ty: &ArgumentType<'_>) -> Option<u8> {
    let sig = match ty {
        ArgumentType::Boolean => TypeSig::Boolean,
        ArgumentType::Char => TypeSig::Char,
        ArgumentType::I1 => TypeSig::I1,
        ArgumentType::U1 => TypeSig::U1,
        ArgumentType::I2 => TypeSig::I2,
        ArgumentType::U2 => TypeSig::U2,
        ArgumentType::I4 => TypeSig::I4,
        ArgumentType::U4 => TypeSig::U4,
        ArgumentType::I8 => TypeSig::I8,
        ArgumentType::U8 => TypeSig::U8,
        ArgumentType::R4 => TypeSig::R4,
        ArgumentType::R8 => TypeSig::R8,
        ArgumentType::String => TypeSig::String,
        _ => return None,
    };
    sig.primitive_element_type()
}

fn write_string(out: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        None => out.push(0xFF),
        Some(text) => {
            let len = u32::try_from(text.len()).map_err(|_| overflow(text.len()))?;
            put_compressed_u32(out, len, STRUCTURE)?;
            out.extend_from_slice(text.as_bytes());
        }
    }
    Ok(())
}

fn write_value(out: &mut Vec<u8>, ty: &ArgumentType<'_>, value: &Value<'_>) -> Result<()> {
    match (ty, value) {
        (ArgumentType::Boolean, Value::Boolean(v)) => out.push(u8::from(*v)),
        (ArgumentType::Char, Value::Char(v)) | (ArgumentType::U2, Value::U2(v)) => put_u16(out, *v),
        (ArgumentType::I1, Value::I1(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (ArgumentType::U1, Value::U1(v)) => out.push(*v),
        (ArgumentType::I2, Value::I2(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (ArgumentType::I4, Value::I4(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (ArgumentType::U4, Value::U4(v)) => put_u32(out, *v),
        (ArgumentType::I8, Value::I8(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (ArgumentType::U8, Value::U8(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (ArgumentType::R4, Value::R4(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (ArgumentType::R8, Value::R8(v)) => out.extend_from_slice(&v.to_le_bytes()),
        (ArgumentType::String, Value::String(v)) | (ArgumentType::Type, Value::Type(v)) => {
            write_string(out, *v)?;
        }
        (ArgumentType::Enum { underlying, .. }, value) => {
            let ty = TypeSig::from_primitive_element_type(*underlying)
                .and_then(|sig| primitive_argument(&sig))
                .ok_or_else(mismatch)?;
            write_value(out, &ty, value)?;
        }
        (ArgumentType::Object, Value::Boxed(boxed)) => {
            write_type(out, &boxed.ty)?;
            write_value(out, &boxed.ty, &boxed.value)?;
        }
        (ArgumentType::SzArray(_), Value::Array(None)) => put_u32(out, u32::MAX),
        (ArgumentType::SzArray(element), Value::Array(Some(values))) => {
            let count = u32::try_from(values.len()).map_err(|_| overflow(values.len()))?;
            put_u32(out, count);
            for value in values {
                write_value(out, element, value)?;
            }
        }
        _ => return Err(mismatch()),
    }
    Ok(())
}

fn primitive_argument(sig: &TypeSig) -> Option<ArgumentType<'static>> {
    Some(match sig {
        TypeSig::Boolean => ArgumentType::Boolean,
        TypeSig::Char => ArgumentType::Char,
        TypeSig::I1 => ArgumentType::I1,
        TypeSig::U1 => ArgumentType::U1,
        TypeSig::I2 => ArgumentType::I2,
        TypeSig::U2 => ArgumentType::U2,
        TypeSig::I4 => ArgumentType::I4,
        TypeSig::U4 => ArgumentType::U4,
        TypeSig::I8 => ArgumentType::I8,
        TypeSig::U8 => ArgumentType::U8,
        _ => return None,
    })
}
