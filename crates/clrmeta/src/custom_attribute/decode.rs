//! The reader of custom attribute value blobs.

use alloc::boxed::Box;
use alloc::vec::Vec;

use clrmeta_model::{MethodSig, TypeSig, element_type as et};

use crate::bytes::Cursor;
use crate::custom_attribute::{
    Argument, ArgumentType, CustomAttributeValue, EnumResolver, EnumType, NamedArgument,
    NamedTarget, PROLOG, Value,
};
use crate::error::{Error, Result};

/// The deepest nesting of arrays and boxes that the reader accepts.
const MAX_DEPTH: u32 = 32;

struct Reader<'a, 'r> {
    cursor: Cursor<'a>,
    resolver: &'r dyn EnumResolver,
    depth: u32,
}

pub(crate) fn parse<'a>(
    blob: &'a [u8],
    constructor: &MethodSig,
    resolver: &dyn EnumResolver,
) -> Result<CustomAttributeValue<'a>> {
    let mut reader = Reader {
        cursor: Cursor::new(blob, "custom attribute value"),
        resolver,
        depth: 0,
    };
    if reader.cursor.u16()? != PROLOG {
        return Err(reader.cursor.malformed_at(0, "the prolog is not 0x0001"));
    }
    let mut fixed = Vec::with_capacity(constructor.params.len());
    for param in &constructor.params {
        let ty = reader.parameter_type(param)?;
        let value = reader.value(&ty)?;
        fixed.push(Argument { ty, value });
    }
    let count = reader.cursor.u16()?;
    let named = (0..count)
        .map(|_| reader.named())
        .collect::<Result<Vec<_>>>()?;
    reader.finish()?;
    Ok(CustomAttributeValue { fixed, named })
}

pub(crate) fn parse_named<'a>(
    blob: &'a [u8],
    resolver: &dyn EnumResolver,
) -> Result<Vec<NamedArgument<'a>>> {
    let mut reader = Reader {
        cursor: Cursor::new(blob, "security attribute arguments"),
        resolver,
        depth: 0,
    };
    let count = reader.cursor.compressed_u32()? as usize;
    if count > reader.cursor.remaining() {
        return Err(reader.cursor.malformed("the count is larger than the blob"));
    }
    let named = (0..count)
        .map(|_| reader.named())
        .collect::<Result<Vec<_>>>()?;
    reader.finish()?;
    Ok(named)
}

impl<'a> Reader<'a, '_> {
    fn finish(&self) -> Result<()> {
        if self.cursor.is_empty() {
            Ok(())
        } else {
            Err(self.cursor.malformed("bytes follow the last argument"))
        }
    }

    /// Returns the argument type of a constructor parameter.
    fn parameter_type(&mut self, param: &TypeSig) -> Result<ArgumentType<'a>> {
        let offset = self.cursor.position();
        if let Some(ty) = primitive(param.unmodified()) {
            return Ok(ty);
        }
        Ok(match param.unmodified() {
            TypeSig::Object => ArgumentType::Object,
            TypeSig::SzArray(element) => {
                ArgumentType::SzArray(Box::new(self.parameter_type(element)?))
            }
            TypeSig::Class(token) if self.resolver.is_system_type(*token) => ArgumentType::Type,
            TypeSig::Class(token) | TypeSig::ValueType(token) => ArgumentType::Enum {
                ty: EnumType::Token(*token),
                underlying: self
                    .resolver
                    .underlying_type_of_token(*token)
                    .ok_or(Error::UnresolvedEnum { offset })?,
            },
            _ => {
                return Err(self
                    .cursor
                    .malformed("the parameter type cannot hold an attribute argument"));
            }
        })
    }

    /// Reads a `FieldOrPropType`.
    fn field_or_prop_type(&mut self) -> Result<ArgumentType<'a>> {
        let offset = self.cursor.position();
        let element = self.cursor.u8()?;
        Ok(match element {
            et::SYSTEM_TYPE => ArgumentType::Type,
            et::BOXED => ArgumentType::Object,
            et::SZARRAY => {
                self.enter()?;
                let element = self.field_or_prop_type()?;
                self.depth -= 1;
                ArgumentType::SzArray(Box::new(element))
            }
            et::ENUM => {
                let name = self
                    .ser_string()?
                    .ok_or_else(|| self.cursor.malformed_at(offset, "the enum name is null"))?;
                ArgumentType::Enum {
                    ty: EnumType::Name(name),
                    underlying: self
                        .resolver
                        .underlying_type_of_name(name)
                        .ok_or(Error::UnresolvedEnum { offset })?,
                }
            }
            other => TypeSig::from_primitive_element_type(other)
                .as_ref()
                .and_then(primitive)
                .ok_or_else(|| {
                    self.cursor
                        .malformed_at(offset, "the element type is not valid")
                })?,
        })
    }

    fn enter(&mut self) -> Result<()> {
        if self.depth >= MAX_DEPTH {
            return Err(self.cursor.malformed("the arguments nest too deep"));
        }
        self.depth += 1;
        Ok(())
    }

    fn named(&mut self) -> Result<NamedArgument<'a>> {
        let offset = self.cursor.position();
        let target = match self.cursor.u8()? {
            et::FIELD => NamedTarget::Field,
            et::PROPERTY => NamedTarget::Property,
            _ => {
                return Err(self
                    .cursor
                    .malformed_at(offset, "a named argument is neither FIELD nor PROPERTY"));
            }
        };
        let ty = self.field_or_prop_type()?;
        let name = self.ser_string()?.ok_or_else(|| {
            self.cursor
                .malformed_at(offset, "the name of the argument is null")
        })?;
        let value = self.value(&ty)?;
        Ok(NamedArgument {
            target,
            name,
            argument: Argument { ty, value },
        })
    }

    /// Reads a `SerString`: a compressed length and UTF-8 bytes, or `0xFF`
    /// for a null string.
    fn ser_string(&mut self) -> Result<Option<&'a str>> {
        if self.cursor.peek_u8()? == 0xFF {
            self.cursor.skip(1)?;
            return Ok(None);
        }
        let len = self.cursor.compressed_u32()? as usize;
        let start = self.cursor.position();
        let bytes = self.cursor.bytes(len)?;
        core::str::from_utf8(bytes)
            .map(Some)
            .map_err(|_| self.cursor.malformed_at(start, "the string is not UTF-8"))
    }

    fn value(&mut self, ty: &ArgumentType<'a>) -> Result<Value<'a>> {
        let c = &mut self.cursor;
        Ok(match ty {
            ArgumentType::Boolean => Value::Boolean(c.u8()? != 0),
            ArgumentType::Char => Value::Char(c.u16()?),
            ArgumentType::I1 => Value::I1(i8::from_le_bytes(c.array()?)),
            ArgumentType::U1 => Value::U1(c.u8()?),
            ArgumentType::I2 => Value::I2(i16::from_le_bytes(c.array()?)),
            ArgumentType::U2 => Value::U2(c.u16()?),
            ArgumentType::I4 => Value::I4(i32::from_le_bytes(c.array()?)),
            ArgumentType::U4 => Value::U4(c.u32()?),
            ArgumentType::I8 => Value::I8(i64::from_le_bytes(c.array()?)),
            ArgumentType::U8 => Value::U8(c.u64()?),
            ArgumentType::R4 => Value::R4(f32::from_le_bytes(c.array()?)),
            ArgumentType::R8 => Value::R8(f64::from_le_bytes(c.array()?)),
            ArgumentType::String => Value::String(self.ser_string()?),
            ArgumentType::Type => Value::Type(self.ser_string()?),
            ArgumentType::Enum { underlying, .. } => {
                let ty = TypeSig::from_primitive_element_type(*underlying)
                    .as_ref()
                    .and_then(primitive)
                    .filter(|ty| {
                        !matches!(
                            ty,
                            ArgumentType::R4 | ArgumentType::R8 | ArgumentType::String
                        )
                    })
                    .ok_or_else(|| {
                        self.cursor
                            .malformed("the underlying type of the enum is not an integer")
                    })?;
                self.value(&ty)?
            }
            ArgumentType::Object => {
                self.enter()?;
                let ty = self.field_or_prop_type()?;
                let value = self.value(&ty)?;
                self.depth -= 1;
                Value::Boxed(Box::new(Argument { ty, value }))
            }
            ArgumentType::SzArray(element) => {
                let count = c.u32()?;
                if count == u32::MAX {
                    Value::Array(None)
                } else {
                    if count as usize > self.cursor.remaining() {
                        return Err(self.cursor.malformed("the array is larger than the blob"));
                    }
                    self.enter()?;
                    let values = (0..count)
                        .map(|_| self.value(element))
                        .collect::<Result<Vec<_>>>()?;
                    self.depth -= 1;
                    Value::Array(Some(values))
                }
            }
        })
    }
}

/// Returns the argument type of a primitive type or `string`.
fn primitive<'a>(ty: &TypeSig) -> Option<ArgumentType<'a>> {
    Some(match ty {
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
        TypeSig::R4 => ArgumentType::R4,
        TypeSig::R8 => ArgumentType::R8,
        TypeSig::String => ArgumentType::String,
        _ => return None,
    })
}
