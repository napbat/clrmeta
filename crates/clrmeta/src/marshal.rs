//! Marshalling descriptors (ECMA-335 II.23.4) with the extensions of the
//! .NET runtime.

use alloc::vec::Vec;

use crate::bytes::{Cursor, put_compressed_u32};
use crate::error::{Error, Result};

/// The `NATIVE_TYPE_*` constants.
pub mod native_type {
    /// `bool` as a 4-byte value.
    pub const BOOLEAN: u8 = 0x02;
    /// `int8`.
    pub const I1: u8 = 0x03;
    /// `unsigned int8`.
    pub const U1: u8 = 0x04;
    /// `int16`.
    pub const I2: u8 = 0x05;
    /// `unsigned int16`.
    pub const U2: u8 = 0x06;
    /// `int32`.
    pub const I4: u8 = 0x07;
    /// `unsigned int32`.
    pub const U4: u8 = 0x08;
    /// `int64`.
    pub const I8: u8 = 0x09;
    /// `unsigned int64`.
    pub const U8: u8 = 0x0A;
    /// `float32`.
    pub const R4: u8 = 0x0B;
    /// `float64`.
    pub const R8: u8 = 0x0C;
    /// A COM currency.
    pub const CURRENCY: u8 = 0x0F;
    /// A COM `BSTR`.
    pub const BSTR: u8 = 0x13;
    /// A pointer to an ANSI string.
    pub const LPSTR: u8 = 0x14;
    /// A pointer to a UTF-16 string.
    pub const LPWSTR: u8 = 0x15;
    /// A pointer to a platform string.
    pub const LPTSTR: u8 = 0x16;
    /// A string of fixed size in a structure.
    pub const FIXED_SYS_STRING: u8 = 0x17;
    /// A COM `IUnknown` pointer.
    pub const IUNKNOWN: u8 = 0x19;
    /// A COM `IDispatch` pointer.
    pub const IDISPATCH: u8 = 0x1A;
    /// A structure.
    pub const STRUCT: u8 = 0x1B;
    /// A COM interface pointer.
    pub const INTERFACE: u8 = 0x1C;
    /// A COM `SAFEARRAY`.
    pub const SAFE_ARRAY: u8 = 0x1D;
    /// An array of fixed size in a structure.
    pub const FIXED_ARRAY: u8 = 0x1E;
    /// `native int`.
    pub const INT: u8 = 0x1F;
    /// `native unsigned int`.
    pub const UINT: u8 = 0x20;
    /// A string with a length prefix in a structure.
    pub const BYVAL_STR: u8 = 0x22;
    /// An ANSI `BSTR`.
    pub const ANSI_BSTR: u8 = 0x23;
    /// A platform `BSTR`.
    pub const TBSTR: u8 = 0x24;
    /// A COM `VARIANT_BOOL`.
    pub const VARIANT_BOOL: u8 = 0x25;
    /// A function pointer.
    pub const FUNC: u8 = 0x26;
    /// A value of any type.
    pub const AS_ANY: u8 = 0x28;
    /// A C-style array.
    pub const ARRAY: u8 = 0x2A;
    /// A pointer to a structure.
    pub const LPSTRUCT: u8 = 0x2B;
    /// A custom marshaler.
    pub const CUSTOM_MARSHALER: u8 = 0x2C;
    /// An `HRESULT`.
    pub const ERROR: u8 = 0x2D;
    /// A Windows Runtime `IInspectable` pointer.
    pub const IINSPECTABLE: u8 = 0x2E;
    /// A Windows Runtime `HSTRING`.
    pub const HSTRING: u8 = 0x2F;
    /// A pointer to a UTF-8 string.
    pub const LPUTF8STR: u8 = 0x30;
    /// The element type of an array that the runtime chooses.
    pub const MAX: u8 = 0x50;
}

/// A marshalling descriptor. The optional values are present only when
/// the blob holds them, so a descriptor encodes back to its blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarshalDescriptor<'a> {
    /// A native type without parameters.
    Simple(u8),
    /// `NATIVE_TYPE_ARRAY`: a C-style array.
    Array {
        /// The native type of the elements.
        element: u8,
        /// The parameter that holds the element count.
        param_index: Option<u32>,
        /// The element count, or the number of elements to add to the
        /// value of the parameter.
        element_count: Option<u32>,
        /// The flags of the runtime (1: the parameter index is given).
        flags: Option<u32>,
    },
    /// `NATIVE_TYPE_FIXEDARRAY`: an array of fixed size in a structure.
    FixedArray {
        /// The number of elements.
        count: Option<u32>,
        /// The native type of the elements.
        element: Option<u8>,
    },
    /// `NATIVE_TYPE_FIXEDSYSSTRING`: a string of fixed size in a structure.
    FixedSysString {
        /// The number of characters.
        count: Option<u32>,
    },
    /// `NATIVE_TYPE_SAFEARRAY`.
    SafeArray {
        /// The `VARTYPE` of the elements.
        variant_type: Option<u32>,
        /// The name of the user-defined element type.
        user_defined_subtype: Option<&'a str>,
    },
    /// `NATIVE_TYPE_IUNKNOWN`, `IDISPATCH`, `INTF` or `IINSPECTABLE`.
    Interface {
        /// The native type.
        native_type: u8,
        /// The parameter that holds the interface identifier.
        iid_parameter_index: Option<u32>,
    },
    /// `NATIVE_TYPE_CUSTOMMARSHALER`.
    CustomMarshaler {
        /// The GUID string of the type library (unused).
        guid: &'a str,
        /// The name of the native type (unused).
        native_type_name: &'a str,
        /// The name of the marshaler type.
        marshaler: &'a str,
        /// The cookie string for the marshaler.
        cookie: &'a str,
    },
    /// Another native type with parameters, kept as bytes.
    Other {
        /// The native type.
        native_type: u8,
        /// The bytes after the native type.
        data: &'a [u8],
    },
}

impl<'a> MarshalDescriptor<'a> {
    /// Parses a descriptor blob.
    ///
    /// # Errors
    ///
    /// Returns an error when the blob is empty or a value is cut short or
    /// not valid.
    pub fn parse(blob: &'a [u8]) -> Result<Self> {
        let mut c = Cursor::new(blob, "marshalling descriptor");
        let native = c.u8()?;
        let descriptor = match native {
            native_type::ARRAY => Self::Array {
                element: byte(&mut c)?,
                param_index: optional(&mut c)?,
                element_count: optional(&mut c)?,
                flags: optional(&mut c)?,
            },
            native_type::FIXED_ARRAY => Self::FixedArray {
                count: optional(&mut c)?,
                element: if c.is_empty() {
                    None
                } else {
                    Some(byte(&mut c)?)
                },
            },
            native_type::FIXED_SYS_STRING => Self::FixedSysString {
                count: optional(&mut c)?,
            },
            native_type::SAFE_ARRAY => Self::SafeArray {
                variant_type: optional(&mut c)?,
                user_defined_subtype: if c.is_empty() {
                    None
                } else {
                    Some(string(&mut c)?)
                },
            },
            native_type::IUNKNOWN
            | native_type::IDISPATCH
            | native_type::INTERFACE
            | native_type::IINSPECTABLE => Self::Interface {
                native_type: native,
                iid_parameter_index: optional(&mut c)?,
            },
            native_type::CUSTOM_MARSHALER => Self::CustomMarshaler {
                guid: string(&mut c)?,
                native_type_name: string(&mut c)?,
                marshaler: string(&mut c)?,
                cookie: string(&mut c)?,
            },
            _ if c.is_empty() => Self::Simple(native),
            _ => Self::Other {
                native_type: native,
                data: c.rest(),
            },
        };
        if matches!(descriptor, Self::Other { .. }) || c.is_empty() {
            Ok(descriptor)
        } else {
            Err(c.malformed("bytes follow the descriptor"))
        }
    }

    /// Encodes the descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when a value does not fit its compressed form, or a
    /// value follows a value that is absent.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        match *self {
            Self::Simple(native) => out.push(native),
            Self::Array {
                element,
                param_index,
                element_count,
                flags,
            } => {
                out.extend_from_slice(&[native_type::ARRAY, element]);
                put_optionals(&mut out, &[param_index, element_count, flags])?;
            }
            Self::FixedArray { count, element } => {
                out.push(native_type::FIXED_ARRAY);
                put_optionals(&mut out, &[count, element.map(u32::from)])?;
            }
            Self::FixedSysString { count } => {
                out.push(native_type::FIXED_SYS_STRING);
                put_optionals(&mut out, &[count])?;
            }
            Self::SafeArray {
                variant_type,
                user_defined_subtype,
            } => {
                out.push(native_type::SAFE_ARRAY);
                put_optionals(&mut out, &[variant_type])?;
                if let Some(name) = user_defined_subtype {
                    if variant_type.is_none() {
                        return Err(gap());
                    }
                    put_string(&mut out, name)?;
                }
            }
            Self::Interface {
                native_type,
                iid_parameter_index,
            } => {
                out.push(native_type);
                put_optionals(&mut out, &[iid_parameter_index])?;
            }
            Self::CustomMarshaler {
                guid,
                native_type_name,
                marshaler,
                cookie,
            } => {
                out.push(native_type::CUSTOM_MARSHALER);
                for text in [guid, native_type_name, marshaler, cookie] {
                    put_string(&mut out, text)?;
                }
            }
            Self::Other { native_type, data } => {
                out.push(native_type);
                out.extend_from_slice(data);
            }
        }
        Ok(out)
    }
}

fn gap() -> Error {
    Error::Malformed {
        structure: "marshalling descriptor",
        offset: 0,
        reason: "a value follows a value that is absent",
    }
}

fn byte(c: &mut Cursor<'_>) -> Result<u8> {
    let offset = c.position();
    let value = c.compressed_u32()?;
    u8::try_from(value).map_err(|_| c.malformed_at(offset, "the native type is larger than a byte"))
}

fn optional(c: &mut Cursor<'_>) -> Result<Option<u32>> {
    if c.is_empty() {
        Ok(None)
    } else {
        c.compressed_u32().map(Some)
    }
}

fn string<'a>(c: &mut Cursor<'a>) -> Result<&'a str> {
    let len = c.compressed_u32()? as usize;
    let start = c.position();
    let bytes = c.bytes(len)?;
    core::str::from_utf8(bytes).map_err(|_| c.malformed_at(start, "the string is not UTF-8"))
}

fn put_optionals(out: &mut Vec<u8>, values: &[Option<u32>]) -> Result<()> {
    let present = values.iter().take_while(|value| value.is_some()).count();
    if values[present..].iter().any(Option::is_some) {
        return Err(gap());
    }
    for value in values.iter().flatten() {
        put_compressed_u32(out, *value, "marshalling descriptor")?;
    }
    Ok(())
}

fn put_string(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let len = u32::try_from(text.len()).map_err(|_| Error::Overflow {
        structure: "marshalling descriptor",
        value: text.len() as u64,
    })?;
    put_compressed_u32(out, len, "marshalling descriptor")?;
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(blob: &[u8]) -> MarshalDescriptor<'_> {
        let descriptor = MarshalDescriptor::parse(blob).unwrap();
        assert_eq!(descriptor.encode().unwrap(), blob);
        descriptor
    }

    #[test]
    fn every_form_of_descriptor_reads_and_writes() {
        assert_eq!(
            round_trip(&[0x07]),
            MarshalDescriptor::Simple(native_type::I4)
        );
        assert_eq!(
            round_trip(&[0x2A, 0x07, 0x02, 0x00, 0x01]),
            MarshalDescriptor::Array {
                element: native_type::I4,
                param_index: Some(2),
                element_count: Some(0),
                flags: Some(1)
            }
        );
        assert!(matches!(
            round_trip(&[0x2A, 0x50]),
            MarshalDescriptor::Array {
                param_index: None,
                ..
            }
        ));
        assert_eq!(
            round_trip(&[0x1E, 0x10, 0x04]),
            MarshalDescriptor::FixedArray {
                count: Some(16),
                element: Some(native_type::U1)
            }
        );
        assert_eq!(
            round_trip(&[0x17, 0x20]),
            MarshalDescriptor::FixedSysString { count: Some(32) }
        );
        assert_eq!(
            round_trip(&[0x1D, 0x08, 0x01, b'T']),
            MarshalDescriptor::SafeArray {
                variant_type: Some(8),
                user_defined_subtype: Some("T")
            }
        );
        assert_eq!(
            round_trip(&[0x1C, 0x01]),
            MarshalDescriptor::Interface {
                native_type: native_type::INTERFACE,
                iid_parameter_index: Some(1)
            }
        );
        assert_eq!(
            round_trip(&[0x2C, 0x00, 0x00, 0x01, b'M', 0x02, b'c', b'k']),
            MarshalDescriptor::CustomMarshaler {
                guid: "",
                native_type_name: "",
                marshaler: "M",
                cookie: "ck"
            }
        );
        assert!(matches!(
            round_trip(&[0x1B, 0x08, 0x10]),
            MarshalDescriptor::Other {
                native_type: 0x1B,
                ..
            }
        ));
    }

    #[test]
    fn malformed_descriptors_are_errors() {
        assert!(MarshalDescriptor::parse(&[]).is_err());
        assert!(MarshalDescriptor::parse(&[0x2C, 0x05, b'a']).is_err());
        assert!(MarshalDescriptor::parse(&[0x17, 0x01, 0x02]).is_err());
        let gap = MarshalDescriptor::Array {
            element: 0x07,
            param_index: None,
            element_count: Some(1),
            flags: None,
        };
        assert!(gap.encode().is_err());
    }
}
