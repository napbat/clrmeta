//! Declarative security permission sets (ECMA-335 II.22.11 and II.23.3).
//!
//! A permission set blob has one of two forms: the XML form of the first
//! runtimes (UTF-16 text), or the binary form that starts with `.`: a list
//! of security attributes, each with a type name and named arguments.

use alloc::vec::Vec;

use crate::bytes::{Cursor, put_compressed_u32};
use crate::custom_attribute::{CustomAttributeValue, EnumResolver, NamedArgument};
use crate::error::{Error, Result};

/// The `SecurityAction` values of `DeclSecurity::action` (II.22.11).
pub mod security_action {
    /// Reserved.
    pub const REQUEST: u16 = 1;
    /// Every caller must have the permission.
    pub const DEMAND: u16 = 2;
    /// The method asserts the permission.
    pub const ASSERT: u16 = 3;
    /// The method denies the permission.
    pub const DENY: u16 = 4;
    /// Only this permission is granted.
    pub const PERMIT_ONLY: u16 = 5;
    /// The immediate caller must have the permission.
    pub const LINK_DEMAND: u16 = 6;
    /// A subtype or an override must have the permission.
    pub const INHERITANCE_DEMAND: u16 = 7;
    /// The minimum permissions of the assembly.
    pub const REQUEST_MINIMUM: u16 = 8;
    /// The optional permissions of the assembly.
    pub const REQUEST_OPTIONAL: u16 = 9;
    /// The permissions that the assembly refuses.
    pub const REQUEST_REFUSE: u16 = 10;
    /// Reserved: a grant of a precompiled image.
    pub const PRE_JIT_GRANT: u16 = 11;
    /// Reserved: a denial of a precompiled image.
    pub const PRE_JIT_DENY: u16 = 12;
    /// Reserved: a non-CAS demand.
    pub const NON_CAS_DEMAND: u16 = 13;
    /// Reserved: a non-CAS link demand.
    pub const NON_CAS_LINK_DEMAND: u16 = 14;
    /// Reserved: a non-CAS inheritance demand.
    pub const NON_CAS_INHERITANCE: u16 = 15;
}

/// A security attribute of the binary form.
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityAttribute<'a> {
    /// The serialized name of the attribute type.
    pub type_name: &'a str,
    /// The named arguments that the attribute sets.
    pub named: Vec<NamedArgument<'a>>,
}

/// A permission set blob.
#[derive(Debug, Clone, PartialEq)]
pub enum PermissionSet<'a> {
    /// The XML form: little-endian UTF-16 text.
    Xml(&'a [u8]),
    /// The binary form.
    Attributes(Vec<SecurityAttribute<'a>>),
}

impl<'a> PermissionSet<'a> {
    /// Parses a permission set blob. An enum argument needs the resolver,
    /// as in a custom attribute.
    ///
    /// # Errors
    ///
    /// Returns an error when the binary form is cut short or not valid.
    pub fn parse(blob: &'a [u8], resolver: &dyn EnumResolver) -> Result<Self> {
        if blob.first() != Some(&b'.') {
            return Ok(Self::Xml(blob));
        }
        let mut c = Cursor::new(blob, "permission set");
        c.skip(1)?;
        let count = c.compressed_u32()? as usize;
        if count > c.remaining() {
            return Err(c.malformed("the count is larger than the blob"));
        }
        let mut attributes = Vec::with_capacity(count);
        for _ in 0..count {
            let len = c.compressed_u32()? as usize;
            let start = c.position();
            let type_name = core::str::from_utf8(c.bytes(len)?)
                .map_err(|_| c.malformed_at(start, "the type name is not UTF-8"))?;
            let len = c.compressed_u32()? as usize;
            let named = CustomAttributeValue::parse_named(c.bytes(len)?, resolver)?;
            attributes.push(SecurityAttribute { type_name, named });
        }
        if !c.is_empty() {
            return Err(c.malformed("bytes follow the last attribute"));
        }
        Ok(Self::Attributes(attributes))
    }

    /// Encodes the permission set.
    ///
    /// # Errors
    ///
    /// Returns an error when an argument does not encode or a length does
    /// not fit its compressed form.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let attributes = match self {
            Self::Xml(text) => return Ok(text.to_vec()),
            Self::Attributes(attributes) => attributes,
        };
        let mut out = alloc::vec![b'.'];
        put_compressed_u32(&mut out, length(attributes.len())?, "permission set")?;
        for attribute in attributes {
            put_compressed_u32(
                &mut out,
                length(attribute.type_name.len())?,
                "permission set",
            )?;
            out.extend_from_slice(attribute.type_name.as_bytes());
            let arguments = CustomAttributeValue::encode_named(&attribute.named)?;
            put_compressed_u32(&mut out, length(arguments.len())?, "permission set")?;
            out.extend_from_slice(&arguments);
        }
        Ok(out)
    }
}

fn length(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Overflow {
        structure: "permission set",
        value: value as u64,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use clrmeta_model::Token;

    use super::*;
    use crate::custom_attribute::{Argument, ArgumentType, NamedTarget, Value};

    struct NoEnums;

    impl EnumResolver for NoEnums {
        fn underlying_type_of_token(&self, _: Token) -> Option<u8> {
            None
        }

        fn underlying_type_of_name(&self, _: &str) -> Option<u8> {
            None
        }

        fn is_system_type(&self, _: Token) -> bool {
            false
        }
    }

    #[test]
    fn the_binary_form_reads_and_writes_its_attributes() {
        let set = PermissionSet::Attributes(vec![SecurityAttribute {
            type_name: "S.P, A",
            named: vec![NamedArgument {
                target: NamedTarget::Property,
                name: "Unrestricted",
                argument: Argument {
                    ty: ArgumentType::Boolean,
                    value: Value::Boolean(true),
                },
            }],
        }]);
        let blob = set.encode().unwrap();
        assert_eq!(&blob[..3], &[b'.', 1, 6]);
        assert_eq!(PermissionSet::parse(&blob, &NoEnums).unwrap(), set);
        assert!(PermissionSet::parse(&blob[..blob.len() - 1], &NoEnums).is_err());
    }

    #[test]
    fn the_xml_form_is_kept_as_text() {
        let blob = [b'<', 0, b'P', 0];
        assert_eq!(
            PermissionSet::parse(&blob, &NoEnums).unwrap(),
            PermissionSet::Xml(&blob)
        );
    }
}
