//! An [`EnumResolver`] over the type definitions of a set of modules.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use clrmeta_model::{TableId, Token, element_type as et};

use crate::custom_attribute::EnumResolver;
use crate::flags::field_attributes;
use crate::metadata::Metadata;
use crate::signature::{FieldSig, Signature};
use crate::tables::TypeDefRow;
use crate::token::Rid;

/// The enums of a set of modules by name in the form of `ilasm`
/// (`Namespace.Outer/Inner`), with their underlying element type.
#[derive(Debug, Clone, Default)]
pub struct EnumIndex {
    enums: BTreeMap<String, u8>,
}

impl EnumIndex {
    /// Makes an index of the enums of the modules. When two modules define
    /// an enum of one name, the first module wins. A type that does not
    /// read is left out.
    #[must_use]
    pub fn new(modules: &[&Metadata<'_>]) -> Self {
        let mut index = Self::default();
        for module in modules {
            index.add_module(module);
        }
        index
    }

    /// Adds the enums of a module. An enum of a name that the index holds
    /// is left out.
    pub fn add_module(&mut self, module: &Metadata<'_>) {
        for (rid, row) in module.tables().table::<TypeDefRow>().iter().flatten() {
            let Some(underlying) = enum_underlying(module, rid, &row) else {
                continue;
            };
            if let Ok(name) = module.type_name(rid.token()) {
                self.enums.entry(name.to_string()).or_insert(underlying);
            }
        }
    }

    /// Returns the underlying element type of the enum of a name in the
    /// form of `ilasm`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u8> {
        self.enums.get(name).copied()
    }

    /// Returns the number of enums.
    #[must_use]
    pub fn len(&self) -> usize {
        self.enums.len()
    }

    /// Returns `true` when the index holds no enum.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.enums.is_empty()
    }
}

/// Answers the questions of the custom attribute reader for one module:
/// its tokens resolve to names in the module, and the names resolve in an
/// [`EnumIndex`] (of the module and of the modules that it refers to, for
/// example `System.Private.CoreLib` for the standard enums).
#[derive(Debug, Clone, Copy)]
pub struct MetadataResolver<'r, 'a> {
    home: &'r Metadata<'a>,
    index: &'r EnumIndex,
}

impl<'r, 'a> MetadataResolver<'r, 'a> {
    /// Makes a resolver for the tokens of `home`.
    #[must_use]
    pub const fn new(home: &'r Metadata<'a>, index: &'r EnumIndex) -> Self {
        Self { home, index }
    }

    fn name_of(&self, token: Token) -> Option<String> {
        let name = self.home.type_name(token).ok()?;
        Some(name.to_string())
    }
}

/// Returns the underlying element type of a type definition that extends
/// `System.Enum`: the type of its instance field.
fn enum_underlying(module: &Metadata<'_>, rid: Rid<TypeDefRow>, row: &TypeDefRow) -> Option<u8> {
    if !matches!(
        row.extends.table(),
        Some(TableId::TypeRef | TableId::TypeDef)
    ) || row.extends.is_null()
    {
        return None;
    }
    if module.type_name(row.extends).ok()?.to_string() != "System.Enum" {
        return None;
    }
    module.fields_of(rid).ok()?.find_map(|field| {
        let field_row = module.tables().row(field).ok()?;
        if field_row.flags & field_attributes::STATIC != 0 {
            return None;
        }
        let sig = FieldSig::parse(module.blobs().get(field_row.signature).ok()?).ok()?;
        let element = sig.field_type.unmodified().primitive_element_type()?;
        // A native-sized enum cannot occur in a value blob, which has no
        // native-sized integers.
        matches!(
            element,
            et::BOOLEAN
                | et::CHAR
                | et::I1
                | et::U1
                | et::I2
                | et::U2
                | et::I4
                | et::U4
                | et::I8
                | et::U8
        )
        .then_some(element)
    })
}

/// Returns the type of a serialized type name in the form of `ilasm`: the part
/// before the assembly name, with `+` for nesting replaced by `/`.
fn ilasm_name(serialized: &str) -> String {
    let mut depth = 0u32;
    let end = serialized
        .char_indices()
        .find(|&(_, c)| {
            match c {
                '[' => depth += 1,
                ']' => depth = depth.saturating_sub(1),
                _ => {}
            }
            c == ',' && depth == 0
        })
        .map_or(serialized.len(), |(index, _)| index);
    serialized[..end].trim().replace('+', "/")
}

impl EnumResolver for MetadataResolver<'_, '_> {
    fn underlying_type_of_token(&self, token: Token) -> Option<u8> {
        self.index.get(&self.name_of(token)?)
    }

    fn underlying_type_of_name(&self, name: &str) -> Option<u8> {
        self.index.get(&ilasm_name(name))
    }

    fn is_system_type(&self, token: Token) -> bool {
        self.name_of(token)
            .is_some_and(|name| name == "System.Type")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_serialized_name_becomes_an_ilasm_name() {
        assert_eq!(
            ilasm_name("System.AttributeTargets, System.Runtime, Version=8.0.0.0"),
            "System.AttributeTargets"
        );
        assert_eq!(ilasm_name("Outer+Inner"), "Outer/Inner");
        assert_eq!(
            ilasm_name("G`1[[System.Int32, mscorlib]], Lib"),
            "G`1[[System.Int32, mscorlib]]"
        );
    }
}
