//! Coded indices (ECMA-335 II.24.2.6) and the coded index of the portable
//! PDB format.

use crate::tables::TableId;
use crate::token::Token;

/// A kind of coded index: a small tag that selects a table, and a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodedIndexKind {
    /// `TypeDef`, `TypeRef` or `TypeSpec`.
    TypeDefOrRef,
    /// `Field`, `Param` or `Property`.
    HasConstant,
    /// One of the 22 tables that can own a custom attribute.
    HasCustomAttribute,
    /// `Field` or `Param`.
    HasFieldMarshal,
    /// `TypeDef`, `MethodDef` or `Assembly`.
    HasDeclSecurity,
    /// `TypeDef`, `TypeRef`, `ModuleRef`, `MethodDef` or `TypeSpec`.
    MemberRefParent,
    /// `Event` or `Property`.
    HasSemantics,
    /// `MethodDef` or `MemberRef`.
    MethodDefOrRef,
    /// `Field` or `MethodDef`.
    MemberForwarded,
    /// `File`, `AssemblyRef` or `ExportedType`.
    Implementation,
    /// `MethodDef` or `MemberRef`, with tags 2 and 3.
    CustomAttributeType,
    /// `Module`, `ModuleRef`, `AssemblyRef` or `TypeRef`.
    ResolutionScope,
    /// `TypeDef` or `MethodDef`.
    TypeOrMethodDef,
    /// One of the 27 tables that can own custom debug information (portable
    /// PDB).
    HasCustomDebugInformation,
}

impl CodedIndexKind {
    /// Every kind.
    pub const ALL: [Self; 14] = [
        Self::TypeDefOrRef,
        Self::HasConstant,
        Self::HasCustomAttribute,
        Self::HasFieldMarshal,
        Self::HasDeclSecurity,
        Self::MemberRefParent,
        Self::HasSemantics,
        Self::MethodDefOrRef,
        Self::MemberForwarded,
        Self::Implementation,
        Self::CustomAttributeType,
        Self::ResolutionScope,
        Self::TypeOrMethodDef,
        Self::HasCustomDebugInformation,
    ];

    /// Returns the name of the kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TypeDefOrRef => "TypeDefOrRef",
            Self::HasConstant => "HasConstant",
            Self::HasCustomAttribute => "HasCustomAttribute",
            Self::HasFieldMarshal => "HasFieldMarshal",
            Self::HasDeclSecurity => "HasDeclSecurity",
            Self::MemberRefParent => "MemberRefParent",
            Self::HasSemantics => "HasSemantics",
            Self::MethodDefOrRef => "MethodDefOrRef",
            Self::MemberForwarded => "MemberForwarded",
            Self::Implementation => "Implementation",
            Self::CustomAttributeType => "CustomAttributeType",
            Self::ResolutionScope => "ResolutionScope",
            Self::TypeOrMethodDef => "TypeOrMethodDef",
            Self::HasCustomDebugInformation => "HasCustomDebugInformation",
        }
    }

    /// Returns the number of tag bits.
    #[must_use]
    pub const fn tag_bits(self) -> u32 {
        match self {
            Self::HasFieldMarshal
            | Self::HasSemantics
            | Self::MethodDefOrRef
            | Self::MemberForwarded
            | Self::TypeOrMethodDef => 1,
            Self::TypeDefOrRef
            | Self::HasConstant
            | Self::HasDeclSecurity
            | Self::Implementation
            | Self::ResolutionScope => 2,
            Self::MemberRefParent | Self::CustomAttributeType => 3,
            Self::HasCustomAttribute | Self::HasCustomDebugInformation => 5,
        }
    }

    /// Returns the table of each tag. `None` marks a tag that ECMA-335 does
    /// not use.
    #[must_use]
    pub const fn tables(self) -> &'static [Option<TableId>] {
        use TableId as T;
        match self {
            Self::TypeDefOrRef => &[Some(T::TypeDef), Some(T::TypeRef), Some(T::TypeSpec)],
            Self::HasConstant => &[Some(T::Field), Some(T::Param), Some(T::Property)],
            Self::HasCustomAttribute => &HAS_CUSTOM_ATTRIBUTE,
            Self::HasFieldMarshal => &[Some(T::Field), Some(T::Param)],
            Self::HasDeclSecurity => &[Some(T::TypeDef), Some(T::MethodDef), Some(T::Assembly)],
            Self::MemberRefParent => &[
                Some(T::TypeDef),
                Some(T::TypeRef),
                Some(T::ModuleRef),
                Some(T::MethodDef),
                Some(T::TypeSpec),
            ],
            Self::HasSemantics => &[Some(T::Event), Some(T::Property)],
            Self::MethodDefOrRef => &[Some(T::MethodDef), Some(T::MemberRef)],
            Self::MemberForwarded => &[Some(T::Field), Some(T::MethodDef)],
            Self::Implementation => &[Some(T::File), Some(T::AssemblyRef), Some(T::ExportedType)],
            Self::CustomAttributeType => {
                &[None, None, Some(T::MethodDef), Some(T::MemberRef), None]
            }
            Self::ResolutionScope => &[
                Some(T::Module),
                Some(T::ModuleRef),
                Some(T::AssemblyRef),
                Some(T::TypeRef),
            ],
            Self::TypeOrMethodDef => &[Some(T::TypeDef), Some(T::MethodDef)],
            Self::HasCustomDebugInformation => &HAS_CUSTOM_DEBUG_INFORMATION,
        }
    }

    /// Returns the number of rows below which every table of the kind fits a
    /// coded index of 2 bytes.
    #[must_use]
    pub const fn small_row_limit(self) -> u32 {
        1 << (16 - self.tag_bits())
    }

    /// Decodes a coded index value. Returns `None` for a tag that the kind
    /// does not use.
    #[must_use]
    pub fn decode(self, value: u32) -> Option<Token> {
        let bits = self.tag_bits();
        let tag = (value & ((1 << bits) - 1)) as usize;
        let table = self.tables().get(tag).copied().flatten()?;
        let row = value >> bits;
        (row <= 0x00FF_FFFF).then(|| Token::new(table, row))
    }

    /// Encodes a token. Returns `None` when the kind cannot name the table
    /// of the token, or when the row does not fit beside the tag.
    #[must_use]
    pub fn encode(self, token: Token) -> Option<u32> {
        let table = token.table()?;
        let tag = self.tables().iter().position(|&t| t == Some(table))?;
        let bits = self.tag_bits();
        let row = token.row();
        (row < (1 << (32 - bits))).then(|| (row << bits) | u32::try_from(tag).unwrap_or(0))
    }

    /// Returns `true` when the kind can name `table`.
    #[must_use]
    pub fn contains(self, table: TableId) -> bool {
        self.tables().contains(&Some(table))
    }
}

const HAS_CUSTOM_ATTRIBUTE: [Option<TableId>; 22] = [
    Some(TableId::MethodDef),
    Some(TableId::Field),
    Some(TableId::TypeRef),
    Some(TableId::TypeDef),
    Some(TableId::Param),
    Some(TableId::InterfaceImpl),
    Some(TableId::MemberRef),
    Some(TableId::Module),
    // ECMA-335 calls this tag "Permission": rows of DeclSecurity.
    Some(TableId::DeclSecurity),
    Some(TableId::Property),
    Some(TableId::Event),
    Some(TableId::StandAloneSig),
    Some(TableId::ModuleRef),
    Some(TableId::TypeSpec),
    Some(TableId::Assembly),
    Some(TableId::AssemblyRef),
    Some(TableId::File),
    Some(TableId::ExportedType),
    Some(TableId::ManifestResource),
    Some(TableId::GenericParam),
    Some(TableId::GenericParamConstraint),
    Some(TableId::MethodSpec),
];

const HAS_CUSTOM_DEBUG_INFORMATION: [Option<TableId>; 27] = [
    Some(TableId::MethodDef),
    Some(TableId::Field),
    Some(TableId::TypeRef),
    Some(TableId::TypeDef),
    Some(TableId::Param),
    Some(TableId::InterfaceImpl),
    Some(TableId::MemberRef),
    Some(TableId::Module),
    Some(TableId::DeclSecurity),
    Some(TableId::Property),
    Some(TableId::Event),
    Some(TableId::StandAloneSig),
    Some(TableId::ModuleRef),
    Some(TableId::TypeSpec),
    Some(TableId::Assembly),
    Some(TableId::AssemblyRef),
    Some(TableId::File),
    Some(TableId::ExportedType),
    Some(TableId::ManifestResource),
    Some(TableId::GenericParam),
    Some(TableId::GenericParamConstraint),
    Some(TableId::MethodSpec),
    Some(TableId::Document),
    Some(TableId::LocalScope),
    Some(TableId::LocalVariable),
    Some(TableId::LocalConstant),
    Some(TableId::ImportScope),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_has_enough_tag_bits_for_its_tables() {
        for kind in CodedIndexKind::ALL {
            assert!(
                kind.tables().len() <= 1 << kind.tag_bits(),
                "{}",
                kind.name()
            );
        }
    }

    #[test]
    fn a_coded_index_decodes_and_encodes_its_table_and_row() {
        let kind = CodedIndexKind::TypeDefOrRef;
        assert_eq!(kind.decode(20), Some(Token::new(TableId::TypeDef, 5)));
        assert_eq!(kind.decode(13), Some(Token::new(TableId::TypeRef, 3)));
        assert_eq!(kind.decode(30), Some(Token::new(TableId::TypeSpec, 7)));
        assert_eq!(kind.decode(3), None);
        assert_eq!(kind.encode(Token::new(TableId::TypeRef, 3)), Some(13));
        assert_eq!(kind.encode(Token::new(TableId::MethodDef, 3)), None);
        let permission = CodedIndexKind::HasCustomAttribute.decode((4 << 5) | 8);
        assert_eq!(permission, Some(Token::new(TableId::DeclSecurity, 4)));
        let ctor = CodedIndexKind::CustomAttributeType.decode((9 << 3) | 3);
        assert_eq!(ctor, Some(Token::new(TableId::MemberRef, 9)));
        assert_eq!(CodedIndexKind::CustomAttributeType.decode(8), None);
    }

    #[test]
    fn the_small_row_limit_follows_the_tag_bits() {
        assert_eq!(CodedIndexKind::TypeDefOrRef.small_row_limit(), 1 << 14);
        assert_eq!(
            CodedIndexKind::HasCustomAttribute.small_row_limit(),
            1 << 11
        );
        assert_eq!(CodedIndexKind::MethodDefOrRef.small_row_limit(), 1 << 15);
    }
}
