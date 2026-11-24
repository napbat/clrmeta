//! Metadata tokens (ECMA-335 II.22, III.1.9) and table identifiers.

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The token type of a string in the `#US` heap (`ldstr`).
pub const USER_STRING_TOKEN_TYPE: u8 = 0x70;

macro_rules! table_ids {
    ($($(#[doc = $doc:literal])+ $id:ident = $value:literal,)+) => {
        /// The identifier of a metadata table: its bit in the `valid` mask of
        /// the tables stream and the high byte of its tokens.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
        #[repr(u8)]
        pub enum TableId {
            $($(#[doc = $doc])+ $id = $value,)+
        }

        impl TableId {
            /// Every table, in the order of the identifiers.
            pub const ALL: &'static [Self] = &[$(Self::$id),+];

            /// Returns the table of an identifier, or `None` when no table
            /// has the identifier.
            #[must_use]
            pub const fn from_u8(value: u8) -> Option<Self> {
                match value {
                    $($value => Some(Self::$id),)+
                    _ => None,
                }
            }

            /// Returns the name of the table in ECMA-335.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$id => stringify!($id),)+
                }
            }
        }
    };
}

table_ids! {
    /// The module (II.22.30).
    Module = 0x00,
    /// References to types of other scopes (II.22.38).
    TypeRef = 0x01,
    /// Type definitions (II.22.37).
    TypeDef = 0x02,
    /// Indirections to fields, of unoptimized metadata.
    FieldPtr = 0x03,
    /// Field definitions (II.22.15).
    Field = 0x04,
    /// Indirections to methods, of unoptimized metadata.
    MethodPtr = 0x05,
    /// Method definitions (II.22.26).
    MethodDef = 0x06,
    /// Indirections to parameters, of unoptimized metadata.
    ParamPtr = 0x07,
    /// Parameter definitions (II.22.33).
    Param = 0x08,
    /// Interface implementations (II.22.23).
    InterfaceImpl = 0x09,
    /// References to members of types (II.22.25).
    MemberRef = 0x0A,
    /// Constant values (II.22.9).
    Constant = 0x0B,
    /// Custom attributes (II.22.10).
    CustomAttribute = 0x0C,
    /// Marshalling descriptors (II.22.17).
    FieldMarshal = 0x0D,
    /// Declarative security (II.22.11).
    DeclSecurity = 0x0E,
    /// Type layouts (II.22.8).
    ClassLayout = 0x0F,
    /// Field offsets (II.22.16).
    FieldLayout = 0x10,
    /// Stand-alone signatures (II.22.36).
    StandAloneSig = 0x11,
    /// The events of types (II.22.12).
    EventMap = 0x12,
    /// Indirections to events, of unoptimized metadata.
    EventPtr = 0x13,
    /// Events (II.22.13).
    Event = 0x14,
    /// The properties of types (II.22.35).
    PropertyMap = 0x15,
    /// Indirections to properties, of unoptimized metadata.
    PropertyPtr = 0x16,
    /// Properties (II.22.34).
    Property = 0x17,
    /// The methods of events and properties (II.22.28).
    MethodSemantics = 0x18,
    /// Explicit method implementations (II.22.27).
    MethodImpl = 0x19,
    /// References to modules (II.22.31).
    ModuleRef = 0x1A,
    /// Type signatures (II.22.39).
    TypeSpec = 0x1B,
    /// Platform invoke imports (II.22.22).
    ImplMap = 0x1C,
    /// The initial data of fields (II.22.18).
    FieldRva = 0x1D,
    /// The edit-and-continue log.
    EncLog = 0x1E,
    /// The edit-and-continue token map.
    EncMap = 0x1F,
    /// The assembly manifest (II.22.2).
    Assembly = 0x20,
    /// Assembly processors; not used (II.22.4).
    AssemblyProcessor = 0x21,
    /// Assembly operating systems; not used (II.22.3).
    AssemblyOs = 0x22,
    /// References to assemblies (II.22.5).
    AssemblyRef = 0x23,
    /// Processors of referenced assemblies; not used (II.22.7).
    AssemblyRefProcessor = 0x24,
    /// Operating systems of referenced assemblies; not used (II.22.6).
    AssemblyRefOs = 0x25,
    /// The files of the assembly (II.22.19).
    File = 0x26,
    /// Exported and forwarded types (II.22.14).
    ExportedType = 0x27,
    /// Manifest resources (II.22.24).
    ManifestResource = 0x28,
    /// Nested types (II.22.32).
    NestedClass = 0x29,
    /// Generic parameters (II.22.20).
    GenericParam = 0x2A,
    /// Generic method instantiations (II.22.29).
    MethodSpec = 0x2B,
    /// Generic parameter constraints (II.22.21).
    GenericParamConstraint = 0x2C,
    /// Source documents (portable PDB).
    Document = 0x30,
    /// Sequence points of methods (portable PDB).
    MethodDebugInformation = 0x31,
    /// Scopes of locals (portable PDB).
    LocalScope = 0x32,
    /// Local variables (portable PDB).
    LocalVariable = 0x33,
    /// Local constants (portable PDB).
    LocalConstant = 0x34,
    /// Namespace import scopes (portable PDB).
    ImportScope = 0x35,
    /// State machine kickoff methods (portable PDB).
    StateMachineMethod = 0x36,
    /// Custom debug information (portable PDB).
    CustomDebugInformation = 0x37,
}

/// A metadata token: the table (or `0x70` for a user string) in the high
/// byte and a 1-based row index (or a heap offset) in the low 24 bits.
///
/// A coded index decodes to a token. Its row can be zero, which is a null
/// reference; the table of a null coded index is the table of its tag.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Token(pub u32);

impl Token {
    /// The null token (table `Module`, row 0).
    pub const NULL: Self = Self(0);

    /// Makes a token from a table and a 1-based row. Only the low 24 bits
    /// of `row` are kept.
    #[must_use]
    pub const fn new(table: TableId, row: u32) -> Self {
        Self(((table as u32) << 24) | (row & 0x00FF_FFFF))
    }

    /// Makes the token of the user string at `offset` of the `#US` heap.
    #[must_use]
    pub const fn user_string(offset: u32) -> Self {
        Self(((USER_STRING_TOKEN_TYPE as u32) << 24) | (offset & 0x00FF_FFFF))
    }

    /// Returns the high byte: the table identifier or the token type.
    #[must_use]
    pub const fn token_type(self) -> u8 {
        self.0.to_be_bytes()[0]
    }

    /// Returns the table of the token, or `None` when the high byte is not a
    /// table (a user string token, for example).
    #[must_use]
    pub const fn table(self) -> Option<TableId> {
        TableId::from_u8(self.token_type())
    }

    /// Returns the low 24 bits: the 1-based row or the heap offset.
    #[must_use]
    pub const fn row(self) -> u32 {
        self.0 & 0x00FF_FFFF
    }

    /// Returns `true` when the row is zero.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.row() == 0
    }

    /// Returns `true` for a token of a string of the `#US` heap.
    #[must_use]
    pub const fn is_user_string(self) -> bool {
        self.token_type() == USER_STRING_TOKEN_TYPE
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({:#010x})", self.0)
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

impl From<u32> for Token {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Token> for u32 {
    fn from(token: Token) -> Self {
        token.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_holds_the_table_and_the_row() {
        let token = Token::new(TableId::MethodDef, 0x1234);
        assert_eq!(token.0, 0x0600_1234);
        assert_eq!(token.table(), Some(TableId::MethodDef));
        assert_eq!(token.row(), 0x1234);
        assert!(!token.is_null());
        assert!(Token::new(TableId::TypeDef, 0).is_null());
        let string = Token::user_string(0x10);
        assert!(string.is_user_string());
        assert_eq!(string.table(), None);
        assert_eq!(string.row(), 0x10);
    }

    #[test]
    fn each_table_identifier_maps_back_to_its_table() {
        for &table in TableId::ALL {
            assert_eq!(TableId::from_u8(table as u8), Some(table));
        }
        assert_eq!(TableId::ALL.len(), 53);
        assert_eq!(TableId::from_u8(0x2D), None);
        assert_eq!(
            TableId::CustomDebugInformation.name(),
            "CustomDebugInformation"
        );
    }
}
