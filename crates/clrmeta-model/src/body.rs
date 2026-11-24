//! Exception handling clauses of method bodies (ECMA-335 II.25.4.6).

use core::ops::Range;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::token::Token;

/// The kind of an exception handling clause and its operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExceptionClauseKind {
    /// A typed handler: the `TypeDef`, `TypeRef` or `TypeSpec` token of the
    /// exception type.
    Catch(Token),
    /// A filter handler: the offset of the filter code in the method body.
    /// The filter code ends where the handler starts.
    Filter(u32),
    /// A `finally` handler.
    Finally,
    /// A `fault` handler.
    Fault,
}

impl ExceptionClauseKind {
    /// The flag of a typed handler.
    pub const FLAG_EXCEPTION: u32 = 0x0000;
    /// The flag of a filter handler.
    pub const FLAG_FILTER: u32 = 0x0001;
    /// The flag of a `finally` handler.
    pub const FLAG_FINALLY: u32 = 0x0002;
    /// The flag of a `fault` handler.
    pub const FLAG_FAULT: u32 = 0x0004;

    /// Returns the clause flags of the kind.
    #[must_use]
    pub const fn flags(self) -> u32 {
        match self {
            Self::Catch(_) => Self::FLAG_EXCEPTION,
            Self::Filter(_) => Self::FLAG_FILTER,
            Self::Finally => Self::FLAG_FINALLY,
            Self::Fault => Self::FLAG_FAULT,
        }
    }
}

/// An exception handling clause. The ranges are byte offsets in the code of
/// the method body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExceptionClause {
    /// The kind of handler.
    pub kind: ExceptionClauseKind,
    /// The protected block.
    pub try_range: Range<u32>,
    /// The handler block.
    pub handler_range: Range<u32>,
}

impl ExceptionClause {
    /// Returns the range of the filter code of a filter clause: from the
    /// filter offset to the start of the handler.
    #[must_use]
    pub fn filter_range(&self) -> Option<Range<u32>> {
        match self.kind {
            ExceptionClauseKind::Filter(start) => Some(start..self.handler_range.start),
            _ => None,
        }
    }
}
