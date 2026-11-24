//! Metadata tokens and typed row indices.

use core::fmt;
use core::marker::PhantomData;

pub use clrmeta_model::{Token, USER_STRING_TOKEN_TYPE};

use crate::tables::TableRow;

/// A 1-based row index into the table of the row type `R`.
///
/// The type parameter makes an index of one table different from an index
/// of another table. Row 0 is the null index.
pub struct Rid<R> {
    row: u32,
    table: PhantomData<fn() -> R>,
}

impl<R> Rid<R> {
    /// Makes an index of row `row`.
    #[must_use]
    pub const fn new(row: u32) -> Self {
        Self {
            row,
            table: PhantomData,
        }
    }

    /// Returns the 1-based row.
    #[must_use]
    pub const fn row(self) -> u32 {
        self.row
    }

    /// Returns `true` when the row is zero.
    #[must_use]
    pub const fn is_null(self) -> bool {
        self.row == 0
    }
}

impl<R: TableRow> Rid<R> {
    /// Returns the token of the row.
    #[must_use]
    pub const fn token(self) -> Token {
        Token::new(R::TABLE, self.row)
    }

    /// Returns the index of the row of `token`, or `None` when the token
    /// names another table.
    #[must_use]
    pub fn from_token(token: Token) -> Option<Self> {
        (token.table() == Some(R::TABLE)).then(|| Self::new(token.row()))
    }
}

impl<R> Clone for Rid<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for Rid<R> {}

impl<R> PartialEq for Rid<R> {
    fn eq(&self, other: &Self) -> bool {
        self.row == other.row
    }
}

impl<R> Eq for Rid<R> {}

impl<R> PartialOrd for Rid<R> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<R> Ord for Rid<R> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.row.cmp(&other.row)
    }
}

impl<R> core::hash::Hash for Rid<R> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.row.hash(state);
    }
}

impl<R> Default for Rid<R> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<R: TableRow> fmt::Debug for Rid<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", R::TABLE.name(), self.row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::{MethodDefRow, TypeDefRow};

    #[test]
    fn a_typed_index_accepts_only_tokens_of_its_table() {
        let rid = Rid::<MethodDefRow>::new(5);
        assert_eq!(rid.token(), Token(0x0600_0005));
        assert_eq!(Rid::<MethodDefRow>::from_token(rid.token()), Some(rid));
        assert_eq!(Rid::<TypeDefRow>::from_token(rid.token()), None);
    }
}
