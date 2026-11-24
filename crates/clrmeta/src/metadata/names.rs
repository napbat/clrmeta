//! The names of types, with their namespace and their enclosing types.

use alloc::vec::Vec;
use core::fmt;

use crate::error::{Error, Result};
use crate::metadata::Metadata;
use crate::tables::{TableId, TypeDefRow, TypeRefRow};
use crate::token::{Rid, Token};

/// The deepest nesting of types that a name follows. A deeper chain is a
/// cycle in a malformed file.
const MAX_NESTING: usize = 64;

/// The name of a type definition or reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeName<'a> {
    /// The namespace of the outermost type.
    pub namespace: &'a str,
    /// The names from the outermost type to the type itself.
    pub names: Vec<&'a str>,
}

impl<'a> TypeName<'a> {
    /// Returns the simple name of the type.
    #[must_use]
    pub fn name(&self) -> &'a str {
        self.names.last().copied().unwrap_or_default()
    }

    /// Returns `true` for a nested type.
    #[must_use]
    pub fn is_nested(&self) -> bool {
        self.names.len() > 1
    }
}

impl fmt::Display for TypeName<'_> {
    /// Writes the name in the form of `ilasm`: `Namespace.Outer/Inner`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.namespace.is_empty() {
            write!(f, "{}.", self.namespace)?;
        }
        for (position, name) in self.names.iter().enumerate() {
            if position > 0 {
                f.write_str("/")?;
            }
            f.write_str(name)?;
        }
        Ok(())
    }
}

impl<'a> Metadata<'a> {
    /// Returns the name of a `TypeDef` or `TypeRef`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] for a token of another table (a `TypeSpec`
    /// has a signature, not a name), and an error when a row or a string is
    /// not valid or the nesting forms a cycle.
    pub fn type_name(&self, token: Token) -> Result<TypeName<'a>> {
        let mut names = Vec::new();
        let mut current = token;
        loop {
            if names.len() >= MAX_NESTING {
                return Err(Error::Token {
                    token,
                    reason: "the enclosing types form a cycle",
                });
            }
            let (namespace, name, outer) = match current.table() {
                Some(TableId::TypeDef) => {
                    let rid = Rid::<TypeDefRow>::new(current.row());
                    let row = self.tables().row(rid)?;
                    let outer = self.enclosing_type(rid)?.map(Rid::token);
                    (row.type_namespace, row.type_name, outer)
                }
                Some(TableId::TypeRef) => {
                    let row = self.tables().row(Rid::<TypeRefRow>::new(current.row()))?;
                    let scope = row.resolution_scope;
                    let outer = (scope.table() == Some(TableId::TypeRef) && !scope.is_null())
                        .then_some(scope);
                    (row.type_namespace, row.type_name, outer)
                }
                _ => {
                    return Err(Error::Token {
                        token: current,
                        reason: "only a TypeDef or a TypeRef has a name",
                    });
                }
            };
            names.push(self.strings().get(name)?);
            if let Some(next) = outer {
                current = next;
            } else {
                names.reverse();
                return Ok(TypeName {
                    namespace: self.strings().get(namespace)?,
                    names,
                });
            }
        }
    }
}
