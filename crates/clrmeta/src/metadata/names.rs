//! The names of types, with their namespace and their enclosing types.

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use crate::error::{Error, Result};
use crate::metadata::Metadata;
use crate::tables::{TableId, TypeDefRow, TypeRefRow};
use crate::token::{Rid, Token};

/// The name of a type definition or reference.
///
/// A name that is not UTF-8 holds U+FFFD for each sequence of bytes that is
/// not UTF-8, as reflection shows it; the runtime loads such a type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeName<'a> {
    /// The namespace of the outermost type.
    pub namespace: Cow<'a, str>,
    /// The names from the outermost type to the type itself.
    pub names: Vec<Cow<'a, str>>,
}

impl TypeName<'_> {
    /// Returns the simple name of the type.
    #[must_use]
    pub fn name(&self) -> &str {
        self.names.last().map_or("", |name| name)
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
    /// A chain of enclosing types that comes back to a type is a cycle. The
    /// runtime rejects a module whose enclosing types form a cycle when it
    /// loads the module (`CoreCLR` `ClassLoader::PopulateAvailableClassHashTable`),
    /// and .NET Framework loads it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Token`] for a token of another table (a `TypeSpec`
    /// has a signature, not a name), and an error when a row or a string is
    /// not valid or the nesting forms a cycle.
    pub fn type_name(&self, token: Token) -> Result<TypeName<'a>> {
        let tables = self.tables();
        let mut names = Vec::new();
        // Brent's cycle detection: `saved` jumps to the current type after
        // 1, 2, 4, … steps, and a chain that meets `saved` again is a cycle.
        // The check takes time linear in the length of the chain.
        let (mut saved, mut power, mut steps) = (token, 1_usize, 0_usize);
        let mut current = token;
        loop {
            let (namespace, name, outer) = match current.table() {
                Some(TableId::TypeDef) => {
                    let rid = Rid::<TypeDefRow>::new(current.row());
                    let row = tables.row(rid)?;
                    let outer = self.enclosing_type(rid)?.map(Rid::token);
                    (row.type_namespace, row.type_name, outer)
                }
                Some(TableId::TypeRef) => {
                    let row = tables.row(Rid::<TypeRefRow>::new(current.row()))?;
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
            names.push(self.strings().get_lossy(name)?);
            if let Some(next) = outer {
                if next == saved {
                    return Err(Error::Token {
                        token,
                        reason: "the enclosing types form a cycle",
                    });
                }
                steps += 1;
                if steps == power {
                    (saved, power, steps) = (next, power.saturating_mul(2), 0);
                }
                current = next;
            } else {
                names.reverse();
                return Ok(TypeName {
                    namespace: self.strings().get_lossy(namespace)?,
                    names,
                });
            }
        }
    }
}
