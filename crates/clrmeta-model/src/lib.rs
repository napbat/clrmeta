//! Owned data types of ECMA-335 CLI metadata: tokens, table identifiers,
//! signatures and exception handling clauses.
//!
//! The crate holds data only. It reads no bytes, so a consumer that receives
//! these values from another process (a plugin, for example) does not need a
//! metadata parser. The `clrmeta` crate parses the values from metadata and
//! method bodies and writes them back. The `serde` feature derives
//! `Serialize` and `Deserialize` for every type.
//!
//! ```
//! use clrmeta_model::{MethodSig, TableId, Token, TypeSig};
//!
//! let token = Token::new(TableId::MethodDef, 7);
//! assert_eq!(token.0, 0x0600_0007);
//!
//! let sig = MethodSig {
//!     calling_convention: clrmeta_model::calling_convention::HAS_THIS,
//!     generic_param_count: 0,
//!     return_type: TypeSig::Void,
//!     params: vec![TypeSig::I4],
//!     sentinel: None,
//! };
//! assert_eq!(sig.stack_argument_count(), 2);
//! ```

#![no_std]

extern crate alloc;

mod body;
pub mod context;
mod signature;
mod token;

pub use body::{ExceptionClause, ExceptionClauseKind};
pub use signature::{
    ArrayShape, FieldSig, LocalSig, MethodSig, MethodSpecSig, PropertySig, TypeSig,
    calling_convention, element_type,
};
pub use token::{TableId, Token, USER_STRING_TOKEN_TYPE};
