//! A zero-copy reader and a writer of ECMA-335 CLI metadata.
//!
//! The crate reads the metadata of a .NET module from bytes: the root, the
//! streams, the heaps, every table of Partition II (the `Ptr` and
//! edit-and-continue tables and the portable PDB tables included), the
//! signatures, custom attribute values, marshalling descriptors, permission
//! sets and method bodies. It does not read PE files: the caller gives the
//! metadata bytes that the CLI header names, and a closure that returns the
//! bytes at a relative virtual address for method bodies.
//!
//! The reader borrows from the input. Every read is checked; a malformed
//! file returns an [`Error`] that names the structure, the row or the
//! offset, never a panic. [`MetadataBuilder`] writes metadata back.
//!
//! The reader reads what the .NET runtime reads and ignores what it
//! ignores, so it reads the files of obfuscators that the runtime loads:
//! duplicate and unknown streams, names that are not UTF-8, unknown tables
//! in the header, coded indices that are not valid in rows that nothing
//! reads, and method bodies with unusual sections. [`Metadata::validate`]
//! and [`MethodBody::validate`] report what ECMA-335 does not allow.
//!
//! ```
//! use clrmeta::{Metadata, MetadataBuilder, TypeDefRow};
//!
//! let mut builder = MetadataBuilder::new("v4.0.30319");
//! let name = builder.strings.add("Program").unwrap();
//! builder.rows.type_def.push(TypeDefRow {
//!     type_name: name,
//!     ..TypeDefRow::default()
//! });
//! let bytes = builder.write().unwrap();
//!
//! let metadata = Metadata::parse(&bytes).unwrap();
//! let types = metadata.tables().table::<TypeDefRow>();
//! for row in &types {
//!     let (rid, row) = row.unwrap();
//!     let name = metadata.type_name(rid.token()).unwrap();
//!     assert_eq!(name.to_string(), "Program");
//!     assert_eq!(metadata.strings().get(row.type_name).unwrap(), "Program");
//! }
//! ```
//!
//! The owned data types (tokens, table identifiers, signatures and
//! exception clauses) come from the `clrmeta-model` crate, which a consumer
//! can use alone.

#![no_std]

extern crate alloc;

pub mod body;
mod bytes;
pub mod custom_attribute;
pub mod error;
pub mod flags;
pub mod heaps;
pub mod marshal;
mod metadata;
pub mod pdb;
pub mod public_key;
mod resolve;
pub mod root;
pub mod security;
pub mod signature;
pub mod tables;
mod token;
mod validate;
mod write;

#[cfg(test)]
mod test_support;

pub use body::{ExceptionClause, ExceptionClauseKind, MethodBody};
pub use clrmeta_model as model;
pub use error::{Error, HeapKind, Result};
pub use heaps::{BlobIndex, GuidIndex, StringIndex};
pub use metadata::{Metadata, RowList, TypeName};
pub use resolve::{FieldRef, Member, MethodRef, Resolver, TypeRef};
pub use signature::Signature;
pub use tables::*;
pub use token::{Rid, Token, USER_STRING_TOKEN_TYPE};
pub use validate::{Issue, Location};
pub use write::{DEFAULT_SORTED, MetadataBuilder, MethodRenumbering, RowReference, StreamSlot};
