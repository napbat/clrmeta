//! Signature blobs (ECMA-335 II.23.2): parsing to the owned types of
//! `clrmeta-model` and encoding back.

use alloc::vec::Vec;

pub use clrmeta_model::{
    ArrayShape, FieldSig, LocalSig, MethodSig, MethodSpecSig, PropertySig, TypeSig,
    calling_convention, element_type,
};

use crate::error::Result;

mod decode;
mod encode;

pub(crate) use decode::SigReader;
pub(crate) use encode::SigWriter;

/// A signature that parses from a blob and encodes to a blob.
pub trait Signature: Sized {
    /// Parses a whole blob.
    ///
    /// # Errors
    ///
    /// Returns an error when the blob is not a valid signature of this kind
    /// or bytes follow its end.
    fn parse(blob: &[u8]) -> Result<Self>;

    /// Encodes the signature. Compressed integers take their shortest form.
    ///
    /// # Errors
    ///
    /// Returns an error when a value does not fit its encoding or a token
    /// names a table that the encoding cannot hold.
    fn encode(&self) -> Result<Vec<u8>>;
}

macro_rules! signature {
    ($ty:ty, $read:ident, $write:ident) => {
        impl Signature for $ty {
            fn parse(blob: &[u8]) -> Result<Self> {
                let mut reader = SigReader::new(blob);
                let sig = reader.$read()?;
                reader.finish()?;
                Ok(sig)
            }

            fn encode(&self) -> Result<Vec<u8>> {
                let mut writer = SigWriter::new();
                writer.$write(self)?;
                Ok(writer.out)
            }
        }
    };
}

signature!(TypeSig, type_sig, type_sig);
signature!(MethodSig, method_sig, method_sig);
signature!(FieldSig, field_sig, field_sig);
signature!(PropertySig, property_sig, property_sig);
signature!(LocalSig, local_sig, local_sig);
signature!(MethodSpecSig, method_spec_sig, method_spec_sig);

/// The signature of a `StandAloneSig` row: the locals of a method body, the
/// call site of `calli`, or (rarely, from debuggers) a field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StandAloneSignature {
    /// A local variable signature.
    Locals(LocalSig),
    /// A method signature of a call site.
    Method(MethodSig),
    /// A field signature.
    Field(FieldSig),
}

impl Signature for StandAloneSignature {
    fn parse(blob: &[u8]) -> Result<Self> {
        match blob.first().map(|b| b & calling_convention::KIND_MASK) {
            Some(calling_convention::LOCAL_SIG) => LocalSig::parse(blob).map(Self::Locals),
            Some(calling_convention::FIELD) => FieldSig::parse(blob).map(Self::Field),
            _ => MethodSig::parse(blob).map(Self::Method),
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Locals(sig) => sig.encode(),
            Self::Method(sig) => sig.encode(),
            Self::Field(sig) => sig.encode(),
        }
    }
}

/// The signature of a `MemberRef` row: a method or a field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MemberSignature {
    /// A method signature.
    Method(MethodSig),
    /// A field signature.
    Field(FieldSig),
}

impl Signature for MemberSignature {
    fn parse(blob: &[u8]) -> Result<Self> {
        if blob.first() == Some(&calling_convention::FIELD) {
            FieldSig::parse(blob).map(Self::Field)
        } else {
            MethodSig::parse(blob).map(Self::Method)
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Method(sig) => sig.encode(),
            Self::Field(sig) => sig.encode(),
        }
    }
}

#[cfg(test)]
mod tests;
