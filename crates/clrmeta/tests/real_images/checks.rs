//! The checks of one assembly: every table, signature, method body,
//! exception clause, custom attribute and permission set reads without an
//! error, and the metadata writes back to bytes that read the same.

use std::fmt::Write as _;

use clrmeta::custom_attribute::{CustomAttributeValue, EnumIndex, MetadataResolver};
use clrmeta::flags::method_impl_attributes;
use clrmeta::security::PermissionSet;
use clrmeta::signature::{
    FieldSig, MemberSignature, MethodSig, MethodSpecSig, PropertySig, Signature,
    StandAloneSignature, TypeSig,
};
use clrmeta::{
    CustomAttributeRow, DeclSecurityRow, FieldRow, MemberRefRow, Metadata, MetadataBuilder,
    MethodBody, MethodDefRow, MethodSpecRow, PropertyRow, StandAloneSigRow, TableId, Token,
    TypeSpecRow,
};

use crate::pe::PeFile;

/// What the checks counted.
#[derive(Debug, Default)]
pub struct Counts {
    pub rows: u64,
    pub signatures: u64,
    pub bodies: u64,
    pub clauses: u64,
    pub custom_attributes: u64,
    pub permission_sets: u64,
    pub user_strings: u64,
}

/// The problems that the checks found, as text.
#[derive(Default)]
pub struct Problems(Vec<String>);

impl Problems {
    fn add(&mut self, text: String) {
        self.0.push(text);
    }

    /// Returns the count and the first problems, or `None` without one.
    pub fn summary(&self, name: &str) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        let mut report = format!("{name}: {} problems, the first ones:\n", self.0.len());
        for problem in self.0.iter().take(30) {
            let _ = writeln!(report, "  {problem}");
        }
        Some(report)
    }

    pub fn assert_none(&self, name: &str) {
        if let Some(summary) = self.summary(name) {
            panic!("{summary}");
        }
    }
}

/// Checks that a signature parses and encodes back to its blob.
fn signature<S: Signature>(
    blob: &[u8],
    what: &str,
    token: Token,
    problems: &mut Problems,
) -> Option<S> {
    match S::parse(blob) {
        Ok(sig) => {
            match sig.encode() {
                Ok(bytes) if bytes == blob => {}
                Ok(_) => problems.add(format!(
                    "{what} {token}: the signature encodes to other bytes"
                )),
                Err(error) => problems.add(format!("{what} {token}: {error}")),
            }
            Some(sig)
        }
        Err(error) => {
            problems.add(format!("{what} {token}: {error}"));
            None
        }
    }
}

macro_rules! each_row {
    ($md:expr, $row:ty, |$rid:ident, $value:ident| $body:block, $problems:expr) => {
        for item in $md.tables().table::<$row>().iter() {
            match item {
                Ok(($rid, $value)) => $body,
                Err(error) => $problems.add(error.to_string()),
            }
        }
    };
}

/// Checks every signature blob of the tables that hold one.
fn check_signatures(md: &Metadata<'_>, counts: &mut Counts, problems: &mut Problems) {
    let blob = |index| md.blobs().get(index).unwrap_or_default();
    each_row!(
        md,
        FieldRow,
        |rid, row| {
            signature::<FieldSig>(blob(row.signature), "Field", rid.token(), problems);
            counts.signatures += 1;
        },
        problems
    );
    each_row!(
        md,
        MethodDefRow,
        |rid, row| {
            signature::<MethodSig>(blob(row.signature), "MethodDef", rid.token(), problems);
            counts.signatures += 1;
        },
        problems
    );
    each_row!(
        md,
        MemberRefRow,
        |rid, row| {
            signature::<MemberSignature>(blob(row.signature), "MemberRef", rid.token(), problems);
            counts.signatures += 1;
        },
        problems
    );
    each_row!(
        md,
        StandAloneSigRow,
        |rid, row| {
            signature::<StandAloneSignature>(
                blob(row.signature),
                "StandAloneSig",
                rid.token(),
                problems,
            );
            counts.signatures += 1;
        },
        problems
    );
    each_row!(
        md,
        PropertyRow,
        |rid, row| {
            signature::<PropertySig>(blob(row.signature), "Property", rid.token(), problems);
            counts.signatures += 1;
        },
        problems
    );
    each_row!(
        md,
        TypeSpecRow,
        |rid, row| {
            signature::<TypeSig>(blob(row.signature), "TypeSpec", rid.token(), problems);
            counts.signatures += 1;
        },
        problems
    );
    each_row!(
        md,
        MethodSpecRow,
        |rid, row| {
            signature::<MethodSpecSig>(
                blob(row.instantiation),
                "MethodSpec",
                rid.token(),
                problems,
            );
            counts.signatures += 1;
        },
        problems
    );
}

/// Checks every IL method body, its clauses and its locals.
fn check_bodies(pe: &PeFile, md: &Metadata<'_>, counts: &mut Counts, problems: &mut Problems) {
    each_row!(
        md,
        MethodDefRow,
        |rid, row| {
            let il = row.impl_flags & method_impl_attributes::CODE_TYPE_MASK
                == method_impl_attributes::IL;
            if row.rva == 0 || !il {
                continue;
            }
            let body = match md.method_body(rid, |rva, len| pe.read(rva, len)) {
                Ok(Some(body)) => body,
                Ok(None) => continue,
                Err(error) => {
                    problems.add(format!("body of {}: {error}", rid.token()));
                    continue;
                }
            };
            counts.bodies += 1;
            counts.clauses += body.clauses.len() as u64;
            for clause in &body.clauses {
                let code = u32::try_from(body.code.len()).unwrap_or(u32::MAX);
                if clause.try_range.end > code || clause.handler_range.end > code {
                    problems.add(format!(
                        "body of {}: a clause is outside the code",
                        rid.token()
                    ));
                }
            }
            if let Err(error) = md.locals_of(&body) {
                problems.add(format!("locals of {}: {error}", rid.token()));
            }
            for error in body.validate_at(row.rva) {
                problems.add(format!("body of {}: {error}", rid.token()));
            }
            let original = pe.read(row.rva, body.size).unwrap_or_default();
            match body.encode() {
                Ok(bytes) if bytes == original => {}
                Ok(_) => problems.add(format!("body of {}: encodes to other bytes", rid.token())),
                Err(error) => problems.add(format!("body of {}: {error}", rid.token())),
            }
            if MethodBody::parse(original).as_ref() != Ok(&body) {
                problems.add(format!(
                    "body of {}: parse and at_rva disagree",
                    rid.token()
                ));
            }
        },
        problems
    );
}

/// Checks the custom attributes and the permission sets with a resolver
/// over an enum index.
fn check_attributes(
    md: &Metadata<'_>,
    index: &EnumIndex,
    counts: &mut Counts,
    problems: &mut Problems,
) {
    let resolver = MetadataResolver::new(md, index);
    each_row!(
        md,
        CustomAttributeRow,
        |rid, row| {
            counts.custom_attributes += 1;
            let result = md.resolver().method(row.attribute_type).and_then(|ctor| {
                let blob = md.blobs().get(row.value)?;
                let value = CustomAttributeValue::parse(blob, &ctor.signature, &resolver)?;
                Ok((blob, value.encode()?))
            });
            match result {
                Ok((blob, bytes)) if bytes == blob => {}
                Ok(_) => problems.add(format!("attribute {}: encodes to other bytes", rid.token())),
                Err(error) => problems.add(format!("attribute {}: {error}", rid.token())),
            }
        },
        problems
    );
    each_row!(
        md,
        DeclSecurityRow,
        |rid, row| {
            counts.permission_sets += 1;
            let result = md
                .blobs()
                .get(row.permission_set)
                .and_then(|blob| Ok((blob, PermissionSet::parse(blob, &resolver)?.encode()?)));
            match result {
                Ok((blob, bytes)) if bytes == blob => {}
                Ok(_) => problems.add(format!(
                    "permission set {}: encodes to other bytes",
                    rid.token()
                )),
                Err(error) => problems.add(format!("permission set {}: {error}", rid.token())),
            }
        },
        problems
    );
}

/// Checks that each member token resolves as exactly one kind, each type
/// has a name, and each user string reads by its token.
fn check_resolution(md: &Metadata<'_>, counts: &mut Counts, problems: &mut Problems) {
    let resolver = md.resolver();
    for &table in &[
        TableId::MethodDef,
        TableId::MemberRef,
        TableId::MethodSpec,
        TableId::Field,
    ] {
        for row in 1..=md.tables().row_count(table) {
            let token = Token::new(table, row);
            let method = resolver.method(token).is_ok();
            let field = resolver.field(token).is_ok();
            if method == field {
                problems.add(format!(
                    "{token}: resolves as a method {method}, as a field {field}"
                ));
            }
        }
    }
    for &table in &[TableId::TypeDef, TableId::TypeRef] {
        for row in 1..=md.tables().row_count(table) {
            if let Err(error) = md.type_name(Token::new(table, row)) {
                problems.add(format!("name of {}: {error}", Token::new(table, row)));
            }
        }
    }
    for (offset, _) in md.user_strings().iter().skip(1) {
        counts.user_strings += 1;
        if let Err(error) = resolver.user_string(Token::user_string(offset)) {
            problems.add(format!("user string {offset:#x}: {error}"));
        }
    }
}

/// Checks that the metadata writes to the same bytes and reads back the
/// same rows.
fn check_round_trip(md: &Metadata<'_>, problems: &mut Problems) {
    let written = match MetadataBuilder::from_metadata(md).and_then(|b| b.write()) {
        Ok(bytes) => bytes,
        Err(error) => return problems.add(format!("write: {error}")),
    };
    let copy = match Metadata::parse(&written) {
        Ok(copy) => copy,
        Err(error) => return problems.add(format!("read of the written metadata: {error}")),
    };
    if copy.tables().to_rows().ok() != md.tables().to_rows().ok() {
        problems.add("the written metadata has other rows".to_string());
    }
    let heaps_equal = copy.strings().data() == md.strings().data()
        && copy.blobs().data() == md.blobs().data()
        && copy.guids().data() == md.guids().data()
        && copy.user_strings().data() == md.user_strings().data();
    if !heaps_equal {
        problems.add("the written metadata has other heaps".to_string());
    }
    if !copy.validate().is_empty() {
        problems.add("the written metadata does not validate".to_string());
    }
    if written.as_slice() != md.data() {
        problems.add(format!(
            "the written metadata ({} bytes) differs from the original ({} bytes)",
            written.len(),
            md.data().len()
        ));
    }
}

/// Runs every check on an assembly. `index` answers the enum questions of
/// the custom attributes.
pub fn check(pe: &PeFile, md: &Metadata<'_>, index: &EnumIndex) -> (Counts, Problems) {
    let mut counts = Counts::default();
    let mut problems = Problems::default();
    match md.tables().to_rows() {
        Ok(_) => {
            counts.rows = TableId::ALL
                .iter()
                .map(|&t| u64::from(md.tables().row_count(t)))
                .sum();
        }
        Err(error) => problems.add(format!("rows: {error}")),
    }
    for issue in md.validate() {
        problems.add(format!("validate: {:?}: {}", issue.location, issue.error));
    }
    check_signatures(md, &mut counts, &mut problems);
    check_bodies(pe, md, &mut counts, &mut problems);
    check_attributes(md, index, &mut counts, &mut problems);
    check_resolution(md, &mut counts, &mut problems);
    check_round_trip(md, &mut problems);
    (counts, problems)
}
