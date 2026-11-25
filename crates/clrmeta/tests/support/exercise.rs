//! Mutations of real metadata and method bodies, and a walk over every
//! reader API. A test passes each mutation to [`exercise`]: the reader must
//! return errors for what it cannot read and never panic.

use clrmeta::custom_attribute::{CustomAttributeValue, EnumIndex, MetadataResolver};
use clrmeta::security::PermissionSet;
use clrmeta::{
    CustomAttributeRow, DeclSecurityRow, Metadata, MetadataBuilder, MethodBody, MethodDefRow, Rid,
    TableId, Token, TypeDefRow,
};

/// A small deterministic random number generator (xorshift64*).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Returns a number below `bound`, or 0 for a bound of 0.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            usize::try_from(self.next() % bound as u64).unwrap_or(0)
        }
    }
}

/// Values that make good damage: zeros, ones, the limits of 2-byte and
/// 4-byte indices, and the high bits of tags and lengths.
const INTERESTING: [u32; 10] = [
    0,
    1,
    2,
    0x7F,
    0x7FFF,
    0xFFFF,
    0x1_0000,
    0x00FF_FFFF,
    0x7FFF_FFFF,
    u32::MAX,
];

/// Returns a copy of `data` with 1 to 4 mutations. Half of the mutations
/// hit the first `hot` bytes, where the headers are.
pub fn mutate(data: &[u8], hot: usize, rng: &mut Rng) -> Vec<u8> {
    let mut out = data.to_vec();
    for _ in 0..=rng.below(4) {
        if out.is_empty() {
            break;
        }
        let range = if rng.below(2) == 0 {
            hot.min(out.len())
        } else {
            out.len()
        };
        let at = rng.below(range);
        match rng.below(6) {
            0 => out[at] ^= 1 << rng.below(8),
            1 => out[at] = u8::try_from(rng.below(256)).unwrap_or(0),
            2 => out[at] = [0, 0xFF][rng.below(2)],
            3 => {
                let value = INTERESTING[rng.below(INTERESTING.len())].to_le_bytes();
                let len = [1, 2, 4][rng.below(3)].min(out.len() - at);
                out[at..at + len].copy_from_slice(&value[..len]);
            }
            4 => out.truncate(at),
            _ => {
                let from = rng.below(out.len());
                let len = rng.below(16).min(out.len() - at).min(out.len() - from);
                out.copy_within(from..from + len, at);
            }
        }
    }
    out
}

/// Calls every reader API on `metadata` and on the method bodies that `read`
/// returns, for at most `limit` rows of each table. Errors are expected;
/// a panic fails the test that calls it.
pub fn exercise<'a>(
    metadata: &[u8],
    read: impl Fn(u32, usize) -> Option<&'a [u8]> + Copy,
    limit: u32,
) {
    let Ok(md) = Metadata::parse(metadata) else {
        return;
    };
    let _ = md.version();
    let _ = md.validate();
    let rows = md.tables().to_rows();
    for &table in TableId::ALL {
        for row in 1..=md.tables().row_count(table).min(limit) {
            let _ = md.row(Token::new(table, row));
        }
    }
    let _ = md.strings().iter().count();
    let _ = md.blobs().iter().count();
    let _ = md.user_strings().iter().count();
    for (offset, _) in md.user_strings().iter().take(limit as usize) {
        let _ = md.resolver().user_string(Token::user_string(offset));
    }
    types(&md, limit);
    members(&md, read, limit);
    attributes(&md, limit);
    if rows.is_ok()
        && let Ok(written) = MetadataBuilder::from_metadata(&md).and_then(|b| b.write())
    {
        let copy = Metadata::parse(&written).expect("written metadata reads back");
        assert_eq!(
            copy.tables().to_rows().ok(),
            md.tables().to_rows().ok(),
            "the written metadata has other rows"
        );
    }
}

fn types(md: &Metadata<'_>, limit: u32) {
    for row in 1..=md.tables().row_count(TableId::TypeDef).min(limit) {
        let rid = Rid::<TypeDefRow>::new(row);
        let _ = md.type_name(rid.token());
        let _ = md.fields_of(rid).map(Iterator::count);
        let _ = md.methods_of(rid).map(Iterator::count);
        let _ = md.events_of(rid).map(Iterator::count);
        let _ = md.properties_of(rid).map(Iterator::count);
        let _ = md.enclosing_type(rid);
        let _ = md.nested_types(rid).count();
        let _ = md.interfaces_of(rid).count();
        let _ = md.class_layout_of(rid);
        let _ = md.generic_params_of(rid.token()).map(Iterator::count);
        let _ = md.custom_attributes_of(rid.token()).map(Iterator::count);
    }
    for row in 1..=md.tables().row_count(TableId::TypeRef).min(limit) {
        let _ = md.type_name(Token::new(TableId::TypeRef, row));
    }
    for row in 1..=md.tables().row_count(TableId::TypeSpec).min(limit) {
        let _ = md.resolver().type_ref(Token::new(TableId::TypeSpec, row));
    }
}

fn members<'a>(
    md: &Metadata<'_>,
    read: impl Fn(u32, usize) -> Option<&'a [u8]> + Copy,
    limit: u32,
) {
    let resolver = md.resolver();
    for row in 1..=md.tables().row_count(TableId::MethodDef).min(limit) {
        let rid = Rid::<MethodDefRow>::new(row);
        let _ = resolver.method(rid.token());
        let _ = md.method_signature(rid);
        let _ = md.params_of(rid).map(Iterator::count);
        let _ = md.method_owner(rid);
        if let Ok(Some(body)) = md.method_body(rid, read) {
            let _ = body.validate();
            let _ = md.locals_of(&body);
            let _ = body.encode();
        }
    }
    for table in [
        TableId::Field,
        TableId::MemberRef,
        TableId::MethodSpec,
        TableId::StandAloneSig,
    ] {
        for row in 1..=md.tables().row_count(table).min(limit) {
            let token = Token::new(table, row);
            let _ = resolver.member(token);
            let _ = resolver.field(token);
            let _ = resolver.stand_alone(token);
        }
    }
}

fn attributes(md: &Metadata<'_>, limit: u32) {
    let index = EnumIndex::new(&[md]);
    let resolver = MetadataResolver::new(md, &index);
    let attributes = md.tables().table::<CustomAttributeRow>();
    for item in attributes.iter().take(limit as usize) {
        let Ok((_, row)) = item else { continue };
        let Ok(ctor) = md.resolver().method(row.attribute_type) else {
            continue;
        };
        if let Ok(blob) = md.blobs().get(row.value)
            && let Ok(value) = CustomAttributeValue::parse(blob, &ctor.signature, &resolver)
        {
            let _ = value.encode();
        }
    }
    let permissions = md.tables().table::<DeclSecurityRow>();
    for item in permissions.iter().take(limit as usize) {
        let Ok((_, row)) = item else { continue };
        if let Ok(blob) = md.blobs().get(row.permission_set)
            && let Ok(set) = PermissionSet::parse(blob, &resolver)
        {
            let _ = set.encode();
        }
    }
}

/// Parses a method body from mutated bytes and calls every body API.
pub fn exercise_body(bytes: &[u8]) {
    let read = |rva: u32, len: usize| bytes.get(usize::try_from(rva).ok()?..)?.get(..len);
    let at_rva = MethodBody::at_rva(0, read);
    if let Ok(body) = MethodBody::parse(bytes) {
        let _ = body.validate();
        if let Ok(encoded) = body.encode() {
            let again = MethodBody::parse(&encoded).expect("an encoded body reads back");
            assert_eq!(
                again.clauses, body.clauses,
                "the encoded body has other clauses"
            );
        }
        assert_eq!(
            at_rva.as_ref().ok(),
            Some(&body),
            "parse and at_rva disagree"
        );
    }
}
