//! Tests on the obfuscated and malformed assemblies of `fixtures/`.
//!
//! `fixtures/build.py` compiles `fixtures/Sample.cs`, obfuscates it with
//! `ConfuserEx` 1.6.0, and patches it for each quirk. It runs every fixture
//! on the .NET runtime and on .NET Framework and checks its output
//! (`fixtures/runs.txt`),
//! so these tests check that the reader reads what the runtime reads.

#[path = "../support/exercise.rs"]
mod exercise;
#[path = "../support/pe.rs"]
mod pe;

use std::path::Path;

use clrmeta::body::DataSection;
use clrmeta::{
    ConstantRow, DeclSecurityRow, Error, ExceptionClauseKind, HeapKind, Issue, Location, Metadata,
    MetadataBuilder, MethodBody, MethodDefRow, Rid, TableId, Token,
};

use crate::exercise::{Rng, exercise, exercise_body, mutate};
use crate::pe::PeFile;

const FIXTURES: [&str; 14] = [
    "sample.exe",
    "confuserex-invalid-metadata.exe",
    "confuserex-anti-tamper.exe",
    "confuserex-maximum.exe",
    "heaps-after.exe",
    "heaps-schema.exe",
    "heaps-dash-case.exe",
    "stream-names.exe",
    "header-quirks.exe",
    "version-non-utf8.exe",
    "names.exe",
    "rows.exe",
    "bodies.exe",
    "bodies-hidden-eh.exe",
];

fn fixture(name: &str) -> PeFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/obfuscated/fixtures")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    PeFile::parse(bytes).unwrap_or_else(|| panic!("{name} is not a PE file"))
}

fn metadata(pe: &PeFile) -> Metadata<'_> {
    Metadata::parse(pe.metadata().expect("the fixture has metadata")).unwrap()
}

fn type_names(md: &Metadata<'_>) -> Vec<String> {
    (1..=md.tables().row_count(TableId::TypeDef))
        .filter_map(|row| md.type_name(Token::new(TableId::TypeDef, row)).ok())
        .map(|name| name.to_string())
        .collect()
}

fn reasons(issues: &[Issue]) -> Vec<(Location, &'static str)> {
    issues
        .iter()
        .map(|issue| {
            let reason = match issue.error {
                Error::Malformed { reason, .. } | Error::Column { reason, .. } => reason,
                _ => "",
            };
            (issue.location, reason)
        })
        .collect()
}

/// Checks that the copy of the metadata writes the same bytes.
fn assert_round_trip(md: &Metadata<'_>) {
    let written = MetadataBuilder::from_metadata(md).unwrap().write().unwrap();
    assert_eq!(written, md.data(), "the copy writes other bytes");
}

/// Checks that the copy of the metadata reads back the same rows.
fn assert_same_rows(md: &Metadata<'_>) {
    let written = MetadataBuilder::from_metadata(md).unwrap().write().unwrap();
    let copy = Metadata::parse(&written).unwrap();
    assert_eq!(
        copy.tables().to_rows().unwrap(),
        md.tables().to_rows().unwrap()
    );
}

fn divide<'a>(pe: &'a PeFile, md: &Metadata<'_>) -> MethodBody<'a> {
    let rid = (1..=md.tables().row_count(TableId::MethodDef))
        .map(Rid::<MethodDefRow>::new)
        .find(|&rid| {
            let row = md.tables().row(rid).unwrap();
            md.strings().get_lossy(row.name).unwrap() == "Divide"
        })
        .expect("the sample has Divide");
    md.method_body(rid, |rva, len| pe.read(rva, len))
        .unwrap()
        .expect("Divide has a body")
}

/// Reads every row, type name and method body. Returns the number of bodies
/// that do not read.
fn read_everything(pe: &PeFile, md: &Metadata<'_>) -> usize {
    md.tables().to_rows().unwrap();
    let mut failed = 0;
    for item in &md.tables().table::<MethodDefRow>() {
        let (rid, _) = item.unwrap();
        if md.method_body(rid, |rva, len| pe.read(rva, len)).is_err() {
            failed += 1;
        }
    }
    failed
}

#[test]
fn the_sample_reads_validates_and_writes_back() {
    let pe = fixture("sample.exe");
    let md = metadata(&pe);
    assert_eq!(read_everything(&pe, &md), 0);
    assert!(type_names(&md).contains(&"Fixture.Circle/Unit".to_string()));
    assert_eq!(md.validate(), []);
    let body = divide(&pe, &md);
    assert_eq!(body.clauses.len(), 2);
    assert_eq!(body.validate(), []);
    assert_round_trip(&md);
}

#[test]
fn confuserex_invalid_metadata_reads_the_heaps_that_the_runtime_reads() {
    // ConfuserEx adds fake #GUID, #Strings and #Blob heaps and a #Schema
    // stream: the runtime takes its read-write reader and the first heaps.
    for name in [
        "confuserex-invalid-metadata.exe",
        "confuserex-anti-tamper.exe",
    ] {
        let pe = fixture(name);
        let md = metadata(&pe);
        assert!(md.stream_selection().uncompressed, "{name}");
        assert_eq!(md.stream_selection().strings, Some(1), "{name}");
        assert!(
            type_names(&md).contains(&"Fixture.Circle".to_string()),
            "{name}"
        );
        assert_eq!(md.tables().row_count(TableId::Module), 2);
        let found = reasons(&md.validate());
        assert!(found.contains(&(
            Location::Column {
                table: TableId::DeclSecurity,
                row: 1,
                column: "parent",
            },
            "the coded index has a tag that the column does not use"
        )));
        assert!(
            found
                .iter()
                .any(|(location, _)| *location == Location::Stream(5))
        );
        let permission = md.tables().row(Rid::<DeclSecurityRow>::new(1)).unwrap();
        assert_eq!(permission.parent, Token::new(TableId::TypeDef, 0));
        let failed = read_everything(&pe, &md);
        // Anti-tamper encrypts method bodies; the runtime decrypts them
        // when the module starts.
        assert_eq!(failed > 0, name.contains("anti-tamper"), "{name}");
        assert_same_rows(&md);
    }
}

#[test]
fn confuserex_maximum_reads_and_reports_the_nesting_that_coreclr_rejects() {
    // CoreCLR rejects the module ("Enclosing type(s) not found"); .NET
    // Framework runs it.
    let pe = fixture("confuserex-maximum.exe");
    let md = metadata(&pe);
    md.tables().to_rows().unwrap();
    let found = reasons(&md.validate());
    assert!(found.iter().any(|(location, reason)| matches!(
        location,
        Location::Column {
            table: TableId::NestedClass,
            ..
        }
    ) && reason.contains("CoreCLR rejects")));
    assert_same_rows(&md);
}

#[test]
fn heaps_after_the_real_heaps_win_without_schema() {
    // CoreCLR and .NET Framework print "CHECKSUM", "Cercle" and 9.
    let pe = fixture("heaps-after.exe");
    let md = metadata(&pe);
    let names = type_names(&md);
    assert!(names.contains(&"Fixture.Cercle".to_string()));
    assert!(!names.contains(&"Fixture.Circle".to_string()));
    let checksum = md
        .user_strings()
        .iter()
        .find_map(|(_, s)| s.to_string().ok().filter(|s| s.starts_with("CHECKSUM")));
    assert!(checksum.is_some());
    let green = md.tables().row(Rid::<ConstantRow>::new(2)).unwrap();
    assert_eq!(md.blobs().get(green.value).unwrap(), &[9, 0, 0, 0]);
    assert_eq!(read_everything(&pe, &md), 0);
    let found = reasons(&md.validate());
    for index in 1..=4 {
        assert!(found.contains(&(
            Location::Stream(index),
            "the runtime reads another stream of this name"
        )));
    }
    assert_round_trip(&md);
}

#[test]
fn a_schema_stream_or_a_dash_stream_makes_the_first_heap_win_without_case() {
    // With #Schema the runtime prints "Circle"; in #- metadata it takes a
    // first heap named #STRINGS and prints "Cercle".
    for (name, expected) in [
        ("heaps-schema.exe", "Fixture.Circle"),
        ("heaps-dash-case.exe", "Fixture.Cercle"),
    ] {
        let pe = fixture(name);
        let md = metadata(&pe);
        assert!(md.stream_selection().uncompressed);
        assert!(type_names(&md).contains(&expected.to_string()), "{name}");
        assert_eq!(read_everything(&pe, &md), 0);
        assert_same_rows(&md);
    }
    assert_round_trip(&metadata(&fixture("heaps-schema.exe")));
}

#[test]
fn unknown_stream_names_and_header_quirks_read() {
    // The runtime ignores streams named "\xFF\xFE\x80junk" and "#strings",
    // and #JTD next to #~; it skips the extra data and unknown tables.
    let pe = fixture("stream-names.exe");
    let md = metadata(&pe);
    assert_eq!(md.root().streams[5].name, b"\xFF\xFE\x80junk");
    assert!(!md.tables().is_wide());
    assert!(type_names(&md).contains(&"Fixture.Circle".to_string()));
    let found = reasons(&md.validate());
    for index in [5, 6] {
        assert!(found.contains(&(
            Location::Stream(index),
            "the runtime ignores a stream of this name"
        )));
    }
    assert_round_trip(&md);

    let pe = fixture("header-quirks.exe");
    let md = metadata(&pe);
    assert_eq!(md.version(), "v4.0.30319");
    assert_eq!(md.root().version.len(), 13);
    let header = md.tables().header();
    assert_eq!(header.extra_data, Some(0x1A2B_3C4D));
    assert_eq!(header.row_counts[0x30], 3);
    assert_eq!(md.tables().row_count(TableId::Document), 0);
    assert_eq!(md.tables().layout().blob_width, 4);
    assert_eq!(read_everything(&pe, &md), 0);
    let found = reasons(&md.validate());
    assert!(
        found
            .iter()
            .any(|(location, _)| *location == Location::Root)
    );
    assert!(
        found
            .iter()
            .filter(|(location, _)| *location == Location::TablesHeader)
            .count()
            >= 3
    );
    assert_round_trip(&md);

    let pe = fixture("version-non-utf8.exe");
    let md = metadata(&pe);
    assert_eq!(md.version(), "v4.0.30319\u{FFFD}\u{FFFD}");
    assert_round_trip(&md);
}

#[test]
fn names_blobs_and_guids_read_as_the_runtime_reads_them() {
    // The runtime shows "C\u{FFFD}rcle", reads an empty public key from
    // blob 0, and reads the MVID past a #GUID heap of 8 bytes.
    let pe = fixture("names.exe");
    let md = metadata(&pe);
    assert!(type_names(&md).contains(&"Fixture.C\u{FFFD}rcle".to_string()));
    assert_eq!(md.blobs().get(clrmeta::BlobIndex(0)).unwrap(), &[] as &[u8]);
    assert_eq!(md.guids().data().len(), 8);
    let module = md.tables().row(Rid::<clrmeta::ModuleRow>::new(1)).unwrap();
    assert!(md.guids().get(module.mvid).unwrap().is_some());
    assert_eq!(read_everything(&pe, &md), 0);
    let found = reasons(&md.validate());
    for heap in [HeapKind::Blob, HeapKind::Guid] {
        assert!(
            found
                .iter()
                .any(|(location, _)| *location == Location::Heap(heap))
        );
    }
    assert_round_trip(&md);
}

#[test]
fn junk_rows_read_and_are_reported() {
    let pe = fixture("rows.exe");
    let md = metadata(&pe);
    assert_eq!(md.tables().row_count(TableId::Module), 2);
    assert_eq!(md.tables().row_count(TableId::EncLog), 2);
    let permission = md.tables().row(Rid::<DeclSecurityRow>::new(1)).unwrap();
    assert_eq!(permission.parent, Token::new(TableId::TypeDef, 0));
    assert!(md.blobs().get(permission.permission_set).is_err());
    assert_eq!(read_everything(&pe, &md), 0);
    let found = reasons(&md.validate());
    assert!(found.iter().any(|(location, _)| *location
        == Location::Column {
            table: TableId::Module,
            row: 2,
            column: "generation",
        }));
    assert_same_rows(&md);
}

#[test]
fn method_bodies_read_as_the_runtime_reads_them() {
    // The runtime runs Divide with a header of 4 dwords, the flags 0x900, a
    // DataSize without its header, a catch with the flag 0x8 and an unknown
    // section after the clauses.
    let pe = fixture("bodies.exe");
    let md = metadata(&pe);
    let body = divide(&pe, &md);
    assert_eq!(body.header_size, 16);
    assert_eq!(body.clauses.len(), 2);
    assert!(matches!(
        body.clauses[0].kind,
        ExceptionClauseKind::Catch(token) if token.table() == Some(TableId::TypeRef)
    ));
    assert_eq!(body.clauses[1].kind, ExceptionClauseKind::Finally);
    assert!(matches!(
        body.sections[..],
        [
            DataSection::ExceptionClauses { count: 2, .. },
            DataSection::Other { .. }
        ]
    ));
    assert_eq!(body.validate().len(), 5);
    // An unknown first section hides the clauses: the exception escapes.
    let pe = fixture("bodies-hidden-eh.exe");
    let md = metadata(&pe);
    let body = divide(&pe, &md);
    assert_eq!(body.clauses, []);
    assert_eq!(body.sections.len(), 2);
}

/// Mutates every fixture and calls every reader API on each mutation: the
/// reader returns errors and never panics.
#[test]
fn mutated_fixtures_never_panic() {
    let mut rng = Rng::new(0x0B5C_0FA7_ED00);
    for name in FIXTURES {
        let pe = fixture(name);
        let bytes = pe.metadata().expect("the fixture has metadata");
        let read = |rva: u32, len: usize| pe.read(rva, len);
        for _ in 0..150 {
            exercise(&mutate(bytes, 1024, &mut rng), read, u32::MAX);
        }
        let md = metadata(&pe);
        for item in &md.tables().table::<MethodDefRow>() {
            let (rid, row) = item.unwrap();
            let Ok(Some(body)) = md.method_body(rid, read) else {
                continue;
            };
            let original = pe.read(row.rva, body.size).unwrap();
            for _ in 0..20 {
                exercise_body(&mutate(original, 16, &mut rng));
            }
        }
    }
}
