//! Metadata that the runtime loads although ECMA-335 does not allow it. Each
//! test builds the sample, breaks it as an obfuscator or an old compiler
//! does, and checks that the reader reads it as the runtime reads it, that the
//! writer writes it back, and that the validator reports it. The comments
//! name the runtime experiment that each test follows.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use clrmeta_model::{TableId, Token};

use crate::error::{Error, HeapKind};
use crate::heaps::{BlobHeap, BlobHeapBuilder, BlobIndex, Guid, StringsHeap, StringsHeapBuilder};
use crate::metadata::Metadata;
use crate::tables::{
    DeclSecurityRow, HEAP_EXTRA_DATA, MethodPtrRow, ModuleRow, NestedClassRow, TypeDefRow,
};
use crate::test_support::sample;
use crate::token::Rid;
use crate::validate::Location;
use crate::write::{MetadataBuilder, StreamSlot};

fn build(change: impl FnOnce(&mut MetadataBuilder)) -> Vec<u8> {
    let mut builder = sample();
    change(&mut builder);
    builder.write().unwrap()
}

/// Copies the metadata with the builder and writes it again.
fn rewrite(bytes: &[u8]) -> Vec<u8> {
    let md = Metadata::parse(bytes).unwrap();
    MetadataBuilder::from_metadata(&md)
        .unwrap()
        .write()
        .unwrap()
}

/// Returns the location and the reason of each problem.
fn problems(md: &Metadata<'_>) -> Vec<(Location, &'static str)> {
    md.validate()
        .into_iter()
        .map(|issue| {
            let reason = match issue.error {
                Error::Malformed { reason, .. } | Error::Column { reason, .. } => reason,
                _ => "",
            };
            (issue.location, reason)
        })
        .collect()
}

fn replace(data: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let at = data.windows(old.len()).position(|w| w == old).unwrap();
    let mut out = data.to_vec();
    out.splice(at..at + old.len(), new.iter().copied());
    out
}

/// Returns a `#Strings` heap of the sample with `Outer` renamed.
fn renamed_strings(builder: &MetadataBuilder, name: &[u8]) -> Vec<u8> {
    replace(builder.strings.as_bytes(), b"Outer\0", name)
}

/// Overwrites a column of a row of written metadata.
fn patch(bytes: &mut [u8], table: TableId, row: u32, column: usize, value: u32) {
    let (at, width) = {
        let md = Metadata::parse(bytes).unwrap();
        let tables = md.stream_selection().tables.unwrap();
        let start = md.root().streams[tables].offset as usize;
        let layout = md.tables().layout().table(table);
        let widths = &layout.widths[..column];
        let before: usize = widths.iter().map(|&w| usize::from(w)).sum();
        let row_start = (row as usize - 1) * layout.row_size as usize;
        let width = usize::from(layout.widths[column]);
        (start + layout.offset + row_start + before, width)
    };
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn outer_name(md: &Metadata<'_>) -> alloc::string::String {
    md.type_name(Token::new(TableId::TypeDef, 2))
        .unwrap()
        .to_string()
}

#[test]
fn the_read_only_reader_takes_the_heaps_after_the_real_heaps() {
    // CoreCLR and .NET Framework print the names of the second #Strings
    // heap when it follows the first and no #Schema stream exists.
    let bytes = build(|builder| {
        let fake = renamed_strings(builder, b"Owned\0");
        builder
            .streams
            .push(StreamSlot::Raw(b"#Strings".to_vec(), fake));
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.stream_selection().strings, Some(5));
    assert_eq!(outer_name(&md), "Ns.Owned");
    assert_eq!(rewrite(&bytes), bytes);
    assert!(problems(&md).contains(&(
        Location::Stream(1),
        "the runtime reads another stream of this name"
    )));
}

#[test]
fn a_schema_stream_makes_the_first_heaps_win() {
    // ConfuserEx adds fake heaps after the real ones and a #Schema stream:
    // the runtime takes its read-write reader, which reads the first heaps.
    let bytes = build(|builder| {
        let fake = renamed_strings(builder, b"Owned\0");
        builder.streams.extend([
            StreamSlot::Raw(b"#GUID".to_vec(), vec![1; 16]),
            StreamSlot::Raw(b"#Strings".to_vec(), fake),
            StreamSlot::Raw(b"#Blob".to_vec(), vec![0; 4]),
            StreamSlot::Raw(b"#Schema".to_vec(), vec![0; 4]),
        ]);
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert!(md.stream_selection().uncompressed);
    assert_eq!(outer_name(&md), "Ns.Outer");
    assert_eq!(rewrite(&bytes), bytes);
    let found = problems(&md);
    assert!(found.contains(&(
        Location::Stream(6),
        "the runtime reads another stream of this name"
    )));
    assert!(
        found
            .iter()
            .any(|(location, _)| *location == Location::Stream(8))
    );
}

#[test]
fn the_uncompressed_reader_matches_names_without_case() {
    // The runtime loads #- metadata whose heap is named #STRINGS.
    let bytes = build(|builder| {
        builder.uncompressed = true;
        let fake = renamed_strings(builder, b"Owned\0");
        builder
            .streams
            .insert(1, StreamSlot::Raw(b"#STRINGS".to_vec(), fake));
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(outer_name(&md), "Ns.Owned");
    // The copy gives the heap its standard name.
    let copy = rewrite(&bytes);
    assert_eq!(outer_name(&Metadata::parse(&copy).unwrap()), "Ns.Owned");
}

#[test]
fn jtd_widens_the_indices_only_in_uncompressed_metadata() {
    // The runtime ignores #JTD next to a #~ stream.
    for uncompressed in [false, true] {
        let bytes = build(|builder| {
            builder.uncompressed = uncompressed;
            builder
                .streams
                .push(StreamSlot::Raw(b"#JTD".to_vec(), Vec::new()));
        });
        let md = Metadata::parse(&bytes).unwrap();
        assert_eq!(md.tables().is_wide(), uncompressed);
        let type_ref = md.tables().layout().table(TableId::TypeRef);
        assert_eq!(type_ref.row_size, if uncompressed { 12 } else { 6 });
        assert_eq!(outer_name(&md), "Ns.Outer");
        assert_eq!(rewrite(&bytes), bytes);
        let ignored = problems(&md).iter().any(|(location, reason)| {
            *location == Location::Stream(5)
                && *reason
                    == "the runtime reads #JTD only in metadata with a #- or a #Schema stream"
        });
        assert_eq!(ignored, !uncompressed);
    }
}

#[test]
fn stream_names_that_are_not_utf8_or_unknown_are_kept() {
    // The runtime loads a module with a stream named "\xFF\xFE\x80junk".
    let bytes = build(|builder| {
        builder.streams.extend([
            StreamSlot::Raw(b"\xFF\xFE\x80junk".to_vec(), vec![1, 2, 3, 4]),
            StreamSlot::Raw(b"#strings".to_vec(), vec![0; 4]),
        ]);
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.root().streams[5].name, b"\xFF\xFE\x80junk");
    assert_eq!(outer_name(&md), "Ns.Outer");
    assert_eq!(rewrite(&bytes), bytes);
    let found = problems(&md);
    for index in [5, 6] {
        assert!(found.contains(&(
            Location::Stream(index),
            "the runtime ignores a stream of this name"
        )));
    }
}

#[test]
fn the_version_field_reads_and_writes_as_stored() {
    // The runtime loads version fields of 13 bytes and of bytes that are
    // not UTF-8.
    for (field, text) in [
        (&b"v4.0.30319\0\0\0"[..], "v4.0.30319"),
        (b"v4\xFF\0", "v4\u{FFFD}"),
    ] {
        let bytes = build(|builder| builder.version = field.to_vec());
        let md = Metadata::parse(&bytes).unwrap();
        assert_eq!(md.version(), text);
        assert_eq!(rewrite(&bytes), bytes);
        assert!(
            problems(&md)
                .iter()
                .any(|(location, _)| *location == Location::Root)
        );
    }
}

#[test]
fn unknown_and_debug_tables_in_the_header_have_no_rows() {
    // The runtime skips the row counts of the valid bits 0x2D, 0x30 and
    // 0x3F, and places no rows for them.
    let bytes = build(|builder| {
        let header = &mut builder.tables_header;
        for (bit, count) in [(0x2D, 5), (0x30, 3), (0x3F, 1)] {
            header.valid |= 1 << bit;
            header.row_counts[bit] = count;
        }
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.tables().row_count(TableId::Document), 0);
    assert_eq!(md.tables().header().row_counts[0x30], 3);
    assert_eq!(md.tables().header().row_counts[0x2D], 5);
    assert_eq!(outer_name(&md), "Ns.Outer");
    assert_eq!(rewrite(&bytes), bytes);
    let found = problems(&md);
    assert!(found.contains(&(
        Location::TablesHeader,
        "the valid mask names tables that the schema does not define; the runtime skips their row counts"
    )));
    assert!(found.contains(&(
        Location::TablesHeader,
        "the valid mask names debug tables in a module; the runtime places no rows for them"
    )));
}

#[test]
fn heap_size_bits_set_the_widths_whatever_the_heaps_hold() {
    // The runtime loads a module with 4-byte heap indices into small heaps,
    // and with the extra data of bit 0x40.
    let bytes = build(|builder| {
        builder.tables_header.heap_sizes = 0x07 | HEAP_EXTRA_DATA;
        builder.tables_header.extra_data = Some(0xDEAD_BEEF);
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.tables().layout().string_width, 4);
    assert_eq!(md.tables().header().extra_data, Some(0xDEAD_BEEF));
    assert_eq!(outer_name(&md), "Ns.Outer");
    assert_eq!(rewrite(&bytes), bytes);
    assert_eq!(
        problems(&md),
        [(
            Location::TablesHeader,
            "the heap size bit 0x40 adds 4 bytes of extra data that ECMA-335 does not define; the runtime skips them"
        )]
    );
}

#[test]
fn a_coded_index_that_is_not_valid_reads_as_the_runtime_reads_it() {
    // ConfuserEx adds a DeclSecurity row whose parent has the unused tag 3
    // and a permission set far outside the heap; the runtime never reads
    // the row.
    let mut bytes = build(|builder| {
        builder.rows.decl_security.push(DeclSecurityRow {
            action: 2,
            parent: Token::new(TableId::TypeDef, 1),
            ..DeclSecurityRow::default()
        });
    });
    patch(&mut bytes, TableId::DeclSecurity, 1, 1, 0x7FFF);
    patch(&mut bytes, TableId::DeclSecurity, 1, 2, 0x7FFF);
    let md = Metadata::parse(&bytes).unwrap();
    let row = md.tables().row(Rid::<DeclSecurityRow>::new(1)).unwrap();
    assert_eq!(row.parent, Token::new(TableId::TypeDef, 0));
    assert!(md.blobs().get(row.permission_set).is_err());
    assert!(md.tables().to_rows().is_ok());
    // The copy writes the token that the runtime reads.
    let copy = rewrite(&bytes);
    let row = Metadata::parse(&copy)
        .unwrap()
        .tables()
        .row(Rid::<DeclSecurityRow>::new(1))
        .unwrap();
    assert_eq!(row.parent, Token::new(TableId::TypeDef, 0));
    let found = problems(&md);
    let column = |column| Location::Column {
        table: TableId::DeclSecurity,
        row: 1,
        column,
    };
    assert!(found.contains(&(
        column("parent"),
        "the coded index has a tag that the column does not use"
    )));
    assert!(
        found
            .iter()
            .any(|(location, _)| *location == column("permission_set"))
    );
}

#[test]
fn names_that_are_not_utf8_read_with_replacement_characters() {
    // The runtime loads a type named "C\xFFrcle"; reflection shows
    // "C\u{FFFD}rcle".
    let bytes = build(|builder| {
        let strings = replace(builder.strings.as_bytes(), b"Outer\0", b"O\xFFter\0");
        let strings = replace(&strings, b"Add\0", b"A\xFFd\0");
        builder.strings = StringsHeapBuilder::from_heap(&StringsHeap::new(&strings));
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(outer_name(&md), "Ns.O\u{FFFD}ter");
    let add = md
        .resolver()
        .method(Token::new(TableId::MethodDef, 2))
        .unwrap();
    assert_eq!(add.name, "A\u{FFFD}d");
    let found = problems(&md);
    let type_name = Location::Column {
        table: TableId::TypeDef,
        row: 2,
        column: "type_name",
    };
    assert!(found.contains(&(type_name, "the string is not UTF-8")));
}

#[test]
fn index_0_of_the_blob_heap_is_empty_whatever_the_heap_holds() {
    // The runtime reads an empty public key for blob 0 when the first byte
    // of the heap is 2.
    let bytes = build(|builder| {
        let mut blobs = builder.blobs.as_bytes().to_vec();
        blobs[0] = 2;
        builder.blobs = BlobHeapBuilder::from_heap(&BlobHeap::new(&blobs));
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.blobs().get(BlobIndex(0)).unwrap(), &[] as &[u8]);
    assert!(md.method_signature(Rid::new(2)).is_ok());
    assert!(problems(&md).contains(&(
        Location::Heap(HeapKind::Blob),
        "the heap does not start with the empty entry; the runtime reads index 0 as empty"
    )));
}

#[test]
fn a_guid_that_ends_after_its_heap_reads_the_next_bytes() {
    // The runtime reads the MVID of a module whose #GUID header says 8
    // bytes from the 16 bytes at the heap.
    let mut bytes = build(|builder| {
        let mvid = builder.guids.add(Guid([7; 16])).unwrap();
        builder.rows.module[0].mvid = mvid;
    });
    let md = Metadata::parse(&bytes).unwrap();
    let guids = md.stream_selection().guids.unwrap();
    let header_end = 16 + md.root().version.len() + 4;
    let names: usize = md.root().streams[..guids]
        .iter()
        .map(|s| 8 + (s.name.len() + 1).next_multiple_of(4))
        .sum();
    let size_at = header_end + names + 4;
    bytes[size_at..size_at + 4].copy_from_slice(&8u32.to_le_bytes());
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.guids().data().len(), 8);
    let module = md.tables().row(Rid::<ModuleRow>::new(1)).unwrap();
    assert_eq!(md.guids().get(module.mvid).unwrap(), Some(Guid([7; 16])));
    assert!(
        problems(&md)
            .iter()
            .any(|(location, _)| *location == Location::Heap(HeapKind::Guid))
    );
    // The copy keeps the bytes after the heap that the MVID ends in.
    assert_eq!(rewrite(&bytes), bytes);
}

#[test]
fn a_nesting_cycle_is_an_error_and_a_deep_chain_is_a_name() {
    // CoreCLR rejects the module whose enclosing types form a cycle; .NET
    // Framework loads it.
    let bytes = build(|builder| {
        builder.rows.nested_class.insert(
            0,
            NestedClassRow {
                nested_class: Rid::new(2),
                enclosing_class: Rid::new(3),
            },
        );
    });
    let md = Metadata::parse(&bytes).unwrap();
    assert!(matches!(
        md.type_name(Token::new(TableId::TypeDef, 3)),
        Err(Error::Token { .. })
    ));
    assert!(problems(&md).iter().any(|(location, _)| *location
        == Location::Column {
            table: TableId::NestedClass,
            row: 1,
            column: "enclosing_class",
        }));
    // A chain of 200 nested types has a name.
    let bytes = build(|builder| {
        let name = builder.strings.add("N").unwrap();
        for row in 5..=204 {
            builder.rows.type_def.push(TypeDefRow {
                type_name: name,
                field_list: Rid::new(4),
                method_list: Rid::new(4),
                ..TypeDefRow::default()
            });
            builder.rows.nested_class.push(NestedClassRow {
                nested_class: Rid::new(row),
                enclosing_class: Rid::new(row - 1),
            });
        }
    });
    let md = Metadata::parse(&bytes).unwrap();
    let name = md.type_name(Token::new(TableId::TypeDef, 204)).unwrap();
    assert_eq!(name.names.len(), 201);
    assert_eq!(name.name(), "N");
}

#[test]
fn a_type_nested_in_a_type_nested_in_module_is_reported() {
    // ConfuserEx nests its types in <Module>, and nests types in those:
    // CoreCLR rejects the module ("Enclosing type(s) not found") and .NET
    // Framework runs it. The names still read.
    let bytes = build(|builder| {
        builder.rows.nested_class.insert(
            0,
            NestedClassRow {
                nested_class: Rid::new(2),
                enclosing_class: Rid::new(1),
            },
        );
    });
    let md = Metadata::parse(&bytes).unwrap();
    let inner = md.type_name(Token::new(TableId::TypeDef, 3)).unwrap();
    assert_eq!(inner.to_string(), "<Module>/Outer/Inner");
    assert!(problems(&md).contains(&(
        Location::Column {
            table: TableId::NestedClass,
            row: 2,
            column: "enclosing_class",
        },
        "the enclosing type is nested in <Module>; CoreCLR rejects the module"
    )));
}

#[test]
fn a_list_that_goes_back_is_empty_and_reported() {
    // The runtime rejects the type whose method list ends before it starts
    // ("File is corrupt"); the reader reads it as empty.
    let bytes = build(|builder| builder.rows.type_def[0].method_list = Rid::new(3));
    let md = Metadata::parse(&bytes).unwrap();
    assert_eq!(md.methods_of(Rid::new(1)).unwrap().count(), 0);
    assert_eq!(md.methods_of(Rid::new(2)).unwrap().count(), 2);
    assert!(problems(&md).contains(&(
        Location::Column {
            table: TableId::TypeDef,
            row: 2,
            column: "method_list",
        },
        "the list starts before the list of the row before"
    )));
}

#[test]
fn the_read_write_reader_reads_a_next_list_start_of_0_as_the_end() {
    // CoreCLR CMiniMdRW::Impl_GetEndRidForColumn: END_OF_TABLE is 0.
    for uncompressed in [false, true] {
        let bytes = build(|builder| {
            builder.uncompressed = uncompressed;
            builder.rows.type_def[2].method_list = Rid::new(0);
        });
        let md = Metadata::parse(&bytes).unwrap();
        let methods: Vec<u32> = md.methods_of(Rid::new(2)).unwrap().map(Rid::row).collect();
        let expected: &[u32] = if uncompressed { &[1, 2, 3] } else { &[] };
        assert_eq!(methods, expected);
        assert_eq!(md.methods_of(Rid::new(3)).unwrap().count(), 0);
    }
}

#[test]
fn extra_rows_and_pointer_tables_are_reported() {
    // ConfuserEx adds a second Module row; the read-only reader of the
    // runtime rejects MethodPtr rows in #~.
    let bytes = build(|builder| {
        builder.rows.module.push(ModuleRow::default());
        builder.rows.method_ptr.push(MethodPtrRow {
            method: Rid::new(1),
        });
    });
    let md = Metadata::parse(&bytes).unwrap();
    let found = problems(&md);
    assert!(found.iter().any(|(location, _)| *location
        == Location::Column {
            table: TableId::Module,
            row: 2,
            column: "generation",
        }));
    assert!(found.contains(&(
        Location::TablesHeader,
        "a #~ stream holds MethodPtr or FieldPtr rows; the read-only reader of the runtime rejects them"
    )));
}
