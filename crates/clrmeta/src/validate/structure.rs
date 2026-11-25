//! The validation of the root, the stream headers, the header of the tables
//! and the heaps (II.24.2).

use alloc::vec::Vec;

use crate::error::{Error, HeapKind};
use crate::metadata::Metadata;
use crate::root::MAX_STREAM_NAME;
use crate::tables::{HEAP_BLOB_WIDE, HEAP_EXTRA_DATA, HEAP_GUID_WIDE, HEAP_STRINGS_WIDE, TableId};
use crate::validate::{Issue, Location};

/// The names of the streams that the runtime or a portable PDB reader
/// knows.
const KNOWN_STREAMS: [&[u8]; 9] = [
    b"#~",
    b"#-",
    b"#Strings",
    b"#US",
    b"#GUID",
    b"#Blob",
    b"#Pdb",
    b"#JTD",
    b"#Schema",
];

const fn malformed(structure: &'static str, offset: usize, reason: &'static str) -> Error {
    Error::Malformed {
        structure,
        offset,
        reason,
    }
}

impl Metadata<'_> {
    /// Reports the problems of the root, the streams, the header of the
    /// tables and the heaps.
    pub(super) fn validate_structure(&self, issues: &mut Vec<Issue>) {
        let mut report = |location, structure, offset, reason| {
            issues.push(Issue {
                location,
                error: malformed(structure, offset, reason),
            });
        };
        for reason in self.root_problems() {
            report(Location::Root, "metadata root", 0, reason);
        }
        for (index, header) in self.root().streams.iter().enumerate() {
            for reason in self.stream_problems(index) {
                report(
                    Location::Stream(index),
                    "metadata stream",
                    header.offset as usize,
                    reason,
                );
            }
        }
        for reason in self.tables_header_problems() {
            report(Location::TablesHeader, "tables stream", 0, reason);
        }
        for (heap, reason) in self.heap_problems() {
            report(Location::Heap(heap), heap.stream_name(), 0, reason);
        }
    }

    fn root_problems(&self) -> Vec<&'static str> {
        let root = self.root();
        let mut problems = Vec::new();
        if (root.major_version, root.minor_version) != (1, 1) {
            problems.push("the version is not 1.1, which the runtime requires");
        }
        if root.reserved != 0 {
            problems.push("the reserved field is not zero");
        }
        if root.flags != 0 {
            problems.push("the flags are not zero, which the runtime requires");
        }
        let version = root.version_string();
        if version.len() == root.version.len() {
            problems.push("the version field holds no zero byte");
        }
        if !root.version.len().is_multiple_of(4) {
            problems.push(
                "the version field is not a multiple of 4 bytes; the read-write reader of the runtime rejects it",
            );
        }
        if version.len() >= 255 {
            problems.push("the version string with its zero byte is longer than 255 bytes");
        }
        if core::str::from_utf8(version).is_err() {
            problems.push("the version string is not UTF-8");
        }
        problems
    }

    fn stream_problems(&self, index: usize) -> Vec<&'static str> {
        let root = self.root();
        let selection = self.stream_selection();
        let header = root.streams[index];
        let name = header.name;
        let is = |known: &[u8]| {
            if selection.uncompressed {
                name.eq_ignore_ascii_case(known)
            } else {
                name == known
            }
        };
        let mut problems = Vec::new();
        if name.is_empty() {
            problems.push("the stream has no name; the runtime rejects the metadata");
        }
        if name.len() >= MAX_STREAM_NAME {
            problems.push(
                "the name has no zero byte in its first 32 bytes; the runtime rejects the metadata",
            );
        }
        if !header.offset.is_multiple_of(4) || !header.size.is_multiple_of(4) {
            problems.push("the offset or the size of the stream is not a multiple of 4");
        }
        if !KNOWN_STREAMS.iter().any(|known| is(known)) {
            problems.push("the runtime ignores a stream of this name");
        } else if is(b"#Schema") {
            problems.push(
                "ECMA-335 does not define #Schema; it makes the runtime read the metadata with its read-write reader, which takes the first stream of each name",
            );
            let tilde_after = root.streams[index..].iter().any(|s| s.name == b"#~");
            if tilde_after {
                problems.push(
                    "a #Schema stream before the #~ stream makes the runtime reject the metadata",
                );
            }
        } else if is(b"#~") || is(b"#-") {
            let tables = root.streams.iter().filter(|s| {
                let name = s.name;
                if selection.uncompressed {
                    name.eq_ignore_ascii_case(b"#~") || name.eq_ignore_ascii_case(b"#-")
                } else {
                    name == b"#~" || name == b"#-"
                }
            });
            if tables.count() > 1 {
                problems.push("the runtime rejects metadata with two tables streams");
            }
        } else if is(b"#JTD") && !selection.uncompressed {
            problems.push("the runtime reads #JTD only in metadata with a #- or a #Schema stream");
        } else if !selection.is_selected(index) {
            problems.push("the runtime reads another stream of this name");
        }
        problems
    }

    fn tables_header_problems(&self) -> Vec<&'static str> {
        let tables = self.tables();
        let header = tables.header();
        let mut problems = Vec::new();
        // The byte after the heap sizes is 1 in ECMA-335, but the runtime
        // ignores it and the trimmed assemblies of the runtime hold other
        // values, so the validator does not check it.
        if header.reserved != 0 {
            problems.push("the reserved field is not zero");
        }
        match (header.major_version, header.minor_version) {
            (2, 0) => {}
            (1, 0) => {
                let generic = header.valid >> (TableId::GenericParam as u8) != 0;
                if generic {
                    problems.push(
                        "the schema 1.0 has no generic tables; the runtime rejects the metadata",
                    );
                }
            }
            _ => problems.push("the schema version is not 2.0; the runtime rejects it"),
        }
        let width_bits = HEAP_STRINGS_WIDE | HEAP_GUID_WIDE | HEAP_BLOB_WIDE;
        if header.extra_data.is_some() {
            problems.push(
                "the heap size bit 0x40 adds 4 bytes of extra data that ECMA-335 does not define; the runtime skips them",
            );
        }
        if header.heap_sizes & !(width_bits | HEAP_EXTRA_DATA) != 0 {
            problems.push("the heap size flags hold bits that ECMA-335 does not define");
        }
        let defined = TableId::ALL
            .iter()
            .fold(0_u64, |mask, &table| mask | 1 << table as u8);
        if header.valid & !defined != 0 {
            problems.push(
                "the valid mask names tables that the schema does not define; the runtime skips their row counts",
            );
        }
        let debug = TableId::ALL
            .iter()
            .filter(|&&table| table as u8 >= TableId::Document as u8)
            .fold(0_u64, |mask, &table| mask | 1 << table as u8);
        if self.pdb().is_none() && header.valid & debug != 0 {
            problems.push(
                "the valid mask names debug tables in a module; the runtime places no rows for them",
            );
        }
        let ptr = |table: TableId| tables.row_count(table) > 0;
        if !self.stream_selection().uncompressed {
            if ptr(TableId::MethodPtr) || ptr(TableId::FieldPtr) {
                problems.push(
                    "a #~ stream holds MethodPtr or FieldPtr rows; the read-only reader of the runtime rejects them",
                );
            }
            if ptr(TableId::ParamPtr) || ptr(TableId::EventPtr) || ptr(TableId::PropertyPtr) {
                problems.push("a #~ stream holds Ptr rows, which ECMA-335 allows only in #-");
            }
        }
        if header.row_counts.iter().any(|&count| count > 0x00FF_FFFF) {
            problems.push("a table has more rows than a token can name");
        }
        problems
    }

    fn heap_problems(&self) -> Vec<(HeapKind, &'static str)> {
        let heap_sizes = self.tables().header().heap_sizes;
        let mut problems = Vec::new();
        let strings = self.strings().data();
        if strings.first().is_some_and(|&b| b != 0) {
            problems.push((
                HeapKind::Strings,
                "the heap does not start with the empty string",
            ));
        }
        if strings.last().is_some_and(|&b| b != 0) {
            problems.push((
                HeapKind::Strings,
                "the heap ends with bytes that no zero byte ends; the runtime cuts them off",
            ));
        }
        for (heap, data) in [
            (HeapKind::Blob, self.blobs().data()),
            (HeapKind::UserStrings, self.user_strings().data()),
        ] {
            if data.first().is_some_and(|&b| b != 0) {
                problems.push((
                    heap,
                    "the heap does not start with the empty entry; the runtime reads index 0 as empty",
                ));
            }
        }
        if !self.guids().data().len().is_multiple_of(16) {
            problems.push((
                HeapKind::Guid,
                "the size of the heap is not a multiple of 16; the runtime reads the last GUID past the heap",
            ));
        }
        let narrow = |flag: u8, len: usize| heap_sizes & flag == 0 && len > 0x1_0000;
        if narrow(HEAP_STRINGS_WIDE, strings.len()) {
            problems.push((
                HeapKind::Strings,
                "2-byte indices cannot reach the end of the heap",
            ));
        }
        if narrow(HEAP_BLOB_WIDE, self.blobs().data().len()) {
            problems.push((
                HeapKind::Blob,
                "2-byte indices cannot reach the end of the heap",
            ));
        }
        if heap_sizes & HEAP_GUID_WIDE == 0 && self.guids().len() > 0xFFFF {
            problems.push((
                HeapKind::Guid,
                "2-byte indices cannot reach the end of the heap",
            ));
        }
        problems
    }
}
