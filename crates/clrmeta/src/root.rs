//! The metadata root and the stream headers (ECMA-335 II.24.2.1 and
//! II.24.2.2), and the choice of the streams that the runtime reads.

use alloc::vec::Vec;

use crate::bytes::{Cursor, put_u16, put_u32};
use crate::error::{Error, Result};

/// The signature of the metadata root: "BSJB".
pub const METADATA_SIGNATURE: u32 = 0x424A_5342;

/// The largest size of a stream name with its zero byte that the runtime
/// reads. A name without a zero byte in these bytes makes the runtime reject
/// the file.
pub const MAX_STREAM_NAME: usize = 32;

/// A stream header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader<'a> {
    /// The offset of the stream from the start of the metadata root.
    pub offset: u32,
    /// The size of the stream in bytes.
    pub size: u32,
    /// The name of the stream without its zero byte (`#~`, `#-`,
    /// `#Strings`, `#US`, `#GUID`, `#Blob`, `#Pdb`, `#JTD`, …). The runtime
    /// compares the bytes and ignores a name that it does not know, so a
    /// name need not be UTF-8.
    pub name: &'a [u8],
}

/// The metadata root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataRoot<'a> {
    /// The major version (1).
    pub major_version: u16,
    /// The minor version (1).
    pub minor_version: u16,
    /// Reserved, zero.
    pub reserved: u32,
    /// The version field as stored: the version string of the runtime
    /// (`v4.0.30319`, for example), a zero byte, and padding. The length of
    /// the field need not be a multiple of 4, and the runtime does not
    /// require UTF-8. [`MetadataRoot::version_string`] returns the string.
    pub version: &'a [u8],
    /// Reserved, zero.
    pub flags: u16,
    /// The stream headers in file order.
    pub streams: Vec<StreamHeader<'a>>,
}

impl<'a> MetadataRoot<'a> {
    /// Parses the metadata root at the start of `data`.
    ///
    /// The parser accepts what the runtime accepts and more: a stream name
    /// of any bytes and any length, and a version field of any length.
    /// [`Metadata::validate`](crate::Metadata::validate) reports the values
    /// that the runtime rejects.
    ///
    /// # Errors
    ///
    /// Returns an error when the signature is not "BSJB", a header is cut
    /// short, or a stream lies outside `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data, "metadata root");
        if cursor.u32()? != METADATA_SIGNATURE {
            return Err(cursor.malformed_at(0, "the signature is not BSJB"));
        }
        let major_version = cursor.u16()?;
        let minor_version = cursor.u16()?;
        let reserved = cursor.u32()?;
        let version_len = cursor.u32()? as usize;
        let version = cursor.bytes(version_len)?;
        let flags = cursor.u16()?;
        let count = cursor.u16()?;
        let mut streams = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let offset = cursor.u32()?;
            let size = cursor.u32()?;
            let name_start = cursor.position();
            let name = cursor.zero_terminated_bytes()?;
            // The name and its zero byte are padded to a multiple of 4.
            let used = cursor.position() - name_start;
            cursor.skip((4 - used % 4) % 4)?;
            let end = u64::from(offset) + u64::from(size);
            if end > data.len() as u64 {
                return Err(Error::Truncated {
                    structure: "metadata stream",
                    offset: offset as usize,
                    needed: usize::try_from(end - data.len() as u64).unwrap_or(usize::MAX),
                });
            }
            streams.push(StreamHeader { offset, size, name });
        }
        Ok(Self {
            major_version,
            minor_version,
            reserved,
            version,
            flags,
            streams,
        })
    }

    /// Returns the version string: the version field up to its first zero
    /// byte.
    #[must_use]
    pub fn version_string(&self) -> &'a [u8] {
        let end = self
            .version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.version.len());
        &self.version[..end]
    }

    /// Returns the first stream with a name.
    #[must_use]
    pub fn stream(&self, name: &str) -> Option<&StreamHeader<'a>> {
        self.streams.iter().find(|s| s.name == name.as_bytes())
    }

    /// Returns the streams that the runtime reads.
    #[must_use]
    pub fn selection(&self) -> StreamSelection {
        let names: Vec<&[u8]> = self.streams.iter().map(|s| s.name).collect();
        StreamSelection::of(&names)
    }

    /// Returns the bytes of a stream.
    #[must_use]
    pub fn stream_data(&self, data: &'a [u8], index: usize) -> &'a [u8] {
        self.streams
            .get(index)
            .and_then(|header| {
                let start = header.offset as usize;
                data.get(start..start.checked_add(header.size as usize)?)
            })
            .unwrap_or_default()
    }

    /// Writes the root header with the given stream headers.
    pub(crate) fn write_header(
        out: &mut Vec<u8>,
        root: &MetadataRoot<'_>,
        streams: &[StreamHeader<'_>],
    ) -> Result<()> {
        put_u32(out, METADATA_SIGNATURE);
        put_u16(out, root.major_version);
        put_u16(out, root.minor_version);
        put_u32(out, root.reserved);
        let len = root.version.len();
        put_u32(out, u32::try_from(len).map_err(|_| overflow(len))?);
        out.extend_from_slice(root.version);
        put_u16(out, root.flags);
        let count = u16::try_from(streams.len()).map_err(|_| overflow(streams.len()))?;
        put_u16(out, count);
        for stream in streams {
            put_u32(out, stream.offset);
            put_u32(out, stream.size);
            out.extend_from_slice(stream.name);
            let used = stream.name.len() + 1;
            out.resize(out.len() + used.next_multiple_of(4) - stream.name.len(), 0);
        }
        Ok(())
    }

    /// Returns the size of the root header with a version field of
    /// `version_len` bytes and streams with names of these lengths.
    pub(crate) fn header_size(version_len: usize, names: impl Iterator<Item = usize>) -> usize {
        let base = 16 + version_len + 4;
        base + names
            .map(|len| 8 + (len + 1).next_multiple_of(4))
            .sum::<usize>()
    }
}

/// The streams that the runtime reads, by their position in
/// [`MetadataRoot::streams`].
///
/// The runtime has two readers (`CoreCLR` `CheckFileFormat`):
///
/// - The read-only reader takes metadata with a `#~` stream. It compares
///   the names byte for byte, and the last stream of a name wins: each
///   stream replaces the stream of the same name before it.
/// - The read-write reader takes metadata with a `#-` or a `#Schema`
///   stream, also when a `#~` stream exists. It compares the names without
///   case, and the first stream of a name wins. It takes a `#~` stream
///   before a `#-` stream, and a `#JTD` stream makes every index 4 bytes.
///
/// An obfuscator adds heaps of the same name and a `#Schema` stream to make
/// other readers take the wrong heaps. The runtime rejects metadata with two
/// tables streams; the selection then takes the stream that the reader of
/// its format takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct StreamSelection {
    /// `true` when the read-write reader reads the metadata.
    pub uncompressed: bool,
    /// The tables stream (`#~` or `#-`).
    pub tables: Option<usize>,
    /// The `#Strings` heap.
    pub strings: Option<usize>,
    /// The `#US` heap.
    pub user_strings: Option<usize>,
    /// The `#GUID` heap.
    pub guids: Option<usize>,
    /// The `#Blob` heap.
    pub blobs: Option<usize>,
    /// The `#Pdb` stream of a portable PDB. The runtime does not read it;
    /// `System.Reflection.Metadata` takes the last `#Pdb` stream.
    pub pdb: Option<usize>,
    /// The `#JTD` stream of a minimal edit-and-continue delta. Only the
    /// read-write reader reads it.
    pub jtd: Option<usize>,
}

impl StreamSelection {
    /// Selects the streams from their names in file order.
    #[must_use]
    pub fn of(names: &[&[u8]]) -> Self {
        let uncompressed = names.iter().any(|&n| n == b"#-" || n == b"#Schema");
        let find = |wanted: &[u8]| -> Option<usize> {
            if uncompressed {
                names.iter().position(|n| n.eq_ignore_ascii_case(wanted))
            } else {
                names.iter().rposition(|&n| n == wanted)
            }
        };
        let last = |wanted: &[u8]| names.iter().rposition(|&n| n == wanted);
        Self {
            uncompressed,
            tables: find(b"#~").or_else(|| find(b"#-")),
            strings: find(b"#Strings"),
            user_strings: find(b"#US"),
            guids: find(b"#GUID"),
            blobs: find(b"#Blob"),
            pdb: last(b"#Pdb"),
            jtd: if uncompressed { find(b"#JTD") } else { None },
        }
    }

    /// Returns `true` when the runtime reads the stream at `index`.
    #[must_use]
    pub fn is_selected(&self, index: usize) -> bool {
        [
            self.tables,
            self.strings,
            self.user_strings,
            self.guids,
            self.blobs,
            self.pdb,
            self.jtd,
        ]
        .contains(&Some(index))
    }
}

fn overflow(value: usize) -> Error {
    Error::Overflow {
        structure: "metadata root",
        value: value as u64,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn root(version: &[u8]) -> MetadataRoot<'_> {
        MetadataRoot {
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            version,
            flags: 0,
            streams: vec![],
        }
    }

    fn header(name: &[u8]) -> StreamHeader<'_> {
        StreamHeader {
            offset: 0,
            size: 0,
            name,
        }
    }

    #[test]
    fn a_root_writes_the_bytes_that_it_parses() {
        let root = root(b"v4.0.30319\0\0");
        let streams = [
            StreamHeader {
                offset: 0,
                size: 4,
                name: b"#~",
            },
            StreamHeader {
                offset: 4,
                size: 4,
                name: b"#Strings",
            },
        ];
        let mut out = Vec::new();
        MetadataRoot::write_header(&mut out, &root, &streams).unwrap();
        assert_eq!(
            out.len(),
            MetadataRoot::header_size(root.version.len(), streams.iter().map(|s| s.name.len()))
        );
        out.resize(out.len() + 8, 0);
        let parsed = MetadataRoot::parse(&out).unwrap();
        assert_eq!(parsed.version_string(), b"v4.0.30319");
        assert_eq!(parsed.streams, streams);
        assert_eq!(parsed.stream("#Strings").unwrap().offset, 4);
        assert_eq!(parsed.stream_data(&out, 1), &out[4..8]);
        assert_eq!(parsed.stream_data(&out, 9), &[] as &[u8]);
    }

    #[test]
    fn a_version_field_of_any_length_and_any_bytes_reads_back() {
        // The runtime loads a version field of 13 bytes, junk after the
        // zero byte, and bytes that are not UTF-8.
        for version in [
            &b"v4.0.30319\0\0\0"[..],
            b"v4.0.30319\0X",
            b"v4\xFF\xFE\0\0",
            b"",
        ] {
            let mut out = Vec::new();
            MetadataRoot::write_header(&mut out, &root(version), &[header(b"#~")]).unwrap();
            let parsed = MetadataRoot::parse(&out).unwrap();
            assert_eq!(parsed.version, version);
            let mut again = Vec::new();
            MetadataRoot::write_header(&mut again, &parsed, &parsed.streams).unwrap();
            assert_eq!(again, out);
        }
        assert_eq!(root(b"v4.0.30319XY").version_string(), b"v4.0.30319XY");
    }

    #[test]
    fn a_stream_name_of_any_bytes_or_length_reads_back() {
        // The runtime ignores a name that is not UTF-8. It rejects a name
        // without a zero byte in 32 bytes; the parser reads it.
        let names = [&b"\xFF\xFE\x80junk"[..], &[b'A'; 40], b"#~"];
        let headers: Vec<_> = names.iter().map(|name| header(name)).collect();
        let mut out = Vec::new();
        MetadataRoot::write_header(&mut out, &root(b"v1\0\0"), &headers).unwrap();
        let parsed = MetadataRoot::parse(&out).unwrap();
        assert_eq!(parsed.streams, headers);
        assert_eq!(parsed.selection().tables, Some(2));
    }

    #[test]
    fn a_bad_signature_or_a_stream_outside_the_data_is_an_error() {
        assert!(matches!(
            MetadataRoot::parse(b"XXXX"),
            Err(Error::Malformed { .. })
        ));
        let mut out = Vec::new();
        let far = StreamHeader {
            offset: 1000,
            size: 4,
            name: b"#~",
        };
        MetadataRoot::write_header(&mut out, &root(b"v\0\0\0"), &[far]).unwrap();
        assert!(matches!(
            MetadataRoot::parse(&out),
            Err(Error::Truncated { .. })
        ));
        let mut cut = Vec::new();
        MetadataRoot::write_header(&mut cut, &root(b"v\0\0\0"), &[header(b"#~")]).unwrap();
        cut.truncate(cut.len() - 3);
        assert!(MetadataRoot::parse(&cut).is_err());
    }

    fn select(names: &[&[u8]]) -> StreamSelection {
        StreamSelection::of(names)
    }

    #[test]
    fn the_read_only_reader_takes_the_last_stream_of_a_name() {
        // ConfuserEx-style heaps after the real heaps, without #Schema:
        // CoreCLR and .NET Framework read the later heaps.
        let s = select(&[
            b"#~",
            b"#Strings",
            b"#Blob",
            b"#Strings",
            b"#Blob",
            b"#strings",
        ]);
        assert!(!s.uncompressed);
        assert_eq!((s.tables, s.strings, s.blobs), (Some(0), Some(3), Some(4)));
        assert_eq!((s.user_strings, s.guids, s.pdb), (None, None, None));
        // The read-only reader does not read #JTD.
        assert_eq!(select(&[b"#~", b"#JTD"]).jtd, None);
        assert!(s.is_selected(3) && !s.is_selected(1) && !s.is_selected(5));
    }

    #[test]
    fn the_read_write_reader_takes_the_first_stream_of_a_name_without_case() {
        // ConfuserEx adds #Schema after its fake heaps: the runtime then
        // reads the first heaps.
        let s = select(&[
            b"#~",
            b"#Strings",
            b"#GUID",
            b"#Strings",
            b"#GUID",
            b"#Schema",
        ]);
        assert!(s.uncompressed);
        assert_eq!((s.tables, s.strings, s.guids), (Some(0), Some(1), Some(2)));
        let s = select(&[b"#-", b"#STRINGS", b"#jtd", b"#Strings"]);
        assert_eq!((s.tables, s.strings, s.jtd), (Some(0), Some(1), Some(2)));
        // Both tables streams: the read-write reader takes #~.
        assert_eq!(select(&[b"#-", b"#~"]).tables, Some(1));
        assert_eq!(select(&[b"#Pdb", b"#~", b"#Pdb"]).pdb, Some(2));
        assert_eq!(select(&[b"#Strings"]).tables, None);
    }
}
