//! The metadata root and the stream headers (ECMA-335 II.24.2.1 and
//! II.24.2.2).

use alloc::vec::Vec;

use crate::bytes::{Cursor, put_u16, put_u32};
use crate::error::{Error, Result};

/// The signature of the metadata root: "BSJB".
pub const METADATA_SIGNATURE: u32 = 0x424A_5342;

/// A stream header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader<'a> {
    /// The offset of the stream from the start of the metadata root.
    pub offset: u32,
    /// The size of the stream in bytes.
    pub size: u32,
    /// The name of the stream (`#~`, `#-`, `#Strings`, `#US`, `#GUID`,
    /// `#Blob`, `#Pdb`, `#JTD`, …).
    pub name: &'a str,
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
    /// The version string of the runtime (`v4.0.30319`, for example).
    pub version: &'a str,
    /// Reserved, zero.
    pub flags: u16,
    /// The stream headers in file order.
    pub streams: Vec<StreamHeader<'a>>,
}

impl<'a> MetadataRoot<'a> {
    /// Parses the metadata root at the start of `data`.
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
        let version_offset = cursor.position();
        let version_bytes = cursor.bytes(version_len)?;
        let text = version_bytes
            .iter()
            .position(|&b| b == 0)
            .map_or(version_bytes, |end| &version_bytes[..end]);
        let version = core::str::from_utf8(text)
            .map_err(|_| cursor.malformed_at(version_offset, "the version string is not UTF-8"))?;
        let flags = cursor.u16()?;
        let count = cursor.u16()?;
        let mut streams = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let offset = cursor.u32()?;
            let size = cursor.u32()?;
            let name_start = cursor.position();
            let name = cursor.zero_terminated()?;
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

    /// Returns the first stream with a name.
    #[must_use]
    pub fn stream(&self, name: &str) -> Option<&StreamHeader<'a>> {
        self.streams.iter().find(|s| s.name == name)
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
        let padded = (root.version.len() + 1).next_multiple_of(4);
        put_u32(out, u32::try_from(padded).map_err(|_| overflow(padded))?);
        out.extend_from_slice(root.version.as_bytes());
        out.resize(out.len() + padded - root.version.len(), 0);
        put_u16(out, root.flags);
        let count = u16::try_from(streams.len()).map_err(|_| overflow(streams.len()))?;
        put_u16(out, count);
        for stream in streams {
            put_u32(out, stream.offset);
            put_u32(out, stream.size);
            out.extend_from_slice(stream.name.as_bytes());
            let used = stream.name.len() + 1;
            out.resize(out.len() + used.next_multiple_of(4) - stream.name.len(), 0);
        }
        Ok(())
    }

    /// Returns the size of the root header with streams of these names.
    pub(crate) fn header_size(version: &str, names: impl Iterator<Item = usize>) -> usize {
        let base = 16 + (version.len() + 1).next_multiple_of(4) + 4;
        base + names
            .map(|len| 8 + (len + 1).next_multiple_of(4))
            .sum::<usize>()
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

    #[test]
    fn a_root_writes_the_bytes_that_it_parses() {
        let root = MetadataRoot {
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            version: "v4.0.30319",
            flags: 0,
            streams: vec![],
        };
        let streams = [
            StreamHeader {
                offset: 0,
                size: 4,
                name: "#~",
            },
            StreamHeader {
                offset: 4,
                size: 4,
                name: "#Strings",
            },
        ];
        let mut out = Vec::new();
        MetadataRoot::write_header(&mut out, &root, &streams).unwrap();
        assert_eq!(
            out.len(),
            MetadataRoot::header_size(root.version, streams.iter().map(|s| s.name.len()))
        );
        out.resize(out.len() + 8, 0);
        let parsed = MetadataRoot::parse(&out).unwrap();
        assert_eq!(parsed.version, "v4.0.30319");
        assert_eq!(parsed.streams, streams);
        assert_eq!(parsed.stream("#Strings").unwrap().offset, 4);
    }

    #[test]
    fn a_bad_signature_or_a_stream_outside_the_data_is_an_error() {
        assert!(matches!(
            MetadataRoot::parse(b"XXXX"),
            Err(Error::Malformed { .. })
        ));
        let root = MetadataRoot {
            major_version: 1,
            minor_version: 1,
            reserved: 0,
            version: "v",
            flags: 0,
            streams: vec![],
        };
        let mut out = Vec::new();
        let far = StreamHeader {
            offset: 1000,
            size: 4,
            name: "#~",
        };
        MetadataRoot::write_header(&mut out, &root, &[far]).unwrap();
        assert!(matches!(
            MetadataRoot::parse(&out),
            Err(Error::Truncated { .. })
        ));
    }
}
