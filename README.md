# clrmeta

A zero-copy `no_std` reader and a writer of ECMA-335 CLI metadata: the metadata of .NET
assemblies, their signatures and their method bodies.

The workspace has two crates:

| Crate | Content |
| --- | --- |
| `clrmeta` | The reader and the writer of the bytes. |
| `clrmeta-model` | Owned data only: tokens, table identifiers, signatures, exception clauses and the method-context wire types. It reads no bytes. The `serde` feature derives `Serialize` and `Deserialize`. |

`clrmeta` does not read PE files. The caller gives the metadata bytes that the CLI header names,
and a closure that returns the bytes at a relative virtual address for method bodies.

## Coverage

| ECMA-335 | Support |
| --- | --- |
| II.24.2.1 metadata root, II.24.2.2 stream headers | read, write |
| II.24.2.3 `#Strings`, II.24.2.4 `#US` and `#Blob`, II.24.2.5 `#GUID` | borrowed views, appendable builders |
| II.24.2.6 `#~` and `#-` tables streams, `HeapSizes` extra data, `#JTD` wide indices | read, write |
| II.22 all 45 tables, the `Ptr` tables and the edit-and-continue tables | typed rows, `Rid<R>` indices, lists through the `Ptr` tables |
| Portable PDB: the `#Pdb` stream and the 8 debug tables | typed rows, indices sized by the type system row counts |
| II.24.2.6 the 13 coded indices, and `HasCustomDebugInformation` | decode to `Token`, encode |
| II.23.1 flag values | constants in `flags` |
| II.23.2 signatures: method (definition, reference, stand-alone, vararg sentinel), field, property, locals (pinned, by-ref, `typedref`), `TypeSpec`, `MethodSpec`, custom modifiers, generic instances, arrays with bounds, function pointers | parse, encode |
| II.23.3 custom attribute values, with an `EnumResolver` for enum types | parse, encode |
| II.23.4 marshalling descriptors | parse, encode |
| II.22.11 permission sets (XML and binary forms) | parse, encode |
| II.25.4 method bodies: tiny and fat headers, small and fat exception clauses (catch, filter, finally, fault) | parse, encode |
| II.6.2.1.3 public key tokens | SHA-1 token |

The `Metadata` type adds the lookups that follow the links between the tables: the fields,
methods, parameters, events and properties of their owners and back, nested types, generic
parameters, custom attributes, constants, layouts and imports, type names
(`Namespace.Outer/Inner`), and a `Resolver` for the tokens of IL instructions. The resolver
checks the kind of entity: a `MemberRef` with a field signature never resolves as a method.
`Metadata::validate` checks the root, the streams, the header of the tables, the heaps and every
row of every table, and `MethodBody::validate` checks a method body.

## Runtime compatibility

The reader reads what the .NET runtime reads and ignores what it ignores, so it reads the
obfuscated and malformed files that the runtime loads. The validator reports what ECMA-335 does
not allow. Examples:

| File | The runtime and clrmeta |
| --- | --- |
| Two heaps of one name | `#~` metadata: the last heap wins. With a `#-` or `#Schema` stream: the first heap wins, names compare without case. |
| Unknown streams, stream names that are not UTF-8, `#JTD` next to `#~` | Ignored. |
| A version string of any length or bytes | Read as stored; `version()` replaces bytes that are not UTF-8. |
| Unknown tables in the `valid` mask, debug tables in a module, extra data (heap size bit 0x40) | The row counts are skipped; no rows. |
| A coded index with an unused tag | Decodes as CoreCLR `decodeToken` decodes it; the row reads. |
| Names that are not UTF-8 | `type_name`, the resolver and `StringsHeap::get_lossy` use U+FFFD. |
| Blob or user string 0, a `#GUID` heap that is not a multiple of 16 | Empty entry; the last GUID reads past the heap. |
| Method bodies | Fat only when the low 3 bits are 3; `DataSize / 12` (or 24) clauses; clauses from the first section only; clause kinds from the flag bits as the JIT tests them. |
| A list that goes back, a nesting cycle | An empty list, an error for the name; both reported. |

`crates/clrmeta/tests/obfuscated/fixtures` holds ConfuserEx samples and patched samples for each
quirk. `build.py` builds them on Windows and runs each one on CoreCLR and .NET Framework to prove
what the runtime reads (`runs.txt`).

## Example

```rust
use clrmeta::{Metadata, MethodDefRow};

fn list_methods<'a>(
    metadata_bytes: &'a [u8],
    read: impl Fn(u32, usize) -> Option<&'a [u8]> + Copy,
) -> clrmeta::Result<()> {
    let metadata = Metadata::parse(metadata_bytes)?;
    let resolver = metadata.resolver();
    for row in &metadata.tables().table::<MethodDefRow>() {
        let (rid, _) = row?;
        let method = resolver.method(rid.token())?;
        let owner = metadata.type_name(method.owner)?;
        if let Some(body) = metadata.method_body(rid, read)? {
            let locals = metadata.locals_of(&body)?;
            println!(
                "{owner}::{} stack {} locals {} clauses {}",
                method.name,
                body.max_stack,
                locals.locals.len(),
                body.clauses.len()
            );
        }
    }
    Ok(())
}
```

`MetadataBuilder::from_metadata` copies parsed metadata, and `MetadataBuilder::write` writes it
back. A copy that changes nothing writes the same bytes. The builder adds rows and heap entries
for an edit: `add_assembly_ref`, `add_type_ref`, `add_type_spec`, `add_member_ref`,
`add_method_spec`, `add_stand_alone_sig` and `UserStringsHeapBuilder::add_units` reuse an equal
entry. `add_method` adds a method to the end of the methods of its type; the later methods get
the next row numbers in every table, the sorted tables are sorted again, and
`MethodRenumbering` gives the new token of each old token. `body::map_tokens` writes the new
tokens into the code of a method body, and `signature::map_type_indices` writes the type indices
of a signature blob again.

## Checks

`AGENTS.md` lists the checks. The real-image tests read every managed assembly of the .NET
runtime of the host:

```text
cargo nextest run --workspace --cargo-profile real-images --profile real-images --run-ignored only
```

## License

MIT
