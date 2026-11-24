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
`Metadata::validate` checks every row of every table.

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
back. A copy that changes nothing writes the same bytes.

## Checks

`AGENTS.md` lists the checks. The real-image tests read every managed assembly of the .NET
runtime of the host:

```text
cargo nextest run --workspace --cargo-profile real-images --profile real-images --run-ignored only
```

## License

MIT
