# Agent rules

These rules apply to all agents that change this repository. Obey all rules in all changes.

- Make the smallest cohesive change that solves the whole problem.
- Preserve public behavior and compatibility unless the task calls for a breaking change.
- Do not add speculative abstractions, dependencies, configuration or features.

## Writing

- Use American English spelling (`analyze`, `color`, `normalize`).
- Write documentation and comments in the napbat STE-like profile: short sentences, one
  instruction or one fact in each sentence, the active voice, and the same word for the same
  thing.
- Document every public item. Update examples and crate documentation when behavior changes.
- Write comments that explain intent, invariants, tradeoffs or safety. Do not restate the code.
- Do not write section-divider or section-label comments. Extract a module instead.
- Name the ECMA-335 section (for example II.23.2.12) when code implements a structure of the
  standard.

## Lints: Clippy pedantic

- Treat the workspace `clippy::pedantic` policy and every warning as an error.
- Keep `[lints] workspace = true` in the `Cargo.toml` file of each crate.
- Fix the cause of a lint. Do not weaken the workspace lint configuration, and do not add
  crate-, module- or file-wide lint exceptions.
- A narrow `#[expect(lint, reason = "...")]` is acceptable only when the lint makes the code
  less correct or less clear. Put it on the smallest item. The workspace denies `#[allow]`.
- Do not use meaningless rewrites, dummy reads or conversions only to silence a warning.
- Do not write `unsafe` code. The workspace denies it.

## File size: 1000 lines

- Keep each hand-written source file at a maximum of 1000 lines, inline tests included.
- Split a file before it grows beyond that size. Split by responsibility, not at a random line.

## Layout: Cargo package layout

Follow the Cargo package layout:
<https://doc.rust-lang.org/cargo/guide/project-layout.html>.

- Put each crate in `crates/<name>/`. Put source in `src/`, integration tests in `tests/`.
- Give a target with many files its own directory with a `main.rs` file.
- Use kebab-case names for targets. Use snake_case names for modules.
- Put a module in `foo.rs` and its child modules in `foo/`. Do not use `mod.rs` files.

## Crate boundaries

- `clrmeta-model` holds owned data only: tokens, table identifiers, signatures, exception
  clauses and the method-context wire types. It reads and writes no bytes, so a consumer
  (a Reify architecture plugin, for example) can use it without a metadata parser. Its only
  optional dependency is `serde`.
- `clrmeta` reads and writes the bytes. It depends on `clrmeta-model` and on nothing else.
- Both crates are `no_std` with `alloc`. Add a dependency only if it supports `no_std`.
- Do not read PE files. The caller gives the metadata bytes and a closure that reads bytes at a
  relative virtual address. Integration tests can read PE headers with their own helper.
- Library code starts no threads and keeps no global state.

## Reader and writer rules

- Never panic on malformed input. Check every read. Return an `Error` that names the
  structure, the table row and column, the heap index, or the offset.
- Borrow from the input where the data is bytes or text (`&'a str`, `&'a [u8]`). Make owned
  types only for parsed structures (signatures, clauses).
- Bound each recursion of a parser (signature nesting, custom attribute nesting), so a
  hostile blob cannot exhaust the stack.
- Each parser has an encoder. Encoding a parsed value gives the original bytes when the
  original uses the shortest forms. Test this on the real images.
- Keep the table schema in one place (`tables/schema.rs`). The table identifiers live in
  `clrmeta-model`; a compile-time check keeps them in agreement.

## API conventions

- The crate root re-exports the main types. Domain modules (`body`, `custom_attribute`,
  `marshal`, `security`, `signature`, `tables`, `heaps`) keep their full API.
- Give each error type a name that ends in `Error` or call it `Error`, and implement
  `core::error::Error`.
- Use `*_count` for counting accessors. Do not use `num_*`.
- Use `unwrap` or `expect` only for a proven invariant. Make an `expect` message state the
  invariant.

## Tests

- Add a regression test for each defect and each change of observable behavior.
- Put unit tests in a `#[cfg(test)] mod tests` in the file that they test. Move them to
  `<parent>/tests.rs` when the file gets near the size limit.
- Cover edge cases, failure paths and malformed input.
- Mark a test that reads a file of the host with `#[ignore = "real image: ..."]` and add it to
  the `real-images` filter of `.config/nextest.toml`. It fails when the file is absent.
- Keep tests deterministic. Do not remove or weaken a test to make a change pass.

## Checks

Make sure that all these checks pass before you report a change as complete:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings -D clippy::pedantic
cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::pedantic
cargo nextest run --workspace --all-features
cargo test --workspace --all-features --doc
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo check --workspace --all-features --target x86_64-unknown-none
cargo nextest run --workspace --cargo-profile real-images --profile real-images --run-ignored only
```

The last check needs a .NET runtime on the host. `.github/workflows/lint.yml` runs the other
checks.
