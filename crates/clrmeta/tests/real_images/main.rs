//! Tests on the assemblies of the installed .NET runtime.
//!
//! The default run ignores them. Run them with the `real-images` profiles:
//! `cargo nextest run --workspace --cargo-profile real-images --profile
//! real-images --run-ignored only`. A test fails when the host has no .NET
//! runtime under `DOTNET_ROOT` (or `C:/Program Files/dotnet`).

mod checks;
mod pe;

use std::path::{Path, PathBuf};

use clrmeta::Metadata;
use clrmeta::custom_attribute::EnumIndex;

use crate::pe::PeFile;

/// Returns the directory of the newest `Microsoft.NETCore.App` runtime.
fn runtime_directory() -> PathBuf {
    let root = std::env::var_os("DOTNET_ROOT")
        .map_or_else(|| PathBuf::from("C:/Program Files/dotnet"), PathBuf::from);
    let shared = root.join("shared").join("Microsoft.NETCore.App");
    let entries = std::fs::read_dir(&shared)
        .unwrap_or_else(|error| panic!("no .NET runtime at {}: {error}", shared.display()));
    let version = |path: &Path| -> Vec<u32> {
        path.file_name()
            .and_then(|name| name.to_str())
            .map_or_else(Vec::new, |name| {
                name.split('.')
                    .map(|part| part.parse().unwrap_or(0))
                    .collect()
            })
    };
    entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.join("System.Private.CoreLib.dll").is_file())
        .max_by_key(|path| version(path))
        .unwrap_or_else(|| {
            panic!(
                "no runtime with System.Private.CoreLib.dll in {}",
                shared.display()
            )
        })
}

fn load(path: &Path) -> Option<PeFile> {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    PeFile::parse(bytes)
}

/// Checks one assembly of the runtime with an enum index of the assembly
/// and `System.Private.CoreLib`, and prints its counts.
fn check_one(name: &str) {
    let directory = runtime_directory();
    let corelib_pe =
        load(&directory.join("System.Private.CoreLib.dll")).expect("CoreLib is a PE file");
    let corelib = Metadata::parse(corelib_pe.metadata().expect("CoreLib has metadata")).unwrap();
    let pe = load(&directory.join(name)).unwrap_or_else(|| panic!("{name} is not a PE file"));
    let md = Metadata::parse(
        pe.metadata()
            .unwrap_or_else(|| panic!("{name} has no metadata")),
    )
    .unwrap();
    let index = EnumIndex::new(&[&md, &corelib]);
    let (counts, problems) = checks::check(&pe, &md, &index);
    println!("{} {name}: {counts:?}", directory.display());
    problems.assert_none(name);
}

#[test]
#[ignore = "real image: reads System.Private.CoreLib.dll of the installed .NET runtime"]
fn system_private_corelib_reads_and_writes_without_a_problem() {
    check_one("System.Private.CoreLib.dll");
}

#[test]
#[ignore = "real image: reads System.Runtime.dll of the installed .NET runtime"]
fn system_runtime_reads_and_writes_without_a_problem() {
    check_one("System.Runtime.dll");
}

/// Checks every managed assembly of the runtime. An enum of a custom
/// attribute resolves in an index of every assembly of the runtime, as a
/// loader resolves it in the assemblies that the module refers to.
#[test]
#[ignore = "real image: reads every managed assembly of the installed .NET runtime"]
fn every_assembly_of_the_runtime_reads_and_writes_without_a_problem() {
    let directory = runtime_directory();
    let mut paths: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "dll"))
        .collect();
    paths.sort();
    let files: Vec<(String, PeFile)> = paths
        .iter()
        .filter_map(|path| {
            let pe = load(path)?;
            pe.metadata()?;
            Some((path.file_name()?.to_string_lossy().into_owned(), pe))
        })
        .collect();
    let mut failures = Vec::new();
    let mut modules = Vec::new();
    for (name, pe) in &files {
        match Metadata::parse(pe.metadata().expect("the file has metadata")) {
            Ok(md) => modules.push((name, pe, md)),
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }
    let all: Vec<&Metadata<'_>> = modules.iter().map(|(_, _, md)| md).collect();
    let index = EnumIndex::new(&all);
    for (name, pe, md) in &modules {
        let (counts, problems) = checks::check(pe, md, &index);
        println!("{name}: {counts:?}");
        failures.extend(problems.summary(name));
    }
    println!(
        "{} managed assemblies and {} enums in {}",
        files.len(),
        index.len(),
        directory.display()
    );
    assert!(files.len() > 100, "only {} managed assemblies", files.len());
    assert!(
        failures.is_empty(),
        "{} assemblies failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
