//! Compound files' directories against olefile (BSD-licensed, run as an
//! oracle only: `tests/fixtures/oracle/olefile_tree.py` wrote
//! `olefile.tsv`): every entry's path, type, size, creation and
//! modification time, in plaso's `Document.doc` (Apache-2.0; a storage
//! inside a storage, with both times) and in every automatic jump list among
//! the fixtures (4,096-byte sectors, and files that end inside their last
//! sector, included).

use std::collections::BTreeSet;

use jumplist::compound::{CompoundFile, Entry};

/// `Document.doc` and the 13 automatic jump lists.
const FILES: usize = 14;

fn fixtures(path: &str) -> String {
    format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"))
}

/// A path as `olefile_tree.py` writes it: characters outside printable
/// ASCII as `\u{hex}`.
fn escaped(path: &str) -> String {
    path.chars()
        .map(|c| {
            if (' '..='~').contains(&c) {
                c.to_string()
            } else {
                c.escape_unicode().to_string()
            }
        })
        .collect()
}

/// A time as a FILETIME, 0 when not recorded.
fn filetime(time: Option<u64>) -> i64 {
    time.map_or(0, |t| t as i64)
}

fn line(file: &str, entry: &Entry) -> String {
    format!(
        "{file}\t{}\t{}\t{}\t{}\t{}",
        escaped(&entry.path),
        entry.kind,
        entry.size,
        filetime(entry.created),
        filetime(entry.modified)
    )
}

#[test]
fn every_entry_as_olefile_reads_it() {
    let oracle = std::fs::read_to_string(fixtures("oracle/olefile.tsv")).unwrap();
    let expected: BTreeSet<String> = oracle.lines().map(str::to_owned).collect();
    let files: BTreeSet<&str> = oracle
        .lines()
        .filter_map(|line| line.split('\t').next())
        .collect();
    assert_eq!(files.len(), FILES);
    let mut got = BTreeSet::new();
    for file in files {
        let data = std::fs::read(fixtures(file)).unwrap();
        let compound = CompoundFile::parse(&data).unwrap();
        assert_eq!(compound.problems, Vec::<String>::new(), "{file}");
        got.extend(compound.entries.iter().map(|entry| line(file, entry)));
    }
    assert_eq!(got, expected);
}

#[test]
fn a_storage_holds_its_children() {
    let data = std::fs::read(fixtures("compound/plaso/Document.doc")).unwrap();
    let file = CompoundFile::parse(&data).unwrap();
    let index = |path: &str| file.entries.iter().position(|e| e.path == path);
    let store = index("Root Entry/MsoDataStore").unwrap();
    let children: Vec<&str> = file
        .entries
        .iter()
        .filter(|e| e.parent == Some(store))
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(children.len(), 1);
    assert_eq!(file.entries[store].parent, index("Root Entry"));
    assert_eq!(
        // 2013-05-16 02:29:49.704 UTC
        file.entries[store].created,
        Some(130_131_449_897_040_000)
    );
    let summary = &file.entries[index("Root Entry/\u{5}SummaryInformation").unwrap()];
    assert_eq!(
        file.contents(summary).unwrap(),
        file.stream("\u{5}SummaryInformation").unwrap().unwrap()
    );
}

#[test]
fn streams_are_found_in_any_case() {
    // Compound files compare names without regard to case (MS-CFB 2.6.4).
    let data = std::fs::read(fixtures("compound/plaso/Document.doc")).unwrap();
    let file = CompoundFile::parse(&data).unwrap();
    let summary = file.stream("\u{5}SummaryInformation").unwrap().unwrap();
    for name in ["\u{5}summaryinformation", "\u{5}SUMMARYINFORMATION"] {
        assert_eq!(
            file.stream(name).unwrap().as_ref(),
            Some(&summary),
            "{name}"
        );
        assert_eq!(
            file.find_stream(name).map(|e| e.name.as_str()),
            Some("\u{5}SummaryInformation")
        );
    }
    assert_eq!(file.stream("\u{5}SummaryInformatio").unwrap(), None);
    let data = std::fs::read(fixtures(
        "jumplist/Win10/f01b4d95cf55d32a.automaticDestinations-ms",
    ))
    .unwrap();
    let file = CompoundFile::parse(&data).unwrap();
    let dest_list = file.stream("DestList").unwrap().unwrap();
    assert_eq!(file.stream("destlist").unwrap(), Some(dest_list));
    assert!(jumplist::compound::same_name(
        "DestListPropertyStore",
        "destlistpropertystore"
    ));
    assert!(!jumplist::compound::same_name("DestList", "DestList2"));
}

/// Names compare as MS-CFB 2.6.4 says: the same length in UTF-16 code units, then each unit
/// uppercased with Unicode's simple (one-to-one) mapping, never the full one that expands.
#[test]
fn names_compare_with_the_simple_uppercase_mapping() {
    use jumplist::compound::same_name;
    for (a, b) in [
        ("é", "É"),
        ("Ünicode", "üNICODE"),
        ("ſ", "S"), // long s
        ("ı", "I"), // dotless i
        ("ß", "ß"),
        ("ᾀ", "ᾈ"), // a ypogegrammeni's simple uppercase: prosgegrammeni
        ("ᾳ", "ᾼ"),
        ("\u{1f600}", "\u{1f600}"), // a surrogate pair, as is
    ] {
        assert!(same_name(a, b), "{a} = {b}");
    }
    for (a, b) in [
        ("ß", "SS"), // full uppercase only
        ("ﬀ", "FF"),
        ("ᾀ", "ἈΙ"),
        ("i", "İ"),
        ("ab", "abc"),
        ("\u{10428}", "\u{10400}"), // outside the BMP: two code units, not uppercased
    ] {
        assert!(!same_name(a, b), "{a} != {b}");
    }
}

mod damage {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        /// `Document.doc` with bytes changed anywhere (tables, directory
        /// links, streams) or cut: parsed or refused, never a panic; every
        /// parent is an entry, and the root reaches each entry once at most.
        #[test]
        fn damaged_files_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let mut data = std::fs::read(fixtures("compound/plaso/Document.doc")).unwrap();
            for (at, byte) in flips {
                let len = data.len();
                data[at % len] = byte;
            }
            data.truncate(cut % (data.len() + 1));
            if let Ok(file) = CompoundFile::parse(&data) {
                for entry in &file.entries {
                    prop_assert!(entry.parent.map_or(true, |p| p < file.entries.len()));
                    prop_assert!(entry.path.matches('/').count() < file.entries.len());
                    let _ = file.contents(entry);
                }
            }
        }
    }
}
