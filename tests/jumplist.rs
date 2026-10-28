//! Jump lists against Eric Zimmerman's JLECmd (its output in `tests/fixtures/oracle/`, JLECmd
//! 2026.10.5): every `DestList` column, and the link columns of each entry, of every automatic
//! jump list in `tests/fixtures/jumplist/` (Windows 7 to 11, `DestList` versions 1, 3, 4 and 6,
//! 512- and 4,096-byte sectors, files that end inside their last sector); the links and category
//! names of the custom ones it reads. See `tests/fixtures/jumplist/README.md` for the sources.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::fs;

use common::{fixtures, path_agrees, records, when};
use jumplist::{compound::CompoundFile, Destination, Kind};
use shell::lnk::Link;

/// Automatic jump lists JLECmd reads: all of them.
const AUTOMATIC: usize = 13;
/// `DestList` entries in them.
const ENTRIES: usize = 136;

const CUSTOM: [&str; 3] = [
    "plaso/368d807282ccde9d.customDestinations-ms",
    "plaso/5afe4de1b92fc382.customDestinations-ms",
    "synthetic/ccba5a5986c77e43.customDestinations-ms",
];

/// A GUID as JLECmd prints it: lowercase, no braces.
fn bare(guid: &str) -> String {
    guid.trim_matches(['{', '}']).to_ascii_lowercase()
}

fn link_columns(link: &Link) -> Vec<(&'static str, String)> {
    let tracker = link.tracker.as_ref();
    vec![
        ("TargetCreated", when(link.created)),
        ("TargetModified", when(link.modified)),
        ("TargetAccessed", when(link.accessed)),
        ("FileSize", link.size.to_string()),
        ("LocalPath", link.local_path.clone()),
        ("Arguments", link.arguments.clone()),
        (
            "MachineID",
            tracker.map_or(String::new(), |t| t.machine_id.clone()),
        ),
        (
            "MachineMACAddress",
            tracker.map_or(String::new(), |t| t.mac.clone()),
        ),
    ]
}

fn check_link(link: &Link, row: &HashMap<String, String>, at: &str) {
    for (column, value) in link_columns(link) {
        assert_eq!(&value, &row[column], "{at}: {column}");
    }
    // Without a target ID list, JLECmd names the target from the link information.
    let mut target = link.target_path();
    if target.is_empty() {
        let base = if link.network_path.is_empty() {
            &link.local_path
        } else {
            &link.network_path
        };
        target = format!("{base}\\{}", link.common_path);
    }
    assert!(
        path_agrees(&row["TargetIDAbsolutePath"], &target),
        "{at}: {} vs {target}",
        row["TargetIDAbsolutePath"]
    );
}

fn oracle(name: &str) -> HashMap<String, Vec<HashMap<String, String>>> {
    let mut by_file: HashMap<String, Vec<_>> = HashMap::new();
    for row in records(&fs::read_to_string(fixtures().join("oracle").join(name)).unwrap()) {
        by_file
            .entry(row["SourceFile"].clone())
            .or_default()
            .push(row);
    }
    by_file
}

fn columns(d: &Destination, version: u32) -> Vec<(&'static str, String)> {
    vec![
        ("EntryNumber", format!("{:X}", d.entry)),
        ("DestListVersion", version.to_string()),
        ("LastModified", when(d.last_used)),
        ("CreationTime", when(d.droid_created)),
        ("Hostname", d.hostname.clone()),
        ("MacAddress", d.mac.clone()),
        (
            "InteractionCount",
            d.interaction_count.unwrap_or(0).to_string(),
        ),
        (
            "PinStatus",
            if d.pin.is_some() { "True" } else { "False" }.to_owned(),
        ),
        ("FileDroid", bare(&d.file_droid)),
        ("VolumeDroid", bare(&d.volume_droid)),
        ("FileBirthDroid", bare(&d.file_birth_droid)),
        ("VolumeBirthDroid", bare(&d.volume_birth_droid)),
    ]
}

/// The automatic jump lists among the fixtures, by path under `tests/fixtures/jumplist/`.
fn automatic_files() -> BTreeSet<String> {
    let mut files = BTreeSet::new();
    let mut dirs = vec![fixtures().join("jumplist")];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path
                .to_string_lossy()
                .ends_with(".automaticDestinations-ms")
            {
                let relative = path.strip_prefix(fixtures().join("jumplist")).unwrap();
                files.insert(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    files
}

#[test]
fn automatic_matches_jlecmd() {
    let mut by_file = oracle("JLECmd.csv");
    let files = automatic_files();
    assert_eq!(files.len(), AUTOMATIC);
    let mut checked = 0;
    for file in &files {
        let data = fs::read(fixtures().join("jumplist").join(file)).unwrap();
        let list = jumplist::automatic(&data).unwrap();
        assert!(list.problems.is_empty(), "{file}: {:?}", list.problems);
        let rows = by_file.remove(file.as_str()).unwrap_or_default();
        assert_eq!(list.destinations.len(), rows.len(), "{file}");
        for row in rows {
            // JLECmd numbers entries most recent first, which is stream order.
            let at = format!("{file} MRU {}", row["MRU"]);
            let d = &list.destinations[row["MRU"].parse::<usize>().unwrap()];
            assert_eq!(d.position.to_string(), row["MRU"], "{at}");
            for (column, value) in columns(d, list.version()) {
                assert_eq!(&value, &row[column], "{at}: {column}");
            }
            // JLECmd appends what it resolves the path to (`… ==> …`).
            let path = row["Path"].split(" ==> ").next().unwrap();
            assert_eq!(d.path, path, "{at}: Path");
            check_link(d.link.as_ref().unwrap(), &row, &at);
            checked += 1;
        }
    }
    assert!(by_file.is_empty(), "files not tested: {:?}", by_file.keys());
    assert_eq!(checked, ENTRIES);
}

#[test]
fn custom_matches_jlecmd() {
    let mut by_file = oracle("JLECmd-custom.csv");
    let mut checked = 0;
    for file in CUSTOM {
        let list = jumplist::custom(&fs::read(fixtures().join("jumplist").join(file)).unwrap());
        assert!(list.problems.is_empty(), "{file}: {:?}", list.problems);
        let links: Vec<(&Kind, &Link)> = list
            .categories
            .iter()
            .flat_map(|c| c.links.iter().map(move |l| (&c.kind, l)))
            .collect();
        let rows = by_file.remove(file).unwrap();
        assert_eq!(links.len(), rows.len(), "{file}");
        for (i, (row, (kind, link))) in rows.iter().zip(links).enumerate() {
            let at = format!("{file} link {i}");
            // JLECmd names a custom category; its tasks have no name.
            match kind {
                Kind::Custom(name) => assert_eq!(name, &row["EntryName"], "{at}"),
                _ => assert_eq!(row["EntryName"], "", "{at}"),
            }
            check_link(link, row, &at);
            checked += 1;
        }
    }
    assert!(by_file.is_empty(), "files not tested: {:?}", by_file.keys());
    assert_eq!(checked, 17);
}

#[test]
fn custom_categories() {
    let kinds = |file: &str| -> Vec<(Kind, usize)> {
        let data = fs::read(fixtures().join("jumplist").join(file)).unwrap();
        jumplist::custom(&data)
            .categories
            .into_iter()
            .map(|c| (c.kind, c.links.len()))
            .collect()
    };
    let named = |name: &str| Kind::Custom(name.to_owned());
    assert_eq!(
        kinds(CUSTOM[0]),
        [
            (named("My Category 1"), 1),
            (Kind::Known(1), 0),
            (Kind::Tasks, 1),
            (named("My Category 2"), 1),
            (Kind::Known(2), 0),
        ]
    );
    assert_eq!(kinds(CUSTOM[1]), [(Kind::Tasks, 9)]);
    assert_eq!(
        kinds(CUSTOM[2]),
        [
            (named("Most visited"), 2),
            (named("Recently closed"), 1),
            (Kind::Tasks, 2),
        ]
    );
    // Windows 11 Chrome: after its three categories, the end of a longer, earlier list. JLECmd
    // refuses the file ("footer missing").
    let rewritten = jumplist::custom(
        &fs::read(
            fixtures()
                .join("jumplist/jumplist_parser/win11/5d696d521de238c3.customDestinations-ms"),
        )
        .unwrap(),
    );
    assert!(rewritten.problems.is_empty(), "{:?}", rewritten.problems);
    assert_eq!(rewritten.links().count(), 6);
    assert_eq!(rewritten.trailing, 3250);
    let leftover: Vec<(usize, &str)> = rewritten
        .leftover
        .iter()
        .map(|l| (l.offset, l.link.arguments.as_str()))
        .collect();
    assert_eq!(
        leftover,
        [
            (
                11_472,
                "--win-jumplist-action=most-visited http://192.168.50.33:5000/"
            ),
            (
                13_609,
                "--win-jumplist-action=recently-closed http://192.168.50.33:3000/"
            ),
        ]
    );
    for current in rewritten.links().map(|(_, l)| &l.arguments) {
        assert!(!current.contains("192.168.50.33"), "{current}");
    }
    // An empty Windows 11 list, which JLECmd refuses.
    let empty_11 = jumplist::custom(
        &fs::read(
            fixtures()
                .join("jumplist/jumplist_parser/win11/f01b4d95cf55d32a.customDestinations-ms"),
        )
        .unwrap(),
    );
    assert_eq!(empty_11.links().count(), 0);
    assert!(empty_11.problems.is_empty(), "{:?}", empty_11.problems);
    // An empty list: a header and no categories.
    let empty =
        fs::read(fixtures().join("jumplist/plaso/c98dce577f884ef8.customDestinations-ms")).unwrap();
    let empty = jumplist::custom(&empty);
    assert!(empty.categories.is_empty() && empty.problems.is_empty());
}

mod garbage {
    use proptest::prelude::*;

    fn damaged(file: &str, flips: Vec<(usize, u8)>, cut: usize) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/jumplist/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut data = std::fs::read(path).unwrap();
        for (at, byte) in flips {
            let len = data.len();
            data[at % len] = byte;
        }
        data.truncate(cut % (data.len() + 1));
        data
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1_000))]

        /// A real jump list corrupted anywhere (its compound file tables,
        /// directory, `DestList` or links), or truncated: parsed or
        /// refused, never a panic.
        #[test]
        fn damaged_automatic_lists_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let data = damaged("Win10/f01b4d95cf55d32a.automaticDestinations-ms", flips, cut);
            if let Ok(file) = jumplist::compound::CompoundFile::parse(&data) {
                for entry in &file.entries {
                    let _ = file.stream(&entry.name);
                }
            }
            let _ = jumplist::automatic(&data);
        }

        #[test]
        fn damaged_custom_lists_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40), cut in any::<usize>()) {
            let data = damaged("plaso/368d807282ccde9d.customDestinations-ms", flips, cut);
            let _ = jumplist::custom(&data);
        }

        /// Any bytes at all.
        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = jumplist::automatic(&data);
            let _ = jumplist::custom(&data);
        }
    }
}

/// Header counts far beyond the file: refused or read within bounds, not
/// allocated.
#[test]
fn huge_header_counts_are_bounded() {
    let mut data =
        fs::read(fixtures().join("jumplist/Win7/1b4dd67f29cb1962.automaticDestinations-ms"))
            .unwrap();
    for at in [44, 72] {
        data[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    let _ = jumplist::automatic(&data);
    let mut custom =
        fs::read(fixtures().join("jumplist/plaso/368d807282ccde9d.customDestinations-ms")).unwrap();
    custom[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(jumplist::custom(&custom).categories.len(), 5);
}

/// A compound file (version 3, 512-byte sectors) holding `streams` in
/// regular sectors (each at least 4,096 bytes, so none is in the mini
/// stream), every entry a right sibling of the one before.
fn compound_file(streams: &[(&str, Vec<u8>)]) -> Vec<u8> {
    const SECTOR: usize = 512;
    const END: u32 = 0xffff_fffe;
    const FREE: u32 = 0xffff_ffff;
    let data: Vec<usize> = streams
        .iter()
        .map(|(_, b)| b.len().div_ceil(SECTOR))
        .collect();
    let dir = (streams.len() + 1).div_ceil(4);
    let fat_sectors = 1;
    let mut fat = vec![FREE; SECTOR / 4];
    fat[0] = 0xffff_fffd; // the FAT itself
    let mut next = fat_sectors;
    let mut chain = |n: usize, next: &mut usize| {
        let start = *next;
        for i in 0..n {
            fat[start + i] = if i + 1 == n {
                END
            } else {
                (start + i + 1) as u32
            };
        }
        *next += n;
        start as u32
    };
    let dir_start = chain(dir, &mut next);
    let starts: Vec<u32> = data.iter().map(|&n| chain(n, &mut next)).collect();
    assert!(next <= SECTOR / 4);
    let entry = |name: &str, kind: u8, right: u32, child: u32, start: u32, size: u32| {
        let mut e = vec![0u8; 128];
        let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
        for (i, u) in units.iter().enumerate() {
            e[2 * i..2 * i + 2].copy_from_slice(&u.to_le_bytes());
        }
        e[64..66].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
        e[66] = kind;
        e[67] = 1; // black
        e[68..72].copy_from_slice(&FREE.to_le_bytes()); // no left sibling
        e[72..76].copy_from_slice(&right.to_le_bytes());
        e[76..80].copy_from_slice(&child.to_le_bytes());
        e[116..120].copy_from_slice(&start.to_le_bytes());
        e[120..124].copy_from_slice(&size.to_le_bytes());
        e
    };
    let mut header = vec![0u8; SECTOR];
    header[..8].copy_from_slice(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    header[24..26].copy_from_slice(&0x3eu16.to_le_bytes());
    header[26..28].copy_from_slice(&3u16.to_le_bytes());
    header[28..30].copy_from_slice(&0xfffeu16.to_le_bytes());
    header[30..32].copy_from_slice(&9u16.to_le_bytes());
    header[32..34].copy_from_slice(&6u16.to_le_bytes());
    header[44..48].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
    header[48..52].copy_from_slice(&dir_start.to_le_bytes());
    header[56..60].copy_from_slice(&4096u32.to_le_bytes());
    header[60..64].copy_from_slice(&END.to_le_bytes());
    header[68..72].copy_from_slice(&END.to_le_bytes());
    for i in 0..109 {
        let v = if i < fat_sectors { i as u32 } else { FREE };
        header[76 + 4 * i..80 + 4 * i].copy_from_slice(&v.to_le_bytes());
    }
    let mut out = header;
    for v in &fat {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let mut directory = entry("Root Entry", 5, FREE, 1, END, 0);
    for (k, (name, bytes)) in streams.iter().enumerate() {
        let right = if k + 1 < streams.len() {
            (k + 2) as u32
        } else {
            FREE
        };
        directory.extend(entry(name, 2, right, FREE, starts[k], bytes.len() as u32));
    }
    directory.resize(dir * SECTOR, 0);
    out.extend(directory);
    for (_, bytes) in streams {
        let mut b = bytes.clone();
        b.resize(b.len().div_ceil(SECTOR) * SECTOR, 0);
        out.extend(b);
    }
    out
}

#[test]
fn destlist_entries_repeating_a_stream_read_it_once() {
    // A DestList (version 4) of 200 entries all naming stream "1": the link
    // is read for the first, and each repeat is a problem, not a copy.
    let link = sample_link();
    let mut stream = link.clone();
    stream.resize(4096, 0);
    let entries = 200;
    let mut dest = vec![0u8; 32];
    dest[..4].copy_from_slice(&4u32.to_le_bytes());
    dest[4..8].copy_from_slice(&(entries as u32).to_le_bytes());
    for _ in 0..entries {
        let mut e = vec![0u8; 130];
        e[88..92].copy_from_slice(&1u32.to_le_bytes()); // entry number: stream "1"
        e[108..112].copy_from_slice(&u32::MAX.to_le_bytes()); // not pinned
        e[128..130].copy_from_slice(&1u16.to_le_bytes()); // a 1-character path
        e.extend_from_slice(&u16::from(b'x').to_le_bytes());
        e.extend_from_slice(&[0; 4]); // trailer
        dest.extend(e);
    }
    dest.resize(dest.len().max(4096), 0);
    let file = compound_file(&[("DestList", dest), ("1", stream)]);
    let list = jumplist::automatic(&file).unwrap();
    assert_eq!(list.destinations.len(), entries);
    let with_link = list
        .destinations
        .iter()
        .filter(|d| d.link.is_some())
        .count();
    assert_eq!(with_link, 1);
    let repeats = list
        .problems
        .iter()
        .filter(|p| p.contains("repeats stream 1"))
        .count();
    assert_eq!(repeats, entries - 1, "{:?}", list.problems.first());
}

/// A real link: the first entry of Windows 10 Explorer's list.
fn sample_link() -> Vec<u8> {
    let data =
        fs::read(fixtures().join("jumplist/Win10/f01b4d95cf55d32a.automaticDestinations-ms"))
            .unwrap();
    CompoundFile::parse(&data)
        .unwrap()
        .stream("1")
        .unwrap()
        .unwrap()
}

/// A property store holding `System.ItemNameDisplay` = `name`.
fn property_store(name: &str) -> Vec<u8> {
    // {B725F130-47EF-101A-A5F1-02608C9EEBAC}, property 10
    let fmtid = [
        0x30, 0xf1, 0x25, 0xb7, 0xef, 0x47, 0x1a, 0x10, 0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb,
        0xac,
    ];
    let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut typed = vec![0x1f, 0, 0, 0];
    typed.extend_from_slice(&(units.len() as u32).to_le_bytes());
    typed.extend(units.iter().flat_map(|u| u.to_le_bytes()));
    typed.resize(typed.len().div_ceil(4) * 4, 0);
    let mut value = Vec::new();
    value.extend_from_slice(&((9 + typed.len()) as u32).to_le_bytes());
    value.extend_from_slice(&10u32.to_le_bytes());
    value.push(0);
    value.extend(typed);
    let mut storage = vec![0; 4];
    storage.extend_from_slice(b"1SPS");
    storage.extend_from_slice(&fmtid);
    storage.extend(value);
    storage.extend_from_slice(&0u32.to_le_bytes());
    let n = storage.len() as u32;
    storage[..4].copy_from_slice(&n.to_le_bytes());
    storage.extend_from_slice(&0u32.to_le_bytes());
    storage
}

/// A version 4 `DestList` entry naming stream `number`, with `path` and a property store.
fn entry_v4(number: u32, path: &str, store: &[u8]) -> Vec<u8> {
    let mut e = vec![0u8; 130];
    e[88..92].copy_from_slice(&number.to_le_bytes());
    e[100..108].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
    e[108..112].copy_from_slice(&u32::MAX.to_le_bytes()); // not pinned
    e[116..120].copy_from_slice(&7u32.to_le_bytes()); // interaction count
    let units: Vec<u16> = path.encode_utf16().collect();
    e[128..130].copy_from_slice(&(units.len() as u16).to_le_bytes());
    e.extend(units.iter().flat_map(|u| u.to_le_bytes()));
    e.extend_from_slice(&(store.len() as u32).to_le_bytes());
    e.extend_from_slice(store);
    e
}

fn dest_list(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut dest = vec![0u8; 32];
    dest[..4].copy_from_slice(&4u32.to_le_bytes());
    dest[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    dest[16..20].copy_from_slice(&3u32.to_le_bytes()); // last entry number
    for e in entries {
        dest.extend_from_slice(e);
    }
    dest
}

/// Windows 10 and 11 can give an entry its own property store, after its path; the next entry
/// follows the store.
#[test]
fn entries_with_property_stores() {
    let store = property_store("Quarterly report");
    let mut dest = dest_list(&[
        entry_v4(1, r"C:\Reports\q3.xlsx", &store),
        entry_v4(2, r"C:\Reports\q4.xlsx", &[]),
    ]);
    dest.resize(dest.len().max(4096), 0);
    let mut link = sample_link();
    link.resize(4096, 0);
    let file = compound_file(&[("DestList", dest), ("1", link.clone()), ("2", link)]);
    let list = jumplist::automatic(&file).unwrap();
    assert!(list.problems.is_empty(), "{:?}", list.problems);
    let paths: Vec<&str> = list.destinations.iter().map(|d| d.path.as_str()).collect();
    assert_eq!(paths, [r"C:\Reports\q3.xlsx", r"C:\Reports\q4.xlsx"]);
    let first = &list.destinations[0];
    assert_eq!(first.properties.len(), 1);
    assert_eq!(
        first.properties[0].canonical_name(),
        Some("System.ItemNameDisplay")
    );
    assert_eq!(first.properties[0].value.display(), "Quarterly report");
    assert_eq!(first.interaction_count, Some(7));
    assert!(
        list.destinations[1].properties.is_empty(),
        "{:?}",
        list.destinations[1].properties
    );
    let header = list.header.as_ref().unwrap();
    assert_eq!(
        (header.version, header.entry_count, header.last_entry_number),
        (4, 2, 3)
    );
}

/// The `DestListPropertyStore` stream (a size, then a property store), and a link stream no
/// entry names.
#[test]
fn the_list_property_store_and_unlisted_streams() {
    // In any case: compound files compare names without regard to case.
    for store_name in ["DestListPropertyStore", "DESTLISTPROPERTYSTORE"] {
        let mut dest = dest_list(&[entry_v4(1, "C:\\a.txt", &[])]);
        dest.resize(4096, 0);
        let store = property_store("Shared store");
        let mut stream = (store.len() as u32).to_le_bytes().to_vec();
        stream.extend(store);
        stream.resize(4096, 0);
        let mut link = sample_link();
        link.resize(4096, 0);
        let file = compound_file(&[
            ("DestList", dest),
            (store_name, stream),
            ("1", link.clone()),
            ("9", link),
        ]);
        let list = jumplist::automatic(&file).unwrap();
        assert!(list.problems.is_empty(), "{:?}", list.problems);
        assert_eq!(list.properties.len(), 1, "{store_name}");
        assert_eq!(list.properties[0].value.display(), "Shared store");
        assert_eq!(list.unlisted.len(), 1, "{store_name}: {:?}", list.unlisted);
        assert_eq!(list.unlisted[0].name, "9");
        assert!(list.unlisted[0].link.is_some());
    }
}

/// An entry whose stream is missing, and counts that disagree with the header.
#[test]
fn missing_streams_and_counts_are_problems() {
    let mut dest = dest_list(&[entry_v4(1, "C:\\a.txt", &[]), entry_v4(2, "C:\\b.txt", &[])]);
    dest[4..8].copy_from_slice(&5u32.to_le_bytes());
    dest.resize(4096, 0);
    let mut link = sample_link();
    link.resize(4096, 0);
    let list = jumplist::automatic(&compound_file(&[("DestList", dest), ("1", link)])).unwrap();
    assert_eq!(list.destinations.len(), 2);
    assert_eq!(
        list.problems,
        [
            "DestList: the header counts 5 entries, the stream holds 2",
            "entry 2 has no stream"
        ]
    );
}

/// A file that ends inside its last sector: the bytes that are there are read.
#[test]
fn a_file_cut_inside_its_last_sector() {
    let data =
        fs::read(fixtures().join("jumplist/artemis/3d2110c4a0cb6d15.automaticDestinations-ms"))
            .unwrap();
    assert_ne!(data.len() % 512, 0);
    let list = jumplist::automatic(&data).unwrap();
    assert_eq!(list.destinations.len(), 41);
    assert!(list.problems.is_empty(), "{:?}", list.problems);
    // Cut further, the stream comes out short and says so.
    let short = jumplist::automatic(&data[..data.len() - 100]).unwrap();
    assert!(
        short.problems.iter().any(|p| p.contains("the file ends")),
        "{:?}",
        short.problems
    );
}

/// Application names, and paths with shell namespace GUIDs named.
#[cfg(feature = "guid-names")]
#[test]
fn application_and_folder_names() {
    assert_eq!(
        jumplist::appid::app_name("f01b4d95cf55d32a"),
        Some("Windows Explorer Windows 8.1")
    );
    let data =
        fs::read(fixtures().join("jumplist/Win10/7e4dca80246863e3.automaticDestinations-ms"))
            .unwrap();
    let list = jumplist::automatic(&data).unwrap();
    // JLECmd: ::{26EE0668-…}\5\::{BB06C0E4-…} ==> ControlPanelHome\5\System
    assert_eq!(
        list.destinations[0].display_path(),
        r"ControlPanelHome\5\System"
    );
}

/// `data` with the compound file directory entry of stream `from` renamed `to` (a name of the same
/// length).
fn rename_stream(data: &mut [u8], from: &str, to: &str) {
    let name = |s: &str| -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    let (from, to) = (name(from), name(to));
    assert_eq!(from.len(), to.len());
    // Directory entries are 128 bytes, sector-aligned: the name, its size in bytes at 64, the
    // type at 66 (2 = stream).
    let at = (0..data.len() - 128)
        .step_by(128)
        .find(|&o| {
            data[o..o + from.len()] == from[..]
                && data[o + 64..o + 66] == (from.len() as u16).to_le_bytes()
                && data[o + 66] == 2
        })
        .unwrap();
    data[at..at + to.len()].copy_from_slice(&to);
}

/// Compound files compare directory entry names without regard to case: stream `A` holds entry
/// `a`'s link, `DESTLIST` is the `DestList`.
#[test]
fn stream_names_match_in_any_case() {
    let data = fs::read(
        fixtures().join("jumplist/jumplist_parser/other/5f7b5f1e01b83767.automaticDestinations-ms"),
    )
    .unwrap();
    let original = jumplist::automatic(&data).unwrap();
    assert!(original.destinations.iter().any(|d| d.entry == 0xa));
    let mut renamed = data.clone();
    rename_stream(&mut renamed, "a", "A");
    rename_stream(&mut renamed, "DestList", "DESTLIST");
    let list = jumplist::automatic(&renamed).unwrap();
    assert!(list.problems.is_empty(), "{:?}", list.problems);
    assert!(list.unlisted.is_empty(), "{:?}", list.unlisted);
    assert_eq!(list.destinations.len(), 37);
    for (a, b) in original.destinations.iter().zip(&list.destinations) {
        assert_eq!(a.link, b.link, "entry {:x}", a.entry);
        assert!(b.link.is_some(), "entry {:x}", b.entry);
    }
}
