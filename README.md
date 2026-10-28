# ys-jump-lists-parser

Yamato Security's parser for Windows jump lists (`*.automaticDestinations-ms`,
`*.customDestinations-ms`), for [Juntei](https://github.com/Yamato-Security/juntei). It grew from the
jump list and compound file code of [sootmark-shell](https://github.com/Sootmark/shell) (Florian
Amette), as Yamato Security's [ys-lnk-parser](https://github.com/Yamato-Security/ys-lnk-parser)
improved it; that history and the MIT OR Apache-2.0 license are kept, and links are read with
ys-lnk-parser.

## Why this base

The Rust jump list parsers were run on 77 public jump lists (51 automatic, 26 custom: Windows 7 to
11, `DestList` versions 1, 3, 4 and 6, from the test sets of jumplist_parser, DFIRArtifactMuseum,
Eric Zimmerman's OleCf, dtformats, fillyfoal, plaso, issen, artemis, dissect, kairon, sootmark-shell,
cfb-forensic, lnk-forensic and LnkParse3) and compared with Eric Zimmerman's JLECmd 2026.10 (built
from source), with libyal's dtformats as a second reference for the `DestList`; then each read
15,400 damaged copies of them.

| Crate | Read | Differences from JLECmd | Damaged copies: panics / allocations over 1 GiB / hangs |
| --- | --- | --- | --- |
| **sootmark-shell 0.3.0**, as in ys-lnk-parser 0.4.0 | 76 | no entries from the 2 files that end inside their last sector (41 and 37 in JLECmd) | 0 / 0 / 0 (0.3.0: one hang) |
| postmortem 0.2.6 | 77 | no birth identifiers; version 1 times wrong; no category names; the 2 cut files | 0 / 0 / 0 |
| jumplist_parser 0.1.0 | 76 | entries re-sorted (99 of 318 out of place); no interaction count; microsecond times | 3 panics (`unwrap`) / 164 / 0 |
| lnk-forensic (4af05f9) | 75 | times to the second; no format version, no categories; 14 target paths | 0 / 0 / 0 |
| artemis 0.21.0 | 75 | millisecond times; no interaction count, version or categories; 14 target paths; its parser is private to the crate | 0 / 204 / 0 |
| ChronosFracture 0.1.0 | 76 | version 3 and 4 entries read at the wrong offsets | 0 / 182 / 0 |
| issen (4dd4a91) | 77 | through lnk-core: the tracker identifiers, times and target paths of most entries; no version or categories | 0 / 0 / 0 |

sootmark-shell's code agreed with JLECmd on every field of every file it read, links included, and
came with tests against JLECmd and olefile; what it missed is below.

## What changed

| Change | Why |
| --- | --- |
| A file that ends inside its last sector (Windows 11 writes them) is read: the partial sector holds the end of the `DestList` and of streams | 2 public files lost every entry (78 in all); libolecf and JLECmd read them |
| An entry's property store (`DestList` 2 and later) is read and skipped by its size; it was assumed empty, so an entry with one shifted every later entry | from the format (JLECmd, dtformats); a built list in the tests |
| From version 2 on, entries run to the end of the stream (as JLECmd reads them; zeros are padding), and a header count that disagrees is a problem | JLECmd |
| The `DestList` header (pinned count, counter, last entry number, revision) and each entry's checksum and score; a host name in UTF-16 | JLECmd, dtformats |
| The `DestListPropertyStore` stream, and streams no entry names (with their links): what a removed entry or damage leaves | |
| Custom lists: a category is kept when its footer is missing or an entry isn't a link (its class is recorded); bytes after the last category are counted, and the links in them are recovered (`Custom::leftover`) | a Windows 11 Chrome list holds two pages ("most visited", "recently closed") in the end of an older, longer version of the list; JLECmd refuses that file |
| Problems for a stream the file cuts short and for an entry without a stream | |
| The application each AppID belongs to (`appid`): Eric Zimmerman's table (MIT), 714 IDs | JLECmd |
| Paths of shell namespace items (`::{GUID}\…`, `knownfolder:{…}`) named (`Destination::display_path`) | JLECmd |
| Links in a code page other than Windows-1252 (`Options::code_page`, feature `codepages`) | ys-lnk-parser |
| CD and DVD burn items in links (`D:\autorun.inf` was `D:\`), in ys-lnk-parser (Yamato-Security/ys-lnk-parser#4) | the one target path that differed from JLECmd |

On the 77 public jump lists, every `DestList` field and every link's path agrees with JLECmd on all
389 entries and links it reads; the six files it refuses (four empty custom lists, one without its
last footer, one that isn't a jump list) are read, the last with its problems. The 15,400 damaged
copies give no panic, allocation over 1 GiB or hang.

```rust
let data = std::fs::read("f01b4d95cf55d32a.automaticDestinations-ms")?;
match jumplist::parse(&data, &jumplist::Options::default())? {
    jumplist::JumpList::Automatic(list) => {
        for d in &list.destinations {
            println!("{} {} {} {}", d.position, d.last_used, d.display_path(), d.interaction_count.unwrap_or(0));
        }
    }
    jumplist::JumpList::Custom(list) => {
        for (category, link) in list.links() {
            println!("{}: {} {}", category.kind.name(), link.target_path(), link.arguments);
        }
        for old in &list.leftover {
            println!("left over at {}: {}", old.offset, old.link.arguments);
        }
    }
}
println!("{:?}", jumplist::appid::app_name("f01b4d95cf55d32a"));
```

Use it from Cargo by commit (it is not published):

```toml
[dependencies]
ys-jump-lists = { git = "https://github.com/Yamato-Security/ys-jump-lists-parser", rev = "<commit>" }
```

Features: `guid-names` (default; names of shell GUIDs, about 900 KB), `codepages` (code pages other
than Windows-1252 for links; Rust 1.88). Without features it builds on Rust 1.80, and for
`wasm32-unknown-unknown`.

## What it reads

- `automatic`: the `DestList` header and each entry (entry number, position, last use, pin, interaction count, score, checksum, machine, the tracker's volume and file identifiers now and at birth, the time and MAC address in a version 1 file identifier, path, property store) with its link, most recent first; the `DestListPropertyStore` stream; streams no entry names; the compound file's streams.
- `custom`: each category (named, frequent or recent, tasks) with its links, other objects' classes, and links left after the last category.
- `appid`: application names by AppID.
- `compound`: compound files (MS-CFB), both sector sizes, mini streams, files cut inside their last sector; every chain and count bounded by the file.

Damage is reported in each result's `problems`, never a panic; what can be read is.

## How it's checked

- Every automatic jump list among the fixtures (13: Windows 7 to 11, `DestList` versions 1, 3, 4 and 6, 512- and 4,096-byte sectors, two cut inside their last sector) against JLECmd: all 136 entries on every `DestList` column and their links (`tests/jumplist.rs`); custom lists' links and category names, and the lists JLECmd refuses by hand.
- Built lists for what the fixtures don't hold: entries with property stores, the `DestListPropertyStore` stream, a stream no entry names, a missing stream, wrong counts, a cut file, a `DestList` repeating one stream 200 times.
- Compound files against olefile (`tests/fixtures/oracle/olefile_tree.py`): every directory entry of the 13 jump lists and plaso's `Document.doc` (`tests/compound.rs`).
- Damaged and truncated lists and arbitrary bytes (property tests): parsed or refused, never a panic.

Test files and their licenses: `tests/fixtures/jumplist/README.md`.

## License

MIT OR Apache-2.0, as sootmark-shell (`LICENSE-MIT`, `LICENSE-APACHE`). The AppID table is Eric
Zimmerman's (MIT, `src/appid/LICENSE`).
