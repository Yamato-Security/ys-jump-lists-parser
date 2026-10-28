//! Automatic jump lists (`%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\
//! <AppID>.automaticDestinations-ms`): what Windows records by itself of the files and folders an
//! application opened, most recently used first, with pinned items.
//!
//! A compound file: a `DestList` stream (a header, then one entry per item: when it was last used,
//! its pin state and usage counts, the machine and the tracker identifiers of its target, its
//! path), one LNK stream per entry named by its entry number in hexadecimal, and on newer Windows
//! a `DestListPropertyStore` stream.
//!
//! `DestList` versions: 1 (Windows 7 and 8), 3 and 4 (Windows 10) and 6 (Windows 11); from
//! version 2 on an entry is longer and may carry a property store of its own.

use shell::lnk::{self, Link};
use shell::property::{self, Property};

use crate::compound::{self, CompoundFile};
use crate::{f32_at, u16_at, u32_at, u64_at, Options};

/// The `DestList` header.
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    /// The format version: 1 (Windows 7 and 8), 3 and 4 (Windows 10), 6 (Windows 11).
    pub version: u32,
    /// How many entries the header counts.
    pub entry_count: u32,
    /// How many of them are pinned.
    pub pinned_count: u32,
    /// A floating-point counter (Eric Zimmerman: `UnknownCounter`).
    pub counter: f32,
    /// The highest entry number handed out so far: entries numbered below it and missing
    /// from the list were removed.
    pub last_entry_number: u32,
    /// How many times the list was rewritten.
    pub last_revision: u32,
}

/// One `DestList` entry and the link it describes.
#[derive(Debug, Clone, PartialEq)]
pub struct Destination {
    /// Its place in the list: 0 is the most recently used.
    pub position: usize,
    /// Its entry number, which names its LNK stream (in hexadecimal).
    pub entry: u32,
    /// A checksum of the entry.
    pub checksum: u64,
    /// When it was last used (FILETIME, UTC; 0 when not recorded).
    pub last_used: u64,
    /// Its position among the pinned items, `None` when it isn't pinned.
    pub pin: Option<u32>,
    /// How many times it was used (version 2 and later; `None` before).
    pub interaction_count: Option<u32>,
    /// A floating-point score that grows with use and decays with time (Eric Zimmerman:
    /// `AccessCount`).
    pub score: f32,
    /// The NetBIOS name of the machine that holds the target.
    pub hostname: String,
    /// The distributed link tracking identifiers of the target's volume and file, now and when
    /// they were created (`{…}` GUIDs; empty when not recorded).
    pub volume_droid: String,
    /// The file's tracking identifier.
    pub file_droid: String,
    /// The volume's identifier when the file was created.
    pub volume_birth_droid: String,
    /// The file's identifier when it was created.
    pub file_birth_droid: String,
    /// When the file's tracking identifier was made, and the MAC address of the machine that
    /// made it: version 1 GUIDs only (0 and empty otherwise).
    pub droid_created: u64,
    /// The MAC address in the file's tracking identifier.
    pub mac: String,
    /// The target's path, as the list stores it: a file system path, a URL, or shell
    /// namespace GUIDs (`::{…}\…`, `knownfolder:{…}`; see [`Destination::display_path`]).
    pub path: String,
    /// The entry's own property store (version 2 and later; usually empty).
    pub properties: Vec<Property>,
    /// The LNK stream of the entry, when there is one that reads.
    pub link: Option<Link>,
}

impl Destination {
    /// The path with the shell namespace GUIDs in it named (`::{20D04FE0-…}` is `This PC`,
    /// `knownfolder:{FDD39AD0-…}` is `Documents`), as Eric Zimmerman's tools name them; the
    /// path itself when it has none.
    #[must_use]
    pub fn display_path(&self) -> String {
        display_path(&self.path)
    }
}

/// An LNK stream that no `DestList` entry names: left behind by a removed entry, or from a
/// damaged list.
#[derive(Debug, Clone, PartialEq)]
pub struct Unlisted {
    /// The stream's name.
    pub name: String,
    /// Its link, when it reads.
    pub link: Option<Link>,
}

/// A parsed automatic jump list.
#[derive(Debug, Clone, PartialEq)]
pub struct Automatic {
    /// The `DestList` header; `None` when the list is empty (no `DestList`, or an empty one).
    pub header: Option<Header>,
    /// The entries, most recently used first.
    pub destinations: Vec<Destination>,
    /// The `DestListPropertyStore` stream's properties (newer Windows; usually empty).
    pub properties: Vec<Property>,
    /// LNK streams no entry names.
    pub unlisted: Vec<Unlisted>,
    /// The compound file's streams other than the root, in directory order: their names and
    /// sizes.
    pub streams: Vec<(String, u64)>,
    /// What couldn't be read, and why: damage to the compound file, entries or links that
    /// don't read, entries without a stream, and counts that disagree.
    pub problems: Vec<String>,
}

impl Automatic {
    /// The `DestList` version, 0 when the list is empty.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.header.as_ref().map_or(0, |h| h.version)
    }
}

/// Parse an automatic jump list, with Windows-1252 for ANSI strings in its links.
///
/// # Errors
/// When it isn't a compound file. A missing or damaged `DestList` leaves no entries and a
/// problem.
pub fn automatic(data: &[u8]) -> Result<Automatic, compound::Error> {
    automatic_with(data, &Options::default())
}

/// [`automatic`] with options (the code page of ANSI strings).
///
/// # Errors
/// When it isn't a compound file.
pub fn automatic_with(data: &[u8], options: &Options) -> Result<Automatic, compound::Error> {
    let file = CompoundFile::parse(data)?;
    let mut list = Automatic {
        header: None,
        destinations: Vec::new(),
        properties: Vec::new(),
        unlisted: Vec::new(),
        streams: file
            .entries
            .iter()
            .filter(|e| e.kind == compound::STREAM)
            .map(|e| (e.name.clone(), e.size))
            .collect(),
        problems: file.problems.clone(),
    };
    let link_options = lnk::Options {
        code_page: options.code_page,
    };
    let read_stream = |name: &str, problems: &mut Vec<String>| -> Option<Vec<u8>> {
        let entry = file
            .entries
            .iter()
            .find(|e| e.kind == compound::STREAM && e.name == name)?;
        match file.contents(entry) {
            Ok(bytes) => {
                if (bytes.len() as u64) < entry.size {
                    problems.push(format!(
                        "{name}: the file ends {} bytes into its {} bytes",
                        bytes.len(),
                        entry.size
                    ));
                }
                Some(bytes)
            }
            Err(e) => {
                problems.push(format!("{name}: {e}"));
                None
            }
        }
    };
    let mut problems = Vec::new();
    if let Some(dest_list) = read_stream("DestList", &mut problems) {
        read_dest_list(&dest_list, options.code_page, &mut list, &mut problems);
    }
    if let Some(store) = read_stream("DestListPropertyStore", &mut problems) {
        // A 32-bit size, then the property store.
        if u32_at(&store, 0).is_some_and(|size| size > 0) {
            list.properties = property::parse(&store[4..], options.code_page);
        }
    }
    // Each entry's link, from the stream its number names. A number seen again is damage, and
    // reading its stream again would copy the link once per entry (a 90 KB file of repeated
    // entries reached 853 MiB).
    let mut named = std::collections::HashSet::new();
    for d in &mut list.destinations {
        let name = format!("{:x}", d.entry);
        if !named.insert(name.clone()) {
            problems.push(format!(
                "DestList entry {} repeats stream {name}",
                d.position
            ));
            continue;
        }
        match read_stream(&name, &mut problems) {
            Some(bytes) => match lnk::parse_with(&bytes, &link_options) {
                Ok(link) => d.link = Some(link),
                Err(e) => problems.push(format!("entry {name}: {e}")),
            },
            None if !file.entries.iter().any(|e| e.name == name) => {
                problems.push(format!("entry {name} has no stream"));
            }
            None => {}
        }
    }
    // Streams no entry names: what a removed entry or a damaged list left behind.
    let others: Vec<String> = list
        .streams
        .iter()
        .map(|(name, _)| name.clone())
        .filter(|n| n != "DestList" && n != "DestListPropertyStore" && !named.contains(n))
        .collect();
    for name in others {
        let link = read_stream(&name, &mut problems).and_then(|bytes| {
            lnk::parse_with(&bytes, &link_options)
                .map_err(|e| problems.push(format!("unlisted stream {name}: {e}")))
                .ok()
        });
        list.unlisted.push(Unlisted { name, link });
    }
    list.problems.extend(problems);
    Ok(list)
}

/// Bytes before the path's length: 112 in version 1, 128 from version 2 on.
const V1_PATH_AT: usize = 112;
const V2_PATH_AT: usize = 128;

/// The `DestList` stream: its header, then its entries. Version 1 has as many entries as the
/// header counts; from version 2 on they run to the end of the stream (as Eric Zimmerman's
/// tools read them; zeros at the end are padding), and a count that disagrees is a problem.
fn read_dest_list(data: &[u8], code_page: u16, list: &mut Automatic, problems: &mut Vec<String>) {
    if data.is_empty() {
        return;
    }
    if data.len() < 32 {
        problems.push(format!(
            "DestList: {} bytes, shorter than its header",
            data.len()
        ));
        return;
    }
    let header = Header {
        version: u32_at(data, 0).unwrap_or(0),
        entry_count: u32_at(data, 4).unwrap_or(0),
        pinned_count: u32_at(data, 8).unwrap_or(0),
        counter: f32_at(data, 12).unwrap_or(0.0),
        last_entry_number: u32_at(data, 16).unwrap_or(0),
        last_revision: u32_at(data, 24).unwrap_or(0),
    };
    let version = header.version;
    let mut at = 32;
    while at < data.len() && (version >= 2 || list.destinations.len() < header.entry_count as usize)
    {
        let position = list.destinations.len();
        let rest = &data[at..];
        if rest.iter().all(|&b| b == 0) {
            // Padding, not entries.
            break;
        }
        match destination(rest, position, version, code_page) {
            Ok((d, stride)) => {
                list.destinations.push(d);
                at += stride;
            }
            Err(problem) => {
                problems.push(format!("DestList entry {position} at {at}: {problem}"));
                break;
            }
        }
    }
    if version >= 2 && list.destinations.len() != header.entry_count as usize {
        problems.push(format!(
            "DestList: the header counts {} entries, the stream holds {}",
            header.entry_count,
            list.destinations.len()
        ));
    }
    list.header = Some(header);
}

/// The entry at the start of `entry`, and its size; what's wrong when it can't be read.
fn destination(
    entry: &[u8],
    position: usize,
    version: u32,
    code_page: u16,
) -> Result<(Destination, usize), String> {
    let path_at = if version >= 2 { V2_PATH_AT } else { V1_PATH_AT };
    let Some(chars) = u16_at(entry, path_at).map(usize::from) else {
        return Err(format!("{} bytes, too short for an entry", entry.len()));
    };
    let path_end = path_at + 2 + 2 * chars;
    let Some(path_bytes) = entry.get(path_at + 2..path_end) else {
        return Err(format!("a path of {chars} characters runs past the end"));
    };
    // From version 2 on, a property store follows the path: its size, then the store.
    let (properties, size) = if version >= 2 {
        let Some(size) = u32_at(entry, path_end).map(|s| s as usize) else {
            return Err("its property store size is missing".to_owned());
        };
        let Some(store) = entry.get(path_end + 4..path_end + 4 + size) else {
            return Err(format!(
                "a property store of {size} bytes runs past the end"
            ));
        };
        let properties = if size > 0 {
            property::parse(store, code_page)
        } else {
            Vec::new()
        };
        (properties, path_end + 4 + size)
    } else {
        (Vec::new(), path_end)
    };
    let units: Vec<u16> = path_bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let (droid_created, mac) = shell::item::guid_v1(&entry[24..40]).unwrap_or_default();
    let d = Destination {
        position,
        entry: u32_at(entry, 88).unwrap_or(0),
        checksum: u64_at(entry, 0).unwrap_or(0),
        last_used: u64_at(entry, 100).unwrap_or(0),
        pin: u32_at(entry, 108).filter(|&p| p != u32::MAX),
        interaction_count: if version >= 2 {
            u32_at(entry, 116)
        } else {
            None
        },
        score: f32_at(entry, 96).unwrap_or(0.0),
        hostname: hostname(&entry[72..88]),
        volume_droid: droid(&entry[8..24]),
        file_droid: droid(&entry[24..40]),
        volume_birth_droid: droid(&entry[40..56]),
        file_birth_droid: droid(&entry[56..72]),
        droid_created,
        mac,
        path: String::from_utf16_lossy(&units),
        properties,
        link: None,
    };
    Ok((d, size))
}

/// The NetBIOS name: ASCII, or UTF-16 when its second byte is 0 (as Eric Zimmerman's tools read
/// it), up to the first NUL.
fn hostname(bytes: &[u8]) -> String {
    if bytes.get(1) == Some(&0) && bytes.first().is_some_and(|&b| b != 0) {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| char::from(b))
            .collect()
    }
}

/// A tracker identifier, empty when it's all zeros (not recorded).
fn droid(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        String::new()
    } else {
        shell::item::guid(bytes).unwrap_or_default()
    }
}

/// `path` with the GUIDs of shell namespace items named: each `::{…}` (or `{…}`) component of a
/// `::` path, and the folder of a `knownfolder:{…}` path; unchanged when none has a name.
pub(crate) fn display_path(path: &str) -> String {
    let named = |component: &str| -> Option<&'static str> {
        let start = component.find('{')?;
        let end = start + component[start..].find('}')?;
        shell::guid_names::name(&component[start..=end])
    };
    if let Some(guid) = path.strip_prefix("knownfolder:") {
        return named(guid).map_or_else(|| path.to_owned(), str::to_owned);
    }
    if !path.starts_with("::") {
        return path.to_owned();
    }
    path.split('\\')
        .map(|component| named(component).unwrap_or(component))
        .collect::<Vec<_>>()
        .join("\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames_in_either_encoding() {
        assert_eq!(hostname(b"desktop-1\0\0\0\0\0\0\0"), "desktop-1");
        let wide: Vec<u8> = "pc7"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .chain([0; 10])
            .collect();
        assert_eq!(hostname(&wide), "pc7");
        assert_eq!(hostname(&[0; 16]), "");
    }

    #[cfg(feature = "guid-names")]
    #[test]
    fn shell_namespace_paths_are_named() {
        // This PC, then a folder by name
        assert_eq!(
            display_path(r"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\C:\Temp"),
            r"This PC\C:\Temp"
        );
        assert_eq!(display_path("C:\\Temp"), "C:\\Temp");
        assert_eq!(
            display_path("knownfolder:{00000000-0000-0000-0000-000000000000}"),
            "knownfolder:{00000000-0000-0000-0000-000000000000}"
        );
    }
}
