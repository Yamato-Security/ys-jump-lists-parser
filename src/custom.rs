//! Custom jump lists (`%AppData%\Microsoft\Windows\Recent\CustomDestinations\
//! <AppID>.customDestinations-ms`): the menu an application builds itself, its own categories
//! ("Most visited", "Recently closed"), its tasks, and the frequent and recent categories
//! Windows fills from its automatic jump list.
//!
//! A header (format version 2, the number of categories), then each category: its type and name
//! or identifier, its entries (a class identifier, then the object: a shell link for the
//! `{00021401-…}` class), and a footer (`0xBABFFBAB`).
//!
//! Windows rewrites the file in place: when a new list is shorter than the old one, the old one's
//! end stays after it. Links found there are [`Custom::leftover`], entries the list no longer
//! shows (a browser's "Recently closed" pages, say).

use shell::lnk::{self, Link};

use crate::{Options, u16_at, u32_at, utf16_units};

/// What a category holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// One the application named ("Most visited", "Recently closed").
    Custom(String),
    /// A category Windows fills from the automatic jump list: 1 frequent, 2 recent. It holds no
    /// entries itself.
    Known(u32),
    /// The application's tasks.
    Tasks,
}

impl Kind {
    /// Its name: the application's, `Frequent` or `Recent` (or `Known <id>`), or `Tasks`.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Kind::Custom(name) => name.clone(),
            Kind::Known(1) => "Frequent".to_owned(),
            Kind::Known(2) => "Recent".to_owned(),
            Kind::Known(id) => format!("Known {id}"),
            Kind::Tasks => "Tasks".to_owned(),
        }
    }
}

/// A category.
#[derive(Debug, Clone, PartialEq)]
pub struct Category {
    /// What it is.
    pub kind: Kind,
    /// Its links, in order.
    pub links: Vec<Link>,
    /// Entries that aren't shell links, by class identifier (`{…}`): their size isn't known, so
    /// the category's other entries after one can't be read.
    pub other_objects: Vec<String>,
}

/// A parsed custom jump list.
#[derive(Debug, Clone, PartialEq)]
pub struct Custom {
    /// The format version (2).
    pub version: u32,
    /// The categories, in order.
    pub categories: Vec<Category>,
    /// Bytes after the last category.
    pub trailing: usize,
    /// Links in those bytes, left from an earlier version of the list.
    pub leftover: Vec<Leftover>,
    /// What couldn't be read, and why; reading stops there.
    pub problems: Vec<String>,
}

impl Custom {
    /// Every link, with the category it is in.
    pub fn links(&self) -> impl Iterator<Item = (&Category, &Link)> {
        self.categories
            .iter()
            .flat_map(|c| c.links.iter().map(move |l| (c, l)))
    }
}

/// A link left after the last category.
#[derive(Debug, Clone, PartialEq)]
pub struct Leftover {
    /// Where it starts in the file.
    pub offset: usize,
    /// The link.
    pub link: Link,
}

const FOOTER: u32 = 0xbabf_fbab;
/// The shell link class identifier, `{00021401-0000-0000-C000-000000000046}`.
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const FORMAT_VERSION: u32 = 2;

/// Parse a custom jump list, with Windows-1252 for ANSI strings in its links.
#[must_use]
pub fn custom(data: &[u8]) -> Custom {
    custom_with(data, &Options::default())
}

/// [`custom`] with options (the code page of ANSI strings).
#[must_use]
pub fn custom_with(data: &[u8], options: &Options) -> Custom {
    let mut list = Custom {
        version: 0,
        categories: Vec::new(),
        trailing: 0,
        leftover: Vec::new(),
        problems: Vec::new(),
    };
    let (Some(version), Some(count)) = (u32_at(data, 0), u32_at(data, 4)) else {
        list.problems
            .push(format!("{} bytes, too short for the header", data.len()));
        return list;
    };
    list.version = version;
    if version != FORMAT_VERSION {
        list.problems
            .push(format!("format version {version}, not 2"));
    }
    let link_options = lnk::Options {
        code_page: options.code_page,
    };
    let mut at = 12;
    for index in 0..count {
        let (category, end, problem) = category(data, at, link_options);
        if let Some(category) = category {
            list.categories.push(category);
        }
        if let Some(problem) = problem {
            list.problems
                .push(format!("category {index} at {at}: {problem}"));
            return list;
        }
        at = end;
    }
    list.trailing = data.len().saturating_sub(at);
    list.leftover = leftover(data, at, link_options);
    list
}

/// Links in `data` from `at` on: a link header (its size, 76, then its class identifier) that
/// parses. An old entry can be cut by the new list, so the search is by signature.
fn leftover(data: &[u8], mut at: usize, link_options: lnk::Options) -> Vec<Leftover> {
    let mut links = Vec::new();
    while let Some(found) = data.get(at..).and_then(|rest| {
        rest.windows(20)
            .position(|w| w[..4] == [0x4c, 0, 0, 0] && w[4..] == LINK_CLSID)
    }) {
        at += found;
        match lnk::parse_with(&data[at..], &link_options) {
            Ok(link) => {
                let length = link.length.max(1);
                links.push(Leftover { offset: at, link });
                at += length;
            }
            Err(_) => at += 1,
        }
    }
    links
}

/// The category at `at`, where the next one starts, and what's wrong with it if anything is
/// (then the next one can't be found). A category whose entries read but whose footer is
/// missing is kept.
fn category(
    data: &[u8],
    mut at: usize,
    link_options: lnk::Options,
) -> (Option<Category>, usize, Option<String>) {
    let truncated = |at: usize| (None, at, Some("truncated".to_owned()));
    let Some(kind) = u32_at(data, at) else {
        return truncated(at);
    };
    let kind = match kind {
        0 => {
            let Some(chars) = u16_at(data, at + 4).map(usize::from) else {
                return truncated(at);
            };
            let Some(bytes) = data.get(at + 6..at + 6 + 2 * chars) else {
                return truncated(at);
            };
            let units: Vec<u16> = utf16_units(bytes);
            at += 6 + 2 * chars;
            Kind::Custom(String::from_utf16_lossy(&units))
        }
        1 => {
            let Some(id) = u32_at(data, at + 4) else {
                return truncated(at);
            };
            at += 8;
            Kind::Known(id)
        }
        2 => {
            at += 4;
            Kind::Tasks
        }
        other => return (None, at, Some(format!("unknown category type {other}"))),
    };
    let mut category = Category {
        kind,
        links: Vec::new(),
        other_objects: Vec::new(),
    };
    if !matches!(category.kind, Kind::Known(_)) {
        let Some(entries) = u32_at(data, at) else {
            return (Some(category), at, Some("truncated".to_owned()));
        };
        at += 4;
        for _ in 0..entries {
            let Some(class) = data.get(at..at + 16) else {
                return (Some(category), at, Some(format!("entry at {at} truncated")));
            };
            if class != LINK_CLSID {
                if u32_at(data, at) == Some(FOOTER) {
                    // Fewer entries than the category counted.
                    break;
                }
                category
                    .other_objects
                    .push(shell::item::guid(class).unwrap_or_default());
                return (
                    Some(category),
                    at,
                    Some(format!(
                        "an object of another class at {at}: its size isn't known"
                    )),
                );
            }
            match lnk::parse_with(&data[at + 16..], &link_options) {
                Ok(link) => {
                    at += 16 + link.length;
                    category.links.push(link);
                }
                Err(e) => {
                    return (
                        Some(category),
                        at,
                        Some(format!("link at {}: {e}", at + 16)),
                    );
                }
            }
        }
    }
    if u32_at(data, at) != Some(FOOTER) {
        return (
            Some(category),
            at,
            Some(format!("no category footer at {at}")),
        );
    }
    (Some(category), at + 4, None)
}
