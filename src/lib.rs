//! Windows jump lists: what each application's taskbar and Start menu entry offers, the files
//! and folders it opened recently and frequently, and pinned items.
//!
//! - Automatic jump lists (`*.automaticDestinations-ms`, [`mod@automatic`]): Windows records them by
//!   itself. A compound file (MS-CFB, [`compound`]) with a `DestList` stream (when each item was
//!   last used, how often, whether it is pinned, the machine and the tracker identifiers of its
//!   target, its path) and a shell link (LNK) per item. Every `DestList` version (1 to 6, Windows 7
//!   to 11), entries' property stores and the `DestListPropertyStore` stream.
//! - Custom jump lists (`*.customDestinations-ms`, [`mod@custom`]): the application's own categories
//!   and tasks, a sequence of shell links.
//! - The application each AppID (a jump list's file name) belongs to ([`appid`]).
//!
//! Links are read with Yamato Security's ys-lnk-parser (`shell`). Damage is reported (each
//! result's `problems`), never a panic; what can be read is.
//!
//! ```no_run
//! let data = std::fs::read("f01b4d95cf55d32a.automaticDestinations-ms")?;
//! match jumplist::parse(&data, &jumplist::Options::default())? {
//!     jumplist::JumpList::Automatic(list) => {
//!         for d in &list.destinations {
//!             println!("{} {} {}", d.position, d.last_used, d.display_path());
//!         }
//!     }
//!     jumplist::JumpList::Custom(list) => {
//!         for (category, link) in list.links() {
//!             println!("{}: {}", category.kind.name(), link.target_path());
//!         }
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod appid;
pub mod automatic;
pub mod compound;
pub mod custom;

pub use automatic::{automatic, automatic_with, Automatic, Destination, Header, Unlisted};
pub use custom::{custom, custom_with, Category, Custom, Kind, Leftover};

/// How to read a jump list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The code page of ANSI strings in links: the system's ANSI code page (1252 for Western
    /// European, 932 for Japanese; others need the `codepages` feature).
    pub code_page: u16,
}

impl Default for Options {
    fn default() -> Self {
        Self { code_page: 1252 }
    }
}

/// A jump list of either kind.
#[derive(Debug, Clone, PartialEq)]
pub enum JumpList {
    /// An automatic jump list (a compound file).
    Automatic(Automatic),
    /// A custom jump list.
    Custom(Custom),
}

/// Parse a jump list of either kind: a compound file is an automatic jump list, anything else is
/// read as a custom one.
///
/// # Errors
/// When a compound file can't be opened.
pub fn parse(data: &[u8], options: &Options) -> Result<JumpList, compound::Error> {
    if compound::is_compound(data) {
        automatic_with(data, options).map(JumpList::Automatic)
    } else {
        Ok(JumpList::Custom(custom_with(data, options)))
    }
}

pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

pub(crate) fn f32_at(b: &[u8], at: usize) -> Option<f32> {
    u32_at(b, at).map(f32::from_bits)
}
