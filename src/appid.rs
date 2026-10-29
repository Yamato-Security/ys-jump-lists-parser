//! Application identifiers: a jump list's file name is its application's AppID
//! (`f01b4d95cf55d32a.automaticDestinations-ms` is Windows Explorer's). Names from an AppID list
//! (MIT licence, `src/appid/LICENSE`). The list's 15-digit AppIDs lost a leading zero; they are
//! given it back.

/// The AppID a jump list's file name starts with: its first 16 hexadecimal digits, lowercase.
#[must_use]
pub fn app_id(file_name: &str) -> Option<String> {
    let id = file_name.get(..16)?;
    id.bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| id.to_ascii_lowercase())
}

/// The name of the application an AppID belongs to (any case), if the list has it.
#[must_use]
pub fn app_name(app_id: &str) -> Option<&'static str> {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    // Sorted by AppID in the file.
    let table = TABLE.get_or_init(|| {
        include_str!("appid/appids.txt")
            .lines()
            .filter_map(|l| l.split_once('|'))
            .collect()
    });
    let id = app_id.to_ascii_lowercase();
    table
        .binary_search_by(|(known, _)| (*known).cmp(id.as_str()))
        .ok()
        .map(|i| table[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_names() {
        assert_eq!(
            app_id("F01B4D95CF55D32A.automaticDestinations-ms").as_deref(),
            Some("f01b4d95cf55d32a")
        );
        assert_eq!(app_id("DestList"), None);
        assert_eq!(
            app_name("F01B4D95CF55D32A"),
            Some("Windows Explorer Windows 8.1")
        );
        // listed without its leading zero
        assert!(app_name("01ab724316049531").is_some());
        assert_eq!(app_name("0000000000000000"), None);
    }

    #[test]
    fn the_table_is_sorted() {
        let ids: Vec<&str> = include_str!("appid/appids.txt")
            .lines()
            .filter_map(|l| l.split_once('|').map(|(id, _)| id))
            .collect();
        assert!(ids.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ids.len(), 714);
    }
}
