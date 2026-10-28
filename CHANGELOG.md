# Changelog

## 0.1.0 (ys-jump-lists-parser)

First version: the jump list and compound file code of sootmark-shell (Sootmark/shell), as
ys-lnk-parser 0.4.0 improved it, made its own crate (`ys-jump-lists`, library `jumplist`), with
links read by ys-lnk-parser. (@YamatoSecurity)

### Added
- `parse` and `JumpList`: either kind of jump list; `Options` (the code page of links' ANSI text).
- `automatic`: the `DestList` header (`Header`: pinned count, counter, last entry number,
  revision), each entry's checksum, score and property store, the `DestListPropertyStore` stream
  (`Automatic::properties`), streams no entry names with their links (`Automatic::unlisted`), the
  compound file's streams, `Destination::display_path` (shell namespace GUIDs named).
- `custom`: the class of objects that aren't links (`Category::other_objects`), the bytes after
  the last category (`Custom::trailing`) and the links left in them from an earlier version of the
  list (`Custom::leftover`).
- `appid`: application names by AppID, from Eric Zimmerman's table (MIT; 714 IDs).
- `compound::is_compound`.
- Tests on every automatic fixture against JLECmd (136 entries) and olefile, on lists built in the
  tests, and on damaged lists.

### Changed
- `Destination::access_count` is `interaction_count`; `Automatic::version` is `Automatic::version()`
  (from `header`).
- From `DestList` version 2 on, entries run to the end of the stream, as JLECmd reads them (zeros
  are padding); a header count that disagrees is a problem.
- A custom category whose footer is missing, or with an entry that isn't a link, is kept.

### Fixed
- A compound file that ends inside its last sector (as Windows 11 writes them) lost the streams
  ending there: the jump list read no entries.
- An entry's property store was assumed empty, so an entry with one shifted every later entry.
- A host name stored in UTF-16 was cut after its first character.
- An entry whose stream is missing, and a stream the file cuts short, are problems.
