# Jump list test files

| Directory | Source | License |
| --- | --- | --- |
| `Win7`, `Win80`, `Win81`, `Win10` | A public jump list test set | MIT (`../LICENSE-test-set.txt`) |
| `plaso` | [plaso](https://github.com/log2timeline/plaso) test data | Apache-2.0 (`plaso/LICENSE-plaso.txt`) |
| `synthetic` | Built for this crate | MIT OR Apache-2.0 |
| `artemis` | [artemis](https://github.com/puffyCid/artemis) test data (3f80fd4, `forensics/tests/test_data/windows/jumplists/win11/automatic/`): Windows 11, a `DestList` of 41 entries whose last sector the file cuts short | MIT (`artemis/LICENSE-artemis.txt`) |
| `jumplist_parser` | AbdulRhman Alfaifi's [jumplist_parser](https://github.com/AbdulRhmanAlfaifi/jumplist_parser) samples (647e8c7): Windows 11 Explorer (26 entries, 4 pinned), a version 6 `DestList` whose last sector the file cuts short, a Windows 11 Chrome custom list followed by the end of an older, longer version of it (two links left over, no footer), an empty custom list | MIT OR Apache-2.0 (`jumplist_parser/NOTICE`) |
| `museum` | [DFIRArtifactMuseum](https://github.com/AndrewRathbun/DFIRArtifactMuseum) (`Windows/JumpLists/Win10/RathbunVM/`): an empty `DestList` | MIT (`museum/LICENSE-DFIRArtifactMuseum.txt`) |
| `cfb-forensic` | [cfb-forensic](https://github.com/SecurityRonin/cfb-forensic) test data (6be0d09): 4,096-byte sectors | Apache-2.0 (`cfb-forensic/LICENSE-cfb-forensic.txt`) |

The expected values (`../oracle/jumplist.csv`, `../oracle/jumplist-custom.csv`) are a reference
jump list parser's output.
