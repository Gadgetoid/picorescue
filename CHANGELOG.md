# Changelog

All notable changes to picorescue are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-25

### Added
- Partition discovery now always runs a signature scan and **merges** it with
  `bi_decl`, so filesystems that are missing from binary info or *nested* inside
  a declared block device are found (e.g. the `dir2uf2 --fs-reserve` hybrid where
  a LittleFS sits in the tail of a FAT partition). Nested filesystems are named
  after their parent, e.g. `MicroPython:littlefs@0x10f00000`.
- `recover` preserves **every distinct version** of a recovered LittleFS file
  with a `.vN` suffix inserted before the extension (`clock.v1.json`,
  `clock.v2.json`); single-version files keep their plain name. Each item records
  its `version` in `MANIFEST.json`.

### Changed
- LittleFS superblock geometry is now read by **replaying the metadata-pair log**
  (`lfs.read_superblock`) and taking the latest superblock commit, instead of a
  fixed-offset read.
- `lfs.mount` tries multiple block counts (bi_decl partition size, superblock
  count, buffer length) and pads the backing buffer with `0xFF`, so truncated
  `-with-filesystem.uf2` images (only the used low blocks present) still mount.

### Fixed
- **LittleFS mount failure (`LFS_ERR_INVAL`) on `--fs-compact` images.** Such
  images compact into the low blocks then `fs_grow` to the device size, which
  appends a *new* superblock commit with the grown `block_count`. The old
  fixed-offset parser read the stale pre-grow value (e.g. 248 instead of 3584),
  producing a geometry mismatch on mount. This was a picorescue parsing bug, not
  a fault in `dir2uf2` or upstream LittleFS `fs_grow`.
- **Garbage entries in LittleFS metadata recovery.** `recover` previously walked
  every 4 KB block as if it were a metadata log, mining spurious "filenames" out
  of raw file-data (CTZ) blocks. A block is now only trusted if its tag log walks
  cleanly (every tag's valid bit clear, all lengths in bounds, at least one CRC
  tag present); names are matched to inline data by tag id across commits.
- Recovered items are now sorted into `deleted/` vs `metadata/` by comparing
  against the live filesystem.

## [0.1.0] - 2026-06-25

### Added
- Initial release. `click` CLI (`info`, `partitions`, `ls`, `extract`,
  `recover`) over a uv project.
- Loads raw `.bin` flash dumps and `.uf2` files (reassembled to correct flash
  addresses, gaps filled with `0xFF`).
- Locates partitions from `bi_decl` `BlockDevice` declarations (vendored
  `py_decl` parser) with a filesystem-signature scan fallback.
- LittleFS: mount, list and extract live files via `littlefs-python`, plus
  recovery of names and inline data from stale metadata commits.
- FAT12/16/32: list live files and undelete `0xE5`-marked entries.
- Filesystem-agnostic Python-source carver for rescuing scripts whose directory
  entry or metadata is gone.
