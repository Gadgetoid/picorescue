# picorescue

Find, inspect and recover data from Raspberry Pi Pico (RP2040 / RP2350) flash
dumps. Built for Pimoroni-style images that pair a MicroPython firmware with a
**LittleFS** filesystem (and optionally a **FAT** partition), where the rescue
target is usually a handful of accidentally-deleted Python scripts.

It reads the `bi_decl` *binary info* region (the same `BlockDevice` declarations
parsed by [`py_decl`](https://github.com/gadgetoid/py_decl)) to locate
partitions, then reads and recovers data from them. It also signature-scans the
whole dump and merges the results, so it finds filesystems that are missing from
`bi_decl` or *nested* inside a declared device - e.g. the `dir2uf2 --fs-reserve`
hybrid where a LittleFS sits in the tail of a FAT block device.

## Install / run

Uses [uv](https://docs.astral.sh/uv/):

```bash
uv sync
uv run picorescue --help
```

or, from pip:

```bash
uv pip install picorescue
uv run picorescue --help
```

Accepts a raw flash dump (`.bin`, offset 0 = flash base `0x10000000`) or a `.uf2`
(reassembled to the correct flash addresses, gaps filled with `0xFF`).

A full-flash dump is ideal. You can grab one with `picotool save -a flash.bin`
or over SWD with OpenOCD.

## Commands

```bash
picorescue info     DUMP            # bi_decl info + discovered partitions
picorescue partitions DUMP          # just the partition table
picorescue ls       DUMP [-p NAME]  # list live files in each filesystem
picorescue extract  DUMP OUTDIR     # extract live (non-deleted) files
picorescue recover  DUMP OUTDIR     # recover deleted / orphaned data
```

`recover` options: `-p/--partition NAME`, `--no-carve`, `--whole-dump` (carve the
entire image, not just known partitions), `--min-score` (carver threshold).

## How recovery works

`recover` writes into `OUTDIR/<partition>/` and a top-level `MANIFEST.json`
describing every recovered item and the method used.

- **LittleFS metadata** (`deleted/`, `metadata/`) - LittleFS is a copy-on-write,
  log-structured filesystem. Deleting or overwriting a file leaves the old
  commit (its name and, for small files, its *inline* content) in the metadata
  block until that block is erased and compacted. picorescue threads the
  XOR-delta tag log of every metadata block and pulls out names + inline data
  across **all** commits, not just the live view. Entries whose name is absent
  from the mounted filesystem are flagged as likely-deleted and sorted into
  `deleted/`.
- **FAT undelete** (`undelete/`) - deletion only sets the directory entry's
  first name byte to `0xE5` and frees the cluster chain; the starting cluster
  and size remain, so contiguous files undelete cleanly. Verify integrity of
  anything recovered this way - fragmented files may be partial.
- **Carving** (`carved/`) - filesystem-agnostic. Scans raw blocks for printable
  text runs and scores them for "Python-ness" (`import`/`def`/`class`, indented
  multi-line structure, assignments). Catches scripts whose directory entry or
  metadata is gone but whose content still lingers in flash. Carved content is
  de-duplicated against live files.

Recovered scripts are best-effort: always eyeball them. Carved fragments may
have a stray leading byte or be truncated at a block boundary.

## Layout

```
src/picorescue/
  bidecl.py   vendored py_decl bi_decl parser (BlockDevice discovery)
  dump.py     load .bin/.uf2 -> addressed flash image; partition discovery
  lfs.py      LittleFS mount/list/extract + metadata-log recovery
  fat.py      FAT12/16/32 read + 0xE5 undelete
  carve.py    Python-source carver
  cli.py      click CLI
```
