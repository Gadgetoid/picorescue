"""LittleFS (v2) reading and recovery.

Two layers:

* :func:`mount` / :func:`list_files` / :func:`extract_all` use ``littlefs-python``
  to read the *live* filesystem (the latest, consistent view).
* :func:`recover_metadata` walks the raw metadata-block logs to surface entries
  from *stale* commits — i.e. files that were deleted or overwritten but whose
  older commit (name + inline data) has not yet been erased.

The metadata walker is intentionally defensive and best-effort: it threads the
XOR-delta tag encoding and bails out of a block on the first implausible tag,
so a corrupt region degrades to "found what we could" rather than crashing.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from littlefs import LittleFS

# Build-time geometry used by Pimoroni dir2uf2; safe defaults for probing.
DEFAULT_BLOCK_SIZE = 4096
DEFAULT_READ_SIZE = 256
DEFAULT_PROG_SIZE = 32

LFS_MAGIC = b"littlefs"

# Tag type1 (top 3 bits of the 11-bit type field).
LFS_TYPE_NAME = 0x0
LFS_TYPE_STRUCT = 0x2
LFS_TYPE_CRC = 0x5
# Name sub-types (chunk byte).
LFS_TYPE_REG = 0x001
LFS_TYPE_DIR = 0x002
LFS_TYPE_SUPERBLOCK = 0x0FF
# Struct sub-types.
LFS_TYPE_INLINE = 0x201
LFS_TYPE_CTZ = 0x202


@dataclass
class LfsFile:
    path: str
    size: int
    data: bytes | None = None


@dataclass
class RecoveredEntry:
    name: str
    file_type: int          # LFS_TYPE_REG / DIR / SUPERBLOCK
    block: int              # metadata block index it was found in
    inline_data: bytes | None = None
    note: str = ""


def block_count_for(size: int, block_size: int = DEFAULT_BLOCK_SIZE) -> int:
    return size // block_size


def read_superblock(data: bytes, block_size: int = DEFAULT_BLOCK_SIZE) -> dict | None:
    """Parse the LittleFS superblock by replaying the metadata-pair log.

    The superblock lives in the metadata pair {block 0, block 1}; the active
    block is the one with the higher revision, and within it the *last*
    superblock-struct commit wins. This matters for ``dir2uf2 --fs-compact``
    images: ``fs_grow`` appends a fresh superblock commit with the grown
    block_count, so a fixed-offset read would return the stale pre-grow value.

    Returns {"version", "block_size", "block_count", "rev"} or None.
    """
    best: tuple[int, int, int, int] | None = None  # (rev, version, bs, bc)
    for b in (0, 1):
        block = data[b * block_size:(b + 1) * block_size]
        if len(block) < 0x20 or block[8:16] != LFS_MAGIC:
            continue
        rev = struct.unpack_from("<I", block, 0)[0]
        geom: tuple[int, int, int] | None = None
        pos = 4
        ptag = 0xFFFFFFFF
        while pos + 4 <= len(block):
            (raw,) = struct.unpack_from(">I", block, pos)
            if raw == 0xFFFFFFFF:
                break
            tag = raw ^ ptag
            ptag = tag
            if (tag >> 31) & 1:  # invalid tag — end of usable log
                break
            type3 = (tag >> 20) & 0x7FF
            type_id = (tag >> 10) & 0x3FF
            length = tag & 0x3FF
            pos += 4
            if length == 0x3FF:
                continue
            if pos + length > len(block):
                break
            payload = block[pos:pos + length]
            pos += length
            if type3 == LFS_TYPE_INLINE and type_id == 0 and length >= 12:
                geom = struct.unpack_from("<III", payload, 0)  # keep last commit
        if geom is not None and (best is None or rev >= best[0]):
            best = (rev, *geom)
    if best is None:
        return None
    rev, version, bs, bc = best
    return {"version": version, "block_size": bs, "block_count": bc, "rev": rev}


def superblock_block_count(data: bytes, block_size: int = DEFAULT_BLOCK_SIZE) -> int | None:
    """The authoritative (latest-commit) block_count from the superblock."""
    sb = read_superblock(data, block_size)
    if sb and 0 < sb["block_count"] <= (1 << 24):
        return sb["block_count"]
    return None


def _mount_with(data: bytes, block_size, read_size, prog_size, block_count) -> LittleFS:
    fs = LittleFS(
        block_size=block_size, block_count=block_count,
        read_size=read_size, prog_size=prog_size, mount=False,
    )
    buf = fs.context.buffer  # pre-sized to block_size * block_count
    n = min(len(buf), len(data))
    buf[:n] = data[:n]
    if len(buf) > n:  # pad the unwritten tail as erased flash (0xFF)
        buf[n:] = b"\xff" * (len(buf) - n)
    fs.mount()
    return fs


def mount(data: bytes, block_size: int = DEFAULT_BLOCK_SIZE,
          read_size: int = DEFAULT_READ_SIZE, prog_size: int = DEFAULT_PROG_SIZE,
          block_count: int | None = None) -> LittleFS:
    """Mount a LittleFS image, trying the most reliable block counts in turn.

    ``block_count`` (from the bi_decl partition size) is tried first because it
    is authoritative for ``--fs-compact`` images whose superblock count is
    stale; the superblock value and the raw buffer length are tried as
    fallbacks. The backing buffer is padded with 0xFF so a truncated dump (only
    the used low blocks captured) still mounts.
    """
    candidates: list[int] = []
    for c in (block_count, superblock_block_count(data, block_size),
              max(1, len(data) // block_size)):
        if c and 0 < c <= (1 << 24) and c not in candidates:
            candidates.append(c)

    last_err: Exception | None = None
    for c in candidates:
        try:
            return _mount_with(data, block_size, read_size, prog_size, c)
        except Exception as e:  # try the next candidate geometry
            last_err = e
    raise last_err if last_err else RuntimeError("no block_count candidates")


def list_files(fs: LittleFS) -> list[LfsFile]:
    out = []
    for root, _dirs, files in fs.walk("/"):
        base = root.rstrip("/")
        for name in files:
            path = f"{base}/{name}"
            try:
                st = fs.stat(path)
                size = st.size
            except Exception:
                size = -1
            out.append(LfsFile(path=path, size=size))
    out.sort(key=lambda f: f.path)
    return out


def read_file(fs: LittleFS, path: str) -> bytes:
    with fs.open(path, "rb") as fh:
        return fh.read()


def extract_all(fs: LittleFS) -> list[LfsFile]:
    out = []
    for f in list_files(fs):
        try:
            f.data = read_file(fs, f.path)
        except Exception:
            f.data = None
        out.append(f)
    return out


# --- raw metadata-log recovery -------------------------------------------------
#
# LittleFS metadata blocks are append-only commit logs of 32-bit tags. Each tag
# is stored big-endian and XOR-encoded against the previous decoded tag (the
# first against 0xFFFFFFFF). A tag packs: valid(1) | type(11) | id(10) | len(10);
# bit 31 == 0 means valid. Commits are delimited by a CRC tag (type1 == 5). A
# file's NAME tag is committed immediately followed by a STRUCT tag (inline /
# CTZ / dir) for the same id.
#
# Recovery walks ALL commits in a block (not just the live view), so stale
# entries from deleted/overwritten files are surfaced too. Raw file-data (CTZ)
# blocks are NOT metadata logs; to avoid mining garbage out of them we only
# trust a block that walks cleanly: every tag valid, lengths in-bounds, and at
# least one CRC tag present. The first invalid tag rejects the whole block.

import re

_FILENAME_RE = re.compile(rb"^[A-Za-z0-9._\-+ ]{1,255}$")


def _is_filename(payload: bytes) -> bool:
    return bool(_FILENAME_RE.match(payload)) and b"  " not in payload


def _block_entries(block: bytes):
    """Parse one metadata block. Returns a list of (name, ftype, inline_or_None)
    across all commits, or None if the block isn't a clean metadata log.

    Names and their (possibly later-committed) inline data are matched by tag
    id within the block. The block-validity gate — every tag valid (bit 31
    clear), every length in-bounds, and at least one CRC tag — is what keeps raw
    file-data (CTZ) blocks from being mined for spurious entries.
    """
    if len(block) < 8:
        return None
    pos = 4  # skip the revision count
    ptag = 0xFFFFFFFF
    saw_crc = False
    names: dict[int, tuple[bytes, int]] = {}      # id -> (name, ftype)
    inlines: list[tuple[int, bytes]] = []         # (id, data) in commit order
    while pos + 4 <= len(block):
        (raw,) = struct.unpack_from(">I", block, pos)
        if raw == 0xFFFFFFFF:  # erased tail — end of log
            break
        tag = raw ^ ptag
        ptag = tag
        if (tag >> 31) & 1:  # invalid tag: this is not a clean metadata block
            return None
        type3 = (tag >> 20) & 0x7FF
        type1 = type3 >> 8
        type_id = (tag >> 10) & 0x3FF
        length = tag & 0x3FF
        pos += 4
        if type1 == LFS_TYPE_CRC:
            saw_crc = True
        if length == 0x3FF:  # null/deleted tag, no payload
            continue
        if pos + length > len(block):
            return None
        payload = block[pos:pos + length]
        pos += length
        if type1 == LFS_TYPE_NAME and (type3 & 0xFF) != LFS_TYPE_SUPERBLOCK:
            names[type_id] = (payload, type3 & 0xFF)
        elif type3 == LFS_TYPE_INLINE and payload:
            inlines.append((type_id, payload))
    if not saw_crc:
        return None  # no commit delimiter — treat as not-metadata

    out: list[tuple[bytes, int, bytes | None]] = []
    for type_id, data in inlines:
        if type_id in names:
            name, ftype = names[type_id]
            out.append((name, ftype, data))
    for type_id, (name, ftype) in names.items():
        out.append((name, ftype, None))
    return out


def recover_metadata(data: bytes, block_size: int = DEFAULT_BLOCK_SIZE) -> list[RecoveredEntry]:
    """Recover file names + inline data from every metadata commit in the image.

    Includes stale entries (deleted / overwritten). De-duplicated by
    (name, inline_data). CTZ-backed (large) files and directories come back as
    name-only hints — their data isn't inline, so carve for the contents.
    """
    found: list[RecoveredEntry] = []
    seen: set[tuple] = set()
    names_with_inline: set[str] = set()
    n_blocks = len(data) // block_size

    # First pass: collect inline recoveries (and remember which names had data).
    parsed: list[tuple[int, list]] = []
    for b in range(n_blocks):
        block = data[b * block_size:(b + 1) * block_size]
        try:
            ents = _block_entries(block)
        except Exception:
            ents = None
        if not ents:
            continue
        parsed.append((b, ents))
        for name, _ftype, inline in ents:
            if inline and _is_filename(name):
                names_with_inline.add(name.decode("utf-8", "replace"))

    for b, ents in parsed:
        for raw_name, ftype, inline in ents:
            if not _is_filename(raw_name):
                continue
            name = raw_name.decode("utf-8", "replace")
            if inline:
                key = (name, inline)
                if key in seen:
                    continue
                seen.add(key)
                found.append(RecoveredEntry(
                    name=name, file_type=ftype, block=b, inline_data=inline,
                    note="inline data recovered from metadata log",
                ))
            else:
                if name in names_with_inline or (name, None) in seen:
                    continue
                seen.add((name, None))
                note = ("directory entry" if ftype == LFS_TYPE_DIR
                        else "name only (CTZ/large file — data not inline, try carving)")
                found.append(RecoveredEntry(
                    name=name, file_type=ftype, block=b,
                    inline_data=None, note=note,
                ))
    return found
