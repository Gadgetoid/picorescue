"""Load a Pico flash dump (.bin or .uf2) and locate its partitions.

A loaded :class:`FlashImage` is a flat bytes buffer where index 0 maps to flash
address ``0x10000000`` (the XIP base). Partitions are discovered two ways:

1. From ``bi_decl`` ``BlockDevice`` declarations (authoritative, requires an
   intact firmware image with binary info).
2. By scanning the whole dump for filesystem signatures (resilient fallback for
   damaged dumps, or raw partition dumps with no firmware).
"""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import bidecl
from .bidecl import FLASH_START_ADDR

UF2_BLOCK_SIZE = 512
UF2_HEADER = struct.Struct(b"<IIIIIIII")
LFS_MAGIC = b"littlefs"
RP_FLASH_BLOCK_SIZE = 4096


@dataclass
class Partition:
    name: str
    address: int            # absolute flash address (0x10xxxxxx)
    size: int               # bytes
    fs_type: str = "unknown"  # "littlefs" | "fat" | "unknown"
    flags: int = 0
    source: str = "bi_decl"   # how it was discovered

    @property
    def offset(self) -> int:
        """Offset into the FlashImage buffer."""
        return self.address - FLASH_START_ADDR

    def perms(self) -> str:
        p = []
        if self.flags & bidecl.BLOCK_DEV_FLAG_READ:
            p.append("read")
        if self.flags & bidecl.BLOCK_DEV_FLAG_WRITE:
            p.append("write")
        if self.flags & bidecl.BLOCK_DEV_FLAG_REFORMAT:
            p.append("reformat")
        return ",".join(p) if p else "-"


@dataclass
class FlashImage:
    data: bytes
    base_addr: int = FLASH_START_ADDR
    info: dict = field(default_factory=dict)  # parsed bi_decl

    def slice(self, partition: Partition) -> bytes:
        start = partition.address - self.base_addr
        end = start + partition.size
        if start < 0:
            start = 0
        return self.data[start:end]

    def __len__(self) -> int:
        return len(self.data)


def _uf2_to_sparse(raw: bytes) -> tuple[bytes, int]:
    """Reassemble a UF2 into an address-correct flash image.

    Returns (image_bytes, base_addr). Gaps between blocks are filled with 0xFF
    (erased flash). Only RP2040/RP2350 flash-family blocks are placed.
    """
    chunks: dict[int, bytes] = {}
    for off in range(0, len(raw), UF2_BLOCK_SIZE):
        block = raw[off:off + UF2_BLOCK_SIZE]
        if len(block) < bidecl.HEADER_SIZE:
            break
        (s0, s1, flags, addr, size, _bno, _nb, family) = UF2_HEADER.unpack(
            block[:bidecl.HEADER_SIZE]
        )
        if s0 != bidecl.UF2_MAGIC_START0 or s1 != bidecl.UF2_MAGIC_START1:
            continue
        if family not in (bidecl.FAMILY_ID_RP2040, bidecl.FAMILY_ID_RP2350):
            continue
        payload = block[bidecl.HEADER_SIZE:bidecl.HEADER_SIZE + size]
        chunks[addr] = payload

    if not chunks:
        return b"", FLASH_START_ADDR

    base = min(chunks)
    end = max(addr + len(d) for addr, d in chunks.items())
    image = bytearray(b"\xff" * (end - base))
    for addr, payload in chunks.items():
        pos = addr - base
        image[pos:pos + len(payload)] = payload
    return bytes(image), base


def load_image(path: str | Path) -> FlashImage:
    path = Path(path)
    raw = path.read_bytes()

    if path.suffix.lower() == ".uf2" or raw[:4] == struct.pack("<I", bidecl.UF2_MAGIC_START0):
        data, base = _uf2_to_sparse(raw)
        image = FlashImage(data=data, base_addr=base)
        # bi_decl parsing wants a contiguous-from-0x10000000 view; the sparse
        # image already gives that when base == FLASH_START_ADDR.
        if base == FLASH_START_ADDR:
            image.info = _parse_bidecl(io.BytesIO(data))
        else:
            image.info = _parse_bidecl(bidecl.UF2Reader(path)) or {}
        return image

    image = FlashImage(data=raw, base_addr=FLASH_START_ADDR)
    image.info = _parse_bidecl(io.BytesIO(raw)) or {}
    return image


def _parse_bidecl(fileobj) -> dict:
    try:
        return bidecl.PyDecl(fileobj).parse() or {}
    except Exception:
        return {}


def _detect_fs(buf: bytes) -> str:
    """Best-effort filesystem identification from the first blocks of a slice."""
    if len(buf) >= 16 and buf[8:16] == LFS_MAGIC:
        return "littlefs"
    # LittleFS superblock lives in the first metadata pair; magic sits at the
    # same place in block 0 or block 1.
    if len(buf) >= RP_FLASH_BLOCK_SIZE + 16 and buf[
        RP_FLASH_BLOCK_SIZE + 8:RP_FLASH_BLOCK_SIZE + 16
    ] == LFS_MAGIC:
        return "littlefs"
    # FAT boot sector: 0x55AA signature + a FAT type string.
    if len(buf) >= 512 and buf[510:512] == b"\x55\xaa":
        if b"FAT" in buf[0x36:0x3B] or b"FAT32" in buf[0x52:0x5A]:
            return "fat"
    return "unknown"


def partitions_from_bidecl(image: FlashImage) -> list[Partition]:
    parts = []
    for bd in image.info.get("BlockDevice", []):
        p = Partition(
            name=bd["name"],
            address=bd["address"],
            size=bd["size"],
            flags=bd.get("flags", 0),
        )
        p.fs_type = _detect_fs(image.slice(p))
        parts.append(p)
    parts.sort(key=lambda p: p.address)
    return parts


def scan_for_partitions(image: FlashImage) -> list[Partition]:
    """Signature-scan the whole dump for LittleFS / FAT regions.

    Used as a fallback when bi_decl is missing or corrupt. Scans on flash-block
    (4K) boundaries, which is where Pico partitions always begin.
    """
    found = []
    data = image.data
    step = RP_FLASH_BLOCK_SIZE
    off = 0
    while off < len(data) - 16:
        # LittleFS superblock magic sits at block_start+8 in the first metadata
        # block. The superblock's inline struct gives us the geometry, so we can
        # size the partition and skip past it (avoiding the block-1 pair copy).
        if data[off + 8:off + 16] == LFS_MAGIC:
            block_size = struct.unpack_from("<I", data, off + 0x18)[0]
            block_count = struct.unpack_from("<I", data, off + 0x1C)[0]
            size = block_size * block_count
            sane = (
                block_size in (256, 512, 1024, 2048, 4096, 8192)
                and 0 < size <= len(data) - off
            )
            if not sane:
                block_size = RP_FLASH_BLOCK_SIZE
                size = len(data) - off  # assume FS runs to end of dump
            found.append(Partition(
                name=f"lfs@{image.base_addr + off:#010x}",
                address=image.base_addr + off, size=size,
                fs_type="littlefs", source="scan",
            ))
            off += max(size, step)
            off -= off % step  # realign to flash-block boundary
            continue
        if data[off + 510:off + 512] == b"\x55\xaa" and (
            b"FAT" in data[off + 0x36:off + 0x3B]
            or b"FAT32" in data[off + 0x52:off + 0x5A]
        ):
            found.append(Partition(
                name=f"fat@{image.base_addr + off:#010x}",
                address=image.base_addr + off,
                size=len(data) - off, fs_type="fat", source="scan",
            ))
        off += step
    return found


def discover(image: FlashImage) -> list[Partition]:
    """Return partitions from bi_decl, merged with a signature scan.

    bi_decl declarations are authoritative for the regions they cover, but they
    can miss filesystems *nested* inside a declared block device — e.g. the
    ``dir2uf2 --fs-reserve`` hybrid where a LittleFS is tucked into the tail of
    a FAT partition. So we always scan and fold in any filesystem the
    declarations don't already account for.
    """
    declared = partitions_from_bidecl(image)
    declared_addrs = {p.address for p in declared}
    scanned = scan_for_partitions(image)

    merged = list(declared)
    for s in scanned:
        if s.address in declared_addrs:
            continue  # same region already named by bi_decl
        # A scanned FS that starts inside a declared partition is a real,
        # separate filesystem (hybrid layout) — keep it, but note its parent.
        parent = next(
            (p for p in declared if p.address <= s.address < p.address + p.size),
            None,
        )
        if parent is not None:
            s.name = f"{parent.name}:{s.fs_type}@{s.address:#010x}"
        merged.append(s)

    merged.sort(key=lambda p: p.address)
    return merged
