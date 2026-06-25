"""Minimal FAT12/16/32 reader with undelete.

Enough to enumerate live files and recover deleted ones from a Pico FAT
partition. Deletion in FAT only marks the directory entry (first name byte set
to 0xE5) and frees the cluster chain; the entry still records the starting
cluster and size, so contiguous files undelete cleanly.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

ATTR_LONG_NAME = 0x0F
ATTR_DIRECTORY = 0x10
ATTR_VOLUME_ID = 0x08
DELETED_MARKER = 0xE5
END_MARKER = 0x00


@dataclass
class FatFile:
    name: str
    size: int
    first_cluster: int
    is_dir: bool = False
    deleted: bool = False
    data: bytes | None = None


class FatFS:
    def __init__(self, data: bytes):
        self.data = data
        bpb = data[:512]
        self.bytes_per_sector = struct.unpack_from("<H", bpb, 0x0B)[0] or 512
        self.sectors_per_cluster = bpb[0x0D] or 1
        self.reserved = struct.unpack_from("<H", bpb, 0x0E)[0]
        self.num_fats = bpb[0x10]
        self.root_entries = struct.unpack_from("<H", bpb, 0x11)[0]
        total16 = struct.unpack_from("<H", bpb, 0x13)[0]
        total32 = struct.unpack_from("<I", bpb, 0x20)[0]
        self.total_sectors = total16 or total32
        fatsz16 = struct.unpack_from("<H", bpb, 0x16)[0]
        fatsz32 = struct.unpack_from("<I", bpb, 0x24)[0]
        self.fat_size = fatsz16 or fatsz32
        self.root_cluster = struct.unpack_from("<I", bpb, 0x2C)[0]

        self.bps = self.bytes_per_sector
        self.spc = self.sectors_per_cluster
        self.cluster_size = self.bps * self.spc

        self.fat_start = self.reserved
        self.root_dir_start = self.fat_start + self.num_fats * self.fat_size
        root_dir_sectors = (
            (self.root_entries * 32) + (self.bps - 1)
        ) // self.bps
        self.data_start = self.root_dir_start + root_dir_sectors

        # FAT type by cluster count (Microsoft's rule).
        data_sectors = self.total_sectors - self.data_start
        self.cluster_count = data_sectors // self.spc if self.spc else 0
        if self.cluster_count < 4085:
            self.fat_type = 12
        elif self.cluster_count < 65525:
            self.fat_type = 16
        else:
            self.fat_type = 32

    def _sector(self, n: int) -> bytes:
        off = n * self.bps
        return self.data[off:off + self.bps]

    def _cluster_offset(self, cluster: int) -> int:
        return (self.data_start + (cluster - 2) * self.spc) * self.bps

    def read_cluster(self, cluster: int) -> bytes:
        off = self._cluster_offset(cluster)
        return self.data[off:off + self.cluster_size]

    def _fat_entry(self, cluster: int) -> int:
        base = self.fat_start * self.bps
        if self.fat_type == 12:
            idx = base + (cluster * 3) // 2
            pair = struct.unpack_from("<H", self.data, idx)[0]
            return (pair >> 4) if (cluster & 1) else (pair & 0x0FFF)
        if self.fat_type == 16:
            return struct.unpack_from("<H", self.data, base + cluster * 2)[0]
        return struct.unpack_from("<I", self.data, base + cluster * 4)[0] & 0x0FFFFFFF

    def _chain(self, first: int, max_clusters: int = 100000):
        end = {12: 0xFF8, 16: 0xFFF8, 32: 0x0FFFFFF8}[self.fat_type]
        cluster = first
        seen = set()
        while 2 <= cluster < end and cluster not in seen:
            seen.add(cluster)
            yield cluster
            cluster = self._fat_entry(cluster)
            if len(seen) > max_clusters:
                break

    def read_chain(self, first: int, size: int) -> bytes:
        out = bytearray()
        for cluster in self._chain(first):
            out += self.read_cluster(cluster)
            if len(out) >= size:
                break
        return bytes(out[:size])

    def read_contiguous(self, first: int, size: int) -> bytes:
        """Read `size` bytes from `first` cluster onward, ignoring the FAT.

        Used for undelete, where the FAT chain has been freed.
        """
        off = self._cluster_offset(first)
        return self.data[off:off + size]

    # --- directory traversal ---------------------------------------------------

    def _root_region(self) -> bytes:
        if self.fat_type == 32:
            data = bytearray()
            for cluster in self._chain(self.root_cluster):
                data += self.read_cluster(cluster)
            return bytes(data)
        start = self.root_dir_start * self.bps
        end = self.data_start * self.bps
        return self.data[start:end]

    def _parse_dir(self, region: bytes, path: str, recurse: bool, out: list):
        lfn_parts: list[str] = []
        for i in range(0, len(region) - 31, 32):
            entry = region[i:i + 32]
            first = entry[0]
            attr = entry[0x0B]
            if first == END_MARKER:
                break
            if attr == ATTR_LONG_NAME:
                # Collect LFN fragments (UTF-16LE in 3 chunks per entry).
                chars = entry[1:11] + entry[14:26] + entry[28:32]
                try:
                    frag = chars.decode("utf-16-le").split("\x00")[0]
                except UnicodeDecodeError:
                    frag = ""
                lfn_parts.insert(0, frag)
                continue
            if attr & ATTR_VOLUME_ID:
                lfn_parts.clear()
                continue

            deleted = first == DELETED_MARKER
            name = self._short_name(entry, deleted)
            long_name = "".join(lfn_parts).strip("￿").rstrip("\x00")
            lfn_parts.clear()
            display = long_name or name
            if display in (".", "..") or not display.strip():
                continue

            hi = struct.unpack_from("<H", entry, 0x14)[0]
            lo = struct.unpack_from("<H", entry, 0x1A)[0]
            cluster = (hi << 16) | lo if self.fat_type == 32 else lo
            size = struct.unpack_from("<I", entry, 0x1C)[0]
            is_dir = bool(attr & ATTR_DIRECTORY)

            f = FatFile(
                name=f"{path}/{display}".replace("//", "/"),
                size=size, first_cluster=cluster, is_dir=is_dir, deleted=deleted,
            )
            out.append(f)
            if is_dir and recurse and not deleted and cluster >= 2:
                sub = bytearray()
                for cl in self._chain(cluster):
                    sub += self.read_cluster(cl)
                self._parse_dir(bytes(sub), f.name, recurse, out)

    @staticmethod
    def _short_name(entry: bytes, deleted: bool) -> str:
        raw = bytearray(entry[:11])
        if deleted:
            raw[0] = ord("_")  # placeholder for the lost first char
        base = raw[:8].decode("ascii", "replace").rstrip()
        ext = raw[8:11].decode("ascii", "replace").rstrip()
        return f"{base}.{ext}" if ext else base

    def list_files(self, recurse: bool = True) -> list[FatFile]:
        out: list[FatFile] = []
        self._parse_dir(self._root_region(), "", recurse, out)
        return out

    def read(self, f: FatFile) -> bytes:
        if f.first_cluster < 2:
            return b""
        if f.deleted:
            return self.read_contiguous(f.first_cluster, f.size)
        return self.read_chain(f.first_cluster, f.size)
