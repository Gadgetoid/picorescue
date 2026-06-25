"""picorescue - inspect and recover LittleFS/FAT partitions from Pico flash dumps."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import click

from . import carve, dump, fat, lfs


def _load(dump_path: str) -> dump.FlashImage:
    image = dump.load_image(dump_path)
    if not image.data:
        raise click.ClickException(
            f"Could not read any flash data from {dump_path} "
            "(empty, or no RP2040/RP2350 blocks in the UF2)."
        )
    return image


def _select(parts, name):
    if not name:
        return parts
    chosen = [p for p in parts if p.name == name]
    if not chosen:
        names = ", ".join(p.name for p in parts) or "(none)"
        raise click.ClickException(f"Partition {name!r} not found. Available: {names}")
    return chosen


def _human(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.2f}MB"
    return f"{n / 1024:.1f}KB"


def _safe_path(base: Path, name: str) -> Path:
    """Join name under base, defeating path traversal and absolute paths."""
    rel = Path(name.lstrip("/")).as_posix()
    parts = [p for p in rel.split("/") if p not in ("", ".", "..")]
    return base.joinpath(*parts) if parts else base / "unnamed"


@click.group()
@click.version_option()
def cli():
    """Find, inspect and recover data from Raspberry Pi Pico flash dumps."""


@cli.command()
@click.argument("dump_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "as_json", is_flag=True, help="Emit raw bi_decl as JSON.")
def info(dump_path, as_json):
    """Show bi_decl binary info and discovered partitions."""
    image = _load(dump_path)
    if as_json:
        click.echo(json.dumps(image.info, indent=2, default=str))
        return
    click.echo(f"Loaded {dump_path}: {_human(len(image))} "
               f"@ base {image.base_addr:#010x}")
    for key in ("ProgramName", "ProgramVersion", "PicoBoard", "SDKVersion",
                "BinaryEndAddress"):
        if key in image.info:
            val = image.info[key]
            if key == "BinaryEndAddress":
                val = f"{val:#010x}"
            click.echo(f"  {key}: {val}")
    _print_partitions(dump.discover(image))


def _print_partitions(parts):
    if not parts:
        click.echo("\nNo partitions found (no bi_decl BlockDevice entries, "
                   "and no LittleFS/FAT signatures detected).")
        return
    click.echo(f"\nPartitions ({len(parts)}):")
    for p in parts:
        size = _human(p.size) if p.size else "auto"
        click.echo(f"  {p.name:<24} {p.address:#010x}  {size:>9}  "
                   f"{p.fs_type:<9} [{p.perms()}] ({p.source})")


@cli.command()
@click.argument("dump_path", type=click.Path(exists=True, dir_okay=False))
def partitions(dump_path):
    """List partitions only."""
    _print_partitions(dump.discover(_load(dump_path)))


@cli.command()
@click.argument("dump_path", type=click.Path(exists=True, dir_okay=False))
@click.option("-p", "--partition", help="Limit to a named partition.")
def ls(dump_path, partition):
    """List live files in each filesystem partition."""
    image = _load(dump_path)
    for p in _select(dump.discover(image), partition):
        click.echo(f"\n# {p.name} ({p.fs_type}) @ {p.address:#010x}")
        buf = image.slice(p)
        if p.fs_type == "littlefs":
            try:
                fs = lfs.mount(buf, block_count=_lfs_bc(p))
                for f in lfs.list_files(fs):
                    click.echo(f"  {f.size:>8}  {f.path}")
            except Exception as e:
                click.echo(f"  ! mount failed: {e}")
        elif p.fs_type == "fat":
            try:
                fs = fat.FatFS(buf)
                click.echo(f"  (FAT{fs.fat_type})")
                for f in fs.list_files():
                    tag = "/" if f.is_dir else ""
                    click.echo(f"  {f.size:>8}  {f.name}{tag}")
            except Exception as e:
                click.echo(f"  ! parse failed: {e}")
        else:
            click.echo("  (unknown filesystem - try `recover` to carve)")


@cli.command()
@click.argument("dump_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("outdir", type=click.Path(file_okay=False))
@click.option("-p", "--partition", help="Limit to a named partition.")
def extract(dump_path, outdir, partition):
    """Extract live (non-deleted) files from each filesystem."""
    image = _load(dump_path)
    out = Path(outdir)
    count = 0
    for p in _select(dump.discover(image), partition):
        dest = out / p.name
        buf = image.slice(p)
        if p.fs_type == "littlefs":
            fs = lfs.mount(buf, block_count=_lfs_bc(p))
            for f in lfs.extract_all(fs):
                if f.data is None:
                    continue
                _write(_safe_path(dest, f.path), f.data)
                count += 1
        elif p.fs_type == "fat":
            fs = fat.FatFS(buf)
            for f in fs.list_files():
                if f.is_dir or f.deleted:
                    continue
                _write(_safe_path(dest, f.name), fs.read(f))
                count += 1
    click.echo(f"Extracted {count} file(s) to {out}")


@cli.command()
@click.argument("dump_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("outdir", type=click.Path(file_okay=False))
@click.option("-p", "--partition", help="Limit to a named partition.")
@click.option("--carve/--no-carve", "carve_", default=True,
              help="Carve Python text from raw blocks.")
@click.option("--whole-dump", is_flag=True,
              help="Also carve the entire dump, not just known partitions.")
@click.option("--min-score", type=float, default=6.0, help="Carver score threshold.")
def recover(dump_path, outdir, partition, carve_, whole_dump, min_score):
    """Recover deleted/orphaned data - primarily Python scripts.

    Writes into OUTDIR/<partition>/{metadata,undelete,carved}/ plus a
    MANIFEST.json describing every recovered item and how it was found.
    """
    image = _load(dump_path)
    out = Path(outdir)
    parts = _select(dump.discover(image), partition)
    manifest = {"dump": str(dump_path), "items": []}

    # Hashes of live content so carving doesn't re-report files we already have.
    known: set[str] = set()
    import hashlib

    for p in parts:
        buf = image.slice(p)
        base = out / p.name
        click.echo(f"\n# {p.name} ({p.fs_type}) @ {p.address:#010x} - {_human(len(buf))}")

        if p.fs_type == "littlefs":
            live_names: set[str] = set()
            try:
                fs = lfs.mount(buf, block_count=_lfs_bc(p))
                for f in lfs.extract_all(fs):
                    live_names.add(f.path.rsplit("/", 1)[-1])
                    if f.data is not None:
                        known.add(hashlib.sha1(f.data.strip()).hexdigest())
            except Exception as e:
                click.echo(f"  ! live mount failed ({e}); recovery continues")

            recovered = lfs.recover_metadata(buf)
            inline_entries = [e for e in recovered if e.inline_data is not None]
            # Each (name, content) pair is a distinct version. When a name has
            # more than one, keep them all with a .vN suffix before the
            # extension; single-version names stay unadorned.
            version_count = Counter(e.name for e in inline_entries)
            version_seen: dict[str, int] = defaultdict(int)
            n_md = n_deleted = 0
            for e in inline_entries:
                is_deleted = e.name not in live_names
                sub = "deleted" if is_deleted else "metadata"
                fname = _clean(e.name)
                version = None
                if version_count[e.name] > 1:
                    version_seen[e.name] += 1
                    version = version_seen[e.name]
                    fname = _versioned_name(fname, version)
                target = base / sub / fname
                _write(target, e.inline_data)
                manifest["items"].append({
                    "partition": p.name, "method": "lfs-metadata",
                    "name": e.name, "version": version,
                    "bytes": len(e.inline_data),
                    "deleted": is_deleted, "note": e.note, "path": str(target),
                })
                n_md += 1
                n_deleted += is_deleted
            names = sorted({e.name for e in recovered if e.inline_data is None})
            click.echo(f"  metadata: {n_md} inline file(s) recovered "
                       f"({n_deleted} not in live FS → likely deleted); "
                       f"{len(names)} name-only hint(s)"
                       + (f": {', '.join(names[:8])}" if names else ""))

        elif p.fs_type == "fat":
            try:
                fs = fat.FatFS(buf)
                n_un = 0
                for f in fs.list_files():
                    if not f.deleted or f.is_dir:
                        continue
                    data = fs.read(f)
                    if not data:
                        continue
                    target = base / "undelete" / _clean(f.name)
                    _write(target, data)
                    manifest["items"].append({
                        "partition": p.name, "method": "fat-undelete",
                        "name": f.name, "bytes": len(data),
                        "note": "contiguous undelete (verify integrity)",
                        "path": str(target),
                    })
                    n_un += 1
                click.echo(f"  FAT{fs.fat_type}: undeleted {n_un} file(s)")
            except Exception as e:
                click.echo(f"  ! FAT parse failed: {e}")

        if carve_:
            n_c = _carve_to(buf, base / "carved", min_score, known, manifest,
                            p.name, "carve-partition")
            click.echo(f"  carved {n_c} Python candidate(s)")

    if whole_dump and carve_:
        n_c = _carve_to(image.data, out / "_whole_dump_carved", min_score,
                        known, manifest, "*whole-dump*", "carve-whole-dump")
        click.echo(f"\nWhole-dump carve: {n_c} additional candidate(s)")

    out.mkdir(parents=True, exist_ok=True)
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2))
    click.echo(f"\nDone. {len(manifest['items'])} item(s) → {out} (see MANIFEST.json)")


def _carve_to(buf, dest, min_score, known, manifest, part_name, method) -> int:
    n = 0
    for c in carve.carve(buf, min_score=min_score, known_hashes=known):
        known.add(c.sha1)
        name = f"{c.offset:08x}_{c.suggested_name()}"
        target = dest / name
        _write(target, c.data)
        manifest["items"].append({
            "partition": part_name, "method": method,
            "name": c.suggested_name(), "offset": c.offset,
            "score": c.score, "bytes": len(c.data), "path": str(target),
        })
        n += 1
    return n


def _lfs_bc(p) -> int | None:
    """Block count implied by a partition's declared size (authoritative for
    --fs-compact images whose superblock count is stale)."""
    return (p.size // lfs.DEFAULT_BLOCK_SIZE) or None if p.size else None


def _clean(name: str) -> str:
    return Path(name.lstrip("/")).name or "unnamed"


def _versioned_name(filename: str, version: int) -> str:
    """Insert a `.vN` tag before the extension: clock.json -> clock.v1.json."""
    p = Path(filename)
    return f"{p.stem}.v{version}{p.suffix}"


def _write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


if __name__ == "__main__":
    cli()
