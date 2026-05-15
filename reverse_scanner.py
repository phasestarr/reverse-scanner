#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator


MAGIC = b"DS3200807"
NOTICE = b"This document is protected by ShadowCube Tech. & Policies."
HEADER_READ_BYTES = 128


@dataclass
class ScanResult:
    path: str
    status: str
    reason: str
    size: int | None = None
    destination: str | None = None
    error: str | None = None


def classify_header(header: bytes, *, loose: bool = False) -> tuple[str, str]:
    if header.startswith(MAGIC) and NOTICE in header:
        return "encrypted", "ShadowCube header magic and protection notice"

    if header.startswith(MAGIC):
        if loose:
            return "encrypted", "ShadowCube header magic"
        return "suspect", "ShadowCube header magic without expected notice"

    return "clear", "No ShadowCube header marker"


def scan_file(path: Path, *, loose: bool = False) -> ScanResult:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            header = handle.read(HEADER_READ_BYTES)
    except OSError as exc:
        return ScanResult(
            path=str(path),
            status="error",
            reason="Could not read file",
            error=str(exc),
        )

    status, reason = classify_header(header, loose=loose)
    return ScanResult(path=str(path), status=status, reason=reason, size=size)


def normalized_absolute(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def is_excluded(path: Path, excluded_dirs: set[str]) -> bool:
    if not excluded_dirs:
        return False

    normalized = normalized_absolute(path)
    for excluded in excluded_dirs:
        if normalized == excluded or normalized.startswith(excluded + os.sep):
            return True

    return False


def iter_targets(
    paths: Iterable[str],
    *,
    follow_links: bool = False,
    excluded_dirs: set[str] | None = None,
) -> Iterator[tuple[Path, Path] | ScanResult]:
    excluded_dirs = excluded_dirs or set()

    for raw_path in paths:
        root = Path(raw_path)
        try:
            if root.is_file():
                yield root, root.parent
            elif root.is_dir():
                yield from walk_directory(root, follow_links=follow_links, excluded_dirs=excluded_dirs)
            else:
                yield ScanResult(
                    path=str(root),
                    status="error",
                    reason="Path does not exist or is not a regular file/directory",
                )
        except OSError as exc:
            yield ScanResult(
                path=str(root),
                status="error",
                reason="Could not inspect path",
                error=str(exc),
            )


def walk_directory(
    root: Path,
    *,
    follow_links: bool = False,
    excluded_dirs: set[str] | None = None,
) -> Iterator[tuple[Path, Path] | ScanResult]:
    stack = [root]
    visited: set[str] = set()
    excluded_dirs = excluded_dirs or set()

    while stack:
        current = stack.pop()

        if is_excluded(current, excluded_dirs):
            continue

        if follow_links:
            real_current = os.path.realpath(current)
            if real_current in visited:
                continue
            visited.add(real_current)

        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entry_path = Path(entry.path)
                    try:
                        if entry.is_dir(follow_symlinks=follow_links):
                            if (follow_links or not entry.is_symlink()) and not is_excluded(
                                entry_path,
                                excluded_dirs,
                            ):
                                stack.append(entry_path)
                        elif entry.is_file(follow_symlinks=False):
                            yield entry_path, root
                    except OSError as exc:
                        yield ScanResult(
                            path=str(entry_path),
                            status="error",
                            reason="Could not inspect directory entry",
                            error=str(exc),
                        )
        except OSError as exc:
            yield ScanResult(
                path=str(current),
                status="error",
                reason="Could not enter directory",
                error=str(exc),
            )


def safe_root_label(root: Path) -> str:
    resolved = Path(os.path.normpath(str(root)))

    parts: list[str] = []
    if resolved.drive:
        parts.append(resolved.drive.rstrip(":"))

    for part in resolved.parts:
        if part == resolved.anchor:
            continue
        clean = "".join(char if char.isalnum() or char in "._-" else "_" for char in part)
        if clean:
            parts.append(clean)

    return "_".join(parts) or "root"


def destination_for(path: Path, scan_root: Path, move_root: Path) -> Path:
    try:
        relative = path.relative_to(scan_root)
    except ValueError:
        relative = Path(path.name)

    return move_root / safe_root_label(scan_root) / relative


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path

    for index in range(1, 10000):
        candidate = path.with_name(f"{path.stem}.{index}{path.suffix}")
        if not candidate.exists():
            return candidate

    raise FileExistsError(f"Could not find unused destination for {path}")


def maybe_move(result: ScanResult, scan_root: Path, move_root: Path, *, dry_run: bool) -> ScanResult:
    source = Path(result.path)
    destination = unique_destination(destination_for(source, scan_root, move_root))
    result.destination = str(destination)

    if dry_run:
        return result

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        result.reason = f"{result.reason}; moved from {source}"
    except OSError as exc:
        result.status = "error"
        result.error = str(exc)
        result.reason = "Detected encrypted file, but move failed"

    return result


def write_csv_report(path: Path, results: list[ScanResult]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["path", "status", "reason", "size", "destination", "error"],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))


def write_json_report(path: Path, results: list[ScanResult]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump([asdict(result) for result in results], handle, indent=2)
        handle.write("\n")


def print_summary(results: list[ScanResult], *, show_all: bool) -> None:
    visible = results if show_all else [item for item in results if item.status != "clear"]

    for result in visible:
        line = f"{result.status.upper():9} {result.path}"
        if result.destination:
            line += f" -> {result.destination}"
        if result.error:
            line += f" ({result.error})"
        print(line)

    encrypted = sum(1 for item in results if item.status == "encrypted")
    suspect = sum(1 for item in results if item.status == "suspect")
    errors = sum(1 for item in results if item.status == "error")
    clear = sum(1 for item in results if item.status == "clear")

    print(
        f"\nScanned {len(results)} item(s): "
        f"{encrypted} encrypted, {suspect} suspect, {clear} clear, {errors} error(s)."
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan files for the observed ShadowCube DRM encryption wrapper.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Files or directories to scan, for example samples C:\\ D:\\",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Print clear files too. By default only encrypted, suspect, and error rows are printed.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        help="Write a CSV report to this path.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Write a JSON report to this path.",
    )
    parser.add_argument(
        "--move-to",
        type=Path,
        help="Move encrypted files into this directory, preserving their scanned relative path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show move destinations without moving files. Useful with --move-to.",
    )
    parser.add_argument(
        "--follow-links",
        action="store_true",
        help="Follow directory symlinks/junctions. Disabled by default to avoid loops.",
    )
    parser.add_argument(
        "--loose",
        action="store_true",
        help="Treat the DS3200807 magic alone as encrypted even if the notice text changed.",
    )
    parser.add_argument(
        "--fail-if-found",
        action="store_true",
        help="Exit with code 2 if encrypted or suspect files are found.",
    )

    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    results: list[ScanResult] = []
    excluded_dirs = {normalized_absolute(args.move_to)} if args.move_to else set()

    for target in iter_targets(
        args.paths,
        follow_links=args.follow_links,
        excluded_dirs=excluded_dirs,
    ):
        if isinstance(target, ScanResult):
            results.append(target)
            continue

        path, scan_root = target
        result = scan_file(path, loose=args.loose)
        if result.status == "encrypted" and args.move_to:
            result = maybe_move(result, scan_root, args.move_to, dry_run=args.dry_run)
        results.append(result)

    print_summary(results, show_all=args.all)

    if args.csv:
        write_csv_report(args.csv, results)
    if args.json:
        write_json_report(args.json, results)

    if args.fail_if_found and any(item.status in {"encrypted", "suspect"} for item in results):
        return 2
    if any(item.status == "error" for item in results):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
