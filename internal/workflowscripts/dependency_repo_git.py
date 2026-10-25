"""Read tracked files at HEAD with one git process per operation.

Each helper reads the pull request's tree, never the working tree, so a file the
change does not track cannot change a fact. A path git cannot list or read, or a
search or read that exceeds its limit, returns None or a flag the caller treats
as unread.
"""

from __future__ import annotations

import io
import subprocess


def _entries(records: str) -> list[tuple[str, str]]:
    """The (path, mode) of each nonempty NUL-separated ls-tree record."""
    entries: list[tuple[str, str]] = []
    for record in records.split("\0"):
        if not record:
            continue
        meta, _separator, path = record.partition("\t")
        entries.append((path, meta.split(" ", 1)[0]))
    return entries


def files(directory: str) -> list[tuple[str, str]] | None:
    """The (path, mode) of each entry directly in `directory` at HEAD, or None when git cannot list them."""
    prefix = "" if directory in {"", "."} else f"{directory}/"
    proc = subprocess.run(
        ["git", "ls-tree", "-z", "HEAD", "--", prefix or "."],
        check=False,
        capture_output=True,
        text=True,
    )
    return None if proc.returncode != 0 else _entries(proc.stdout)


def _grep(
    needles: list[str],
    limit: int | None,
    *,
    word: bool = False,
    ignore_case: bool = False,
) -> list[str] | None:
    """The tracked paths at HEAD whose text contains any needle, or None on an error or above `limit`."""
    args = ["git", "grep", "-l", "-F", "-I", "-z"]
    if word:
        args.append("-w")
    if ignore_case:
        args.append("-i")
    for needle in needles:
        args.extend(["-e", needle])
    args.extend(["HEAD", "--"])
    proc = subprocess.run(args, check=False, capture_output=True, text=True)
    if proc.returncode not in {0, 1}:
        return None
    found = [record.removeprefix("HEAD:") for record in proc.stdout.split("\0") if record]
    return None if limit is not None and len(found) > limit else found


def grep(needle: str) -> list[str] | None:
    """The tracked paths at HEAD whose text contains `needle`, or None when git cannot search them."""
    return _grep([needle], None)


def grep_any(needles: tuple[str, ...], limit: int) -> list[str] | None:
    """The tracked paths at HEAD whose text contains any of `needles` as a whole word, ignoring case.

    Returns None on an error or when the result is above `limit`.
    """
    return _grep(list(needles), limit, word=True, ignore_case=True)


def bytes_at(rev: str, path: str) -> bytes | None:
    """The bytes of `path` at `rev`, or None when git cannot read it."""
    proc = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        check=False,
        capture_output=True,
    )
    return None if proc.returncode != 0 else proc.stdout


def text_at(rev: str, path: str) -> str | None:
    """The text of `path` at `rev`, "" when git cannot read it, or None when it is not UTF-8."""
    data = bytes_at(rev, path)
    if data is None:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def tree() -> list[tuple[str, str]] | None:
    """The (path, mode) of every tracked entry at HEAD, or None when git cannot list them."""
    proc = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return None if proc.returncode != 0 else _entries(proc.stdout)


def blobs(paths: list[str], limit: int) -> tuple[dict[str, bytes], bool]:
    """The bytes of each path at HEAD and whether the read limit skipped any of them.

    The paths are read in one `git cat-file --batch` after a size check, so a large repository does not run one git
    process per file and a file over the limit is not read. A path with a line break is skipped, because the batch
    protocol cannot carry it.
    """
    unique = sorted(set(paths))
    specs = [f"HEAD:{path}" for path in unique if "\n" not in path and "\r" not in path]
    overflow = len(specs) != len(unique)
    if not specs:
        return {}, overflow
    check = subprocess.run(
        ["git", "cat-file", "--batch-check"],
        input=("\n".join(specs) + "\n").encode(),
        check=False,
        capture_output=True,
    )
    if check.returncode != 0:
        return {}, True
    selected: list[str] = []
    total = 0
    for spec, line in zip(specs, check.stdout.splitlines()):
        fields = line.split()
        if len(fields) != 3:
            overflow = True
            continue
        try:
            size = int(fields[2])
        except ValueError:
            overflow = True
            continue
        if total + size > limit:
            overflow = True
            continue
        total += size
        selected.append(spec)
    if not selected:
        return {}, overflow
    batch = subprocess.run(
        ["git", "cat-file", "--batch"],
        input=("\n".join(selected) + "\n").encode(),
        check=False,
        capture_output=True,
    )
    if batch.returncode != 0:
        return {}, True
    found: dict[str, bytes] = {}
    stream = io.BytesIO(batch.stdout)
    for spec in selected:
        header = stream.readline()
        if not header:
            return found, True
        fields = header.split()
        if len(fields) != 3:
            overflow = True
            continue
        try:
            size = int(fields[2])
        except ValueError:
            return found, True
        body = stream.read(size)
        if len(body) != size:
            return found, True
        stream.read(1)
        found[spec.removeprefix("HEAD:")] = body
    return found, overflow
