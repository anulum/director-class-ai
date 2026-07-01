# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — crash-durable file writes

"""Crash-durable file primitives for the audit chain and approval queue.

The governance evidence is only as trustworthy as its durability: an audit record
that is buffered in the OS page cache and lost to a crash is a gap an attacker can
arrange. These helpers make a write survive a power loss before the caller
proceeds — the data is flushed and ``fsync``-ed, full-file updates are swapped in
atomically by rename so a crash never leaves a half-written file, and the
directory entry is itself synced so the rename is durable.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

__all__ = ["atomic_write_text", "durable_append_line"]


def _fsync_dir(directory: Path) -> None:
    """Best-effort fsync of a directory so a rename within it is durable.

    Directory syncing is unsupported on some platforms (notably Windows); there
    it is a no-op rather than an error.
    """
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_text(path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Replace ``path`` with ``text`` atomically and durably.

    The text is written to a sibling temporary file that is flushed and synced,
    then renamed over ``path`` (an atomic operation on POSIX), and the parent
    directory is synced. A crash at any point leaves either the old file intact or
    the new file complete — never a truncated mix.

    The temporary file name is unique per write (process id plus a random token).
    Two writers targeting the same path — for example separate instances
    persisting a shared approval queue — therefore never share one temporary file
    and truncate each other's content before the rename; each write remains an
    independent atomic swap. The temporary file is removed if the write or the
    rename fails, so a failed write leaves no stray sibling behind.
    """
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    try:
        with tmp.open("w", encoding=encoding) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_dir(path.parent)


def durable_append_line(path: str | Path, line: str, *, encoding: str = "utf-8") -> None:
    """Append ``line`` to ``path`` and fsync it so the record survives a crash.

    Used for the append-only audit chain, where each entry must be on disk before
    the decision it records is allowed to take effect.
    """
    with Path(path).open("a", encoding=encoding) as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
