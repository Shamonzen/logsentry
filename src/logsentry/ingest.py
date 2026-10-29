"""Read only the new lines of a growing log file, resuming from the offset saved in SQLite."""

import sqlite3
from pathlib import Path

from logsentry import store


def read_new_lines(conn: sqlite3.Connection, path: Path) -> tuple[list[str], int, int] | None:
    """Return (complete lines added since the saved offset, inode, offset after them).

    A different inode (the file was rotated) or a file shorter than the offset (it was truncated)
    restarts from 0. A trailing line without its newline is left for the next call, since the
    writer may still be in the middle of it. Returns None while the file does not exist.
    The caller saves the returned offset with store.set_offset once the lines are processed,
    so a crash re-reads lines instead of losing them.
    """
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    saved = store.get_offset(conn, str(path))
    offset = saved[1] if saved and saved[0] == st.st_ino and saved[1] <= st.st_size else 0
    lines = []
    # shortcut: lines written to the old file between our last poll and a rotation are lost;
    # upgrade by draining the old inode first if the lab ever rotates under load.
    with path.open("rb") as f:
        f.seek(offset)
        for raw in f:
            if not raw.endswith(b"\n"):
                break
            lines.append(raw.decode("utf-8", errors="replace"))
            offset += len(raw)
    return lines, st.st_ino, offset
