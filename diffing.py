"""Text diff engine.

Pure functions, stdlib only (``difflib``). No FastAPI imports so this module can
be imported and unit-tested in isolation, exactly like ``generators.py``.

``diff_texts`` returns a single, render-agnostic payload: a list of *aligned
rows*. The front-end projects the same rows into either an inline (unified) view
or a side-by-side view, so switching modes never needs another request.

Each non-empty side carries ``segs`` — intra-line word/char segments with an
``hl`` flag — so changed lines can highlight exactly what differs within them.
Joining a side's segment texts always reconstructs that side's line verbatim,
which is what makes rendering safe (the UI renders text via ``textContent``).
"""

from __future__ import annotations

import difflib
import re

# Lossless tokenizer: alternating whitespace / non-whitespace runs so that
# "".join(WORD_RE.findall(s)) == s for any string.
WORD_RE = re.compile(r"\s+|\S+")

# Guard rails — difflib is O(n*m); cap inputs so a paste can't pin a CPU.
MAX_BYTES = 200_000   # per side, UTF-8 encoded (~200 KB)
MAX_LINES = 5_000     # per side


def _tokenize(line: str, granularity: str) -> list[str]:
    """Split a line into comparison tokens. Lossless: "".join(...) == line."""
    if granularity == "char":
        return list(line)
    return WORD_RE.findall(line)


def _normalize(line: str, *, ignore_whitespace: bool, ignore_case: bool) -> str:
    """The comparison key for a display line (matching only, never shown)."""
    if ignore_whitespace:
        line = re.sub(r"\s+", " ", line).strip()
    if ignore_case:
        line = line.lower()
    return line


def _split_lines(
    text: str, *, ignore_whitespace: bool, ignore_case: bool
) -> tuple[list[str], list[str]]:
    """Return ``(display_lines, compare_lines)``.

    ``display_lines`` are what the UI shows, verbatim. ``splitlines()`` collapses
    CRLF / CR / LF, so inputs differing only by line endings compare equal.
    ``compare_lines`` are normalized copies used solely for matching.
    """
    display = text.splitlines()
    compare = [
        _normalize(ln, ignore_whitespace=ignore_whitespace, ignore_case=ignore_case)
        for ln in display
    ]
    return display, compare


def _intra_line_segments(
    a: str, b: str, granularity: str
) -> tuple[list[dict], list[dict]]:
    """Word/char-level diff of one changed pair → ``(left_segs, right_segs)``.

    A segment is ``{"text": str, "hl": bool}``. ``hl`` marks tokens that were
    removed (left) or added (right). Adjacent same-state tokens are merged so the
    payload stays compact.
    """
    a_tokens = _tokenize(a, granularity)
    b_tokens = _tokenize(b, granularity)
    sm = difflib.SequenceMatcher(None, a_tokens, b_tokens, autojunk=False)
    left: list[dict] = []
    right: list[dict] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        left_hl = tag in ("replace", "delete")
        right_hl = tag in ("replace", "insert")
        if i2 > i1:
            _push_seg(left, "".join(a_tokens[i1:i2]), left_hl)
        if j2 > j1:
            _push_seg(right, "".join(b_tokens[j1:j2]), right_hl)
    return left, right


def _push_seg(segs: list[dict], text: str, hl: bool) -> None:
    """Append text, merging into the previous segment if the flag matches."""
    if not text:
        return
    if segs and segs[-1]["hl"] == hl:
        segs[-1]["text"] += text
    else:
        segs.append({"text": text, "hl": hl})


def _plain_segs(text: str) -> list[dict]:
    """A single un-highlighted segment (used for equal/added/removed lines)."""
    return [{"text": text, "hl": False}] if text else []


def _side(num: int, text: str, segs: list[dict] | None = None) -> dict:
    return {"num": num, "text": text, "segs": segs if segs is not None else _plain_segs(text)}


def _check_size(text: str) -> None:
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError(f"Input too large: limit is {MAX_BYTES // 1000} KB per side.")
    if text.count("\n") + 1 > MAX_LINES:
        raise ValueError(f"Input too large: limit is {MAX_LINES} lines per side.")


def diff_texts(
    text1: str,
    text2: str,
    *,
    ignore_whitespace: bool = False,
    ignore_case: bool = False,
    granularity: str = "word",
) -> dict:
    """Compare two texts and return aligned diff rows plus summary stats.

    Raises ``ValueError`` if either side exceeds the size limits.
    """
    _check_size(text1)
    _check_size(text2)
    if granularity not in ("word", "char"):
        granularity = "word"

    disp1, cmp1 = _split_lines(text1, ignore_whitespace=ignore_whitespace, ignore_case=ignore_case)
    disp2, cmp2 = _split_lines(text2, ignore_whitespace=ignore_whitespace, ignore_case=ignore_case)

    sm = difflib.SequenceMatcher(None, cmp1, cmp2, autojunk=False)
    rows: list[dict] = []
    added = removed = changed = unchanged = 0

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append({
                    "type": "equal",
                    "left": _side(i1 + k + 1, disp1[i1 + k]),
                    "right": _side(j1 + k + 1, disp2[j1 + k]),
                })
                unchanged += 1
        elif tag == "delete":
            for k in range(i1, i2):
                rows.append({"type": "remove", "left": _side(k + 1, disp1[k]), "right": None})
                removed += 1
        elif tag == "insert":
            for k in range(j1, j2):
                rows.append({"type": "add", "left": None, "right": _side(k + 1, disp2[k])})
                added += 1
        else:  # replace — pair lines positionally, intra-line highlight each pair
            paired = min(i2 - i1, j2 - j1)
            for k in range(paired):
                lseg, rseg = _intra_line_segments(disp1[i1 + k], disp2[j1 + k], granularity)
                rows.append({
                    "type": "change",
                    "left": _side(i1 + k + 1, disp1[i1 + k], lseg),
                    "right": _side(j1 + k + 1, disp2[j1 + k], rseg),
                })
                changed += 1
            for k in range(i1 + paired, i2):  # extra originals → removals
                rows.append({"type": "remove", "left": _side(k + 1, disp1[k]), "right": None})
                removed += 1
            for k in range(j1 + paired, j2):  # extra changed → additions
                rows.append({"type": "add", "left": None, "right": _side(k + 1, disp2[k])})
                added += 1

    similarity = round(difflib.SequenceMatcher(None, "\n".join(cmp1), "\n".join(cmp2)).ratio() * 100, 1)
    identical = added == 0 and removed == 0 and changed == 0

    return {
        "rows": rows,
        "stats": {
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": unchanged,
            "similarity": similarity,
            "identical": identical,
        },
        "options": {
            "ignore_whitespace": ignore_whitespace,
            "ignore_case": ignore_case,
            "granularity": granularity,
        },
        "unified": unified(text1, text2),
    }


def unified(text1: str, text2: str, n: int = 3) -> str:
    """Standard unified diff text — powers the 'Copy unified' button."""
    lines = difflib.unified_diff(
        text1.splitlines(),
        text2.splitlines(),
        fromfile="original",
        tofile="changed",
        lineterm="",
        n=n,
    )
    return "\n".join(lines)
