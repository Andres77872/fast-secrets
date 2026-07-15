"""Tests for the browser-local text-diff engine (diffing.py)."""

import pytest

from fast_secrets import diffing


# ── helpers ──────────────────────────────────────────────────────────────────
def _types(payload):
    return [r["type"] for r in payload["rows"]]


def _assert_lossless(payload):
    """Every side's segment texts must rejoin to that side's line verbatim."""
    for row in payload["rows"]:
        for side in (row["left"], row["right"]):
            if side is not None:
                assert "".join(s["text"] for s in side["segs"]) == side["text"]


# ── pure engine ──────────────────────────────────────────────────────────────
def test_identical_texts():
    p = diffing.diff_texts("a\nb\nc", "a\nb\nc")
    assert p["stats"]["identical"] is True
    assert p["stats"]["similarity"] == 100.0
    assert set(_types(p)) == {"equal"}


def test_both_empty():
    p = diffing.diff_texts("", "")
    assert p["rows"] == []
    assert p["stats"]["identical"] is True


def test_pure_insert():
    p = diffing.diff_texts("a\nb", "a\nb\nc")
    assert _types(p) == ["equal", "equal", "add"]
    assert p["stats"]["added"] == 1 and p["stats"]["removed"] == 0
    add_row = p["rows"][-1]
    assert add_row["left"] is None and add_row["right"]["text"] == "c"


def test_pure_delete():
    p = diffing.diff_texts("a\nb\nc", "a\nb")
    assert _types(p) == ["equal", "equal", "remove"]
    assert p["stats"]["removed"] == 1 and p["stats"]["added"] == 0
    rem_row = p["rows"][-1]
    assert rem_row["right"] is None and rem_row["left"]["text"] == "c"


def test_replace_with_intra_line_highlight():
    p = diffing.diff_texts("hello world", "hello brave world")
    assert _types(p) == ["change"]
    row = p["rows"][0]
    assert any(s["hl"] for s in row["right"]["segs"])  # "brave " highlighted
    # equal portions are not highlighted
    assert any(not s["hl"] for s in row["right"]["segs"])
    _assert_lossless(p)


def test_char_granularity():
    p = diffing.diff_texts("abc", "axc", granularity="char")
    row = p["rows"][0]
    hl = [s["text"] for s in row["right"]["segs"] if s["hl"]]
    assert hl == ["x"]
    _assert_lossless(p)


def test_ignore_whitespace():
    on = diffing.diff_texts("a  b", "a b", ignore_whitespace=True)
    assert on["stats"]["identical"] is True
    off = diffing.diff_texts("a  b", "a b", ignore_whitespace=False)
    assert off["stats"]["identical"] is False


def test_ignore_case():
    on = diffing.diff_texts("Hello", "hello", ignore_case=True)
    assert on["stats"]["identical"] is True
    off = diffing.diff_texts("Hello", "hello", ignore_case=False)
    assert off["stats"]["identical"] is False


def test_crlf_equals_lf():
    p = diffing.diff_texts("a\r\nb", "a\nb")
    assert p["stats"]["identical"] is True


def test_stats_counts():
    p = diffing.diff_texts("keep\nold\ngone", "keep\nnew")
    s = p["stats"]
    assert s["unchanged"] == 1   # "keep"
    assert s["changed"] == 1     # old -> new
    assert s["removed"] == 1     # gone
    assert s["added"] == 0


def test_similarity_is_monotonic():
    close = diffing.diff_texts("the quick brown fox", "the quick brown cat")["stats"]["similarity"]
    far = diffing.diff_texts("the quick brown fox", "zzz")["stats"]["similarity"]
    assert close > far


def test_segments_lossless_across_inputs():
    for a, b in [("foo(bar)", "foo(baz)"), ("x y z", "x q z r"), ("", "abc"), ("abc", "")]:
        _assert_lossless(diffing.diff_texts(a, b))


def test_large_input_raises():
    big = "x\n" * (diffing.MAX_LINES + 1)
    with pytest.raises(ValueError):
        diffing.diff_texts(big, "y")


def test_unified_output():
    out = diffing.unified("a\nb\nc", "a\nB\nc")
    assert "@@" in out
    assert "-b" in out and "+B" in out
