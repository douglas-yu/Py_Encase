
#!/usr/bin/env python3
"""
fix_bookmark_lambda.py
======================
Fixes the 'Add to Bookmark' crash:

    TypeError: EvidenceBrowser._file_ctx.<locals>.<lambda>()
               missing 1 required positional argument: '_'

Root cause
----------
PyQt6's  QMenu.addAction(str, callable)  calls the slot with NO arguments —
it does NOT pass the triggered(bool) value through this convenience overload.
Every lambda with  `_, `  as its first required parameter therefore crashes.

Locations fixed
---------------
  1. EvidenceBrowser._file_ctx  — image-browser bookmark submenu
     (handles both the original `dd=d` form AND the previously patched `dd=_bm2` form)
  2. EvidenceBrowser._file_ctx  — host-file bookmark submenu
  3. ResultsTab._table_ctx      — analysis-results bookmark submenu

Usage
-----
    python fix_bookmark_lambda.py path/to/forensic_qt.py
"""

import sys, os, shutil

# ── helpers ──────────────────────────────────────────────────────────────────

def patch(code: str, old: str, new: str, tag: str, replace_all: bool = False) -> str:
    count = code.count(old)
    if count == 0:
        print(f"  [SKIP] not found — {tag}")
        return code
    result = code.replace(old, new) if replace_all else code.replace(old, new, 1)
    applied = code.count(old) - result.count(old)
    print(f"  [OK]   {tag}  ({applied}× replaced)")
    return result

# ── FIX 1a: image-browser bookmark — original form (dd=d) ────────────────────
# The lambda loop variable capture used d directly.

F1A_OLD = """\
                    bm_sub2.addAction(tag,
                        lambda _, t=tag, dd=d: self.main._on_bookmark(
                            "Image Browser",
                            {"Name": dd["name"], "Image": dd["image_path"],
                             "Inode": str(dd["inode"]),
                             "Size": fmt_size(dd.get("size",0))}, t))"""

F1A_NEW = """\
                    bm_sub2.addAction(tag,
                        lambda t=tag, dd=d: self.main._on_bookmark(
                            "Image Browser",
                            {"Name": dd["name"], "Image": dd["image_path"],
                             "Inode": str(dd["inode"]),
                             "Size": fmt_size(dd.get("size",0))}, t))"""

# ── FIX 1b: image-browser bookmark — previously patched form (dd=_bm2) ───────
# Only present if the earlier patcher (fix 1) was already applied.

F1B_OLD = """\
                    bm_sub2.addAction(tag,
                        lambda _, t=tag, dd=_bm2: self.main._on_bookmark(
                            "Image Browser",
                            {"Name":  dd["name"],
                             "Image": dd["image_path"],
                             "Inode": dd["inode"],
                             "Size":  fmt_size(dd["size"])}, t))"""

F1B_NEW = """\
                    bm_sub2.addAction(tag,
                        lambda t=tag, dd=_bm2: self.main._on_bookmark(
                            "Image Browser",
                            {"Name":  dd["name"],
                             "Image": dd["image_path"],
                             "Inode": dd["inode"],
                             "Size":  fmt_size(dd["size"])}, t))"""

# ── FIX 2: host-file bookmark submenu ────────────────────────────────────────

F2_OLD = """\
                bm_sub.addAction(tag,
                    lambda _, t=tag, d=_bm_data: self.main._on_bookmark(
                        "File Browser", dict(d), t))"""

F2_NEW = """\
                bm_sub.addAction(tag,
                    lambda t=tag, d=_bm_data: self.main._on_bookmark(
                        "File Browser", dict(d), t))"""

# ── FIX 3: results-table bookmark submenu ────────────────────────────────────
# rd is captured by closure (not a default arg) — that is intentional and safe
# because rd is a local dict computed right above and never reassigned.

F3_OLD = """\
            bm.addAction(tag,
                lambda _, t=tag: self.bookmark_requested.emit(
                    self._current_name, dict(rd), t))"""

F3_NEW = """\
            bm.addAction(tag,
                lambda t=tag: self.bookmark_requested.emit(
                    self._current_name, dict(rd), t))"""

# ── entry point ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_bookmark_lambda.py <forensic_qt.py>")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"Error: file not found — {src}")
        sys.exit(1)

    bak = src + ".bak2"
    shutil.copy2(src, bak)
    print(f"Backup: {bak}\n")

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    print("Applying patches …")
    code = patch(code, F1A_OLD, F1A_NEW,
                 "Fix 1a — image-browser bookmark lambda (original form, dd=d)")
    code = patch(code, F1B_OLD, F1B_NEW,
                 "Fix 1b — image-browser bookmark lambda (patched form, dd=_bm2)")
    code = patch(code, F2_OLD,  F2_NEW,
                 "Fix 2  — host-file bookmark lambda")
    code = patch(code, F3_OLD,  F3_NEW,
                 "Fix 3  — results-table bookmark lambda", replace_all=True)

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(code)

    print(f"\nDone — patched: {src}")
    print(f"       Restore: {bak}")
    print()
    print("Summary of what was changed")
    print("  ALL  lambda _, t=tag  …  ──►  lambda t=tag  …")
    print("  ALL  lambda _, t=tag, dd=…  ──►  lambda t=tag, dd=…")
    print()
    print("Why:  PyQt6 QMenu.addAction(str, slot) calls slot() with ZERO args.")
    print("      Having `_` as a required positional arg crashes the app.")


if __name__ == "__main__":
    main()
