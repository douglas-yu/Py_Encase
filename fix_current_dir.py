
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_image_browse.py
===================
Fixes ALL forensic-image browsing issues in EvidenceBrowser.
Run AFTER fix_tree_thumbs.py.

Root causes fixed
-----------------
1. _load_image_dir() never set self._in_image_mode = True, so
   current_dir kept pointing at the last host-fs directory while
   the file table showed forensic-image contents.
   _go_up(), thumbnail switch, and hash all then used the wrong path.

2. _on_file_double(), _on_file_select(), and _file_ctx() all computed
       path = self.current_dir / name
   instead of reading the absolute path already stored in column 6
   by _add_file_row().  Column 6 is always authoritative.

3. _switch_file_view("thumb") passed self.current_dir to the thumbnail
   loader even when in image-mode, showing thumbnails from the wrong
   (old host-fs) directory.

Changes
-------
A  _load_dir          — set self._in_image_mode = False
B  _load_image_dir    — set self._in_image_mode = True
C  _go_up             — return early when _in_image_mode is True
D  _on_file_double    — read path from col 6, fallback current_dir/name
E  _on_file_select    — read path from col 6, fallback current_dir/name
F  _file_ctx          — read path from col 6, fallback current_dir/name
G  _switch_file_view  — guard thumb-load with _in_image_mode check

Usage
-----
    python fix_current_dir.py  path/to/forensic_qt.py
"""

import sys, os, shutil


def patch(code, old, new, tag):
    if old not in code:
        print("  [SKIP] not found - " + tag)
        return code
    print("  [OK]   " + tag)
    return code.replace(old, new, 1)


# ---------------------------------------------------------------------------
# A  _load_dir: mark host-fs mode, clear image-mode flag
# ---------------------------------------------------------------------------
PA_OLD = (
    "    def _load_dir(self, path: Path):\n"
    "        self.current_dir = path\n"
    "        self.path_edit.setText(str(path))"
)
PA_NEW = (
    "    def _load_dir(self, path: Path):\n"
    "        self.current_dir = path\n"
    "        self._in_image_mode = False   # host-fs navigation\n"
    "        self.path_edit.setText(str(path))"
)

# ---------------------------------------------------------------------------
# B  _load_image_dir: mark image-fs mode so host-fs helpers know to bail
# ---------------------------------------------------------------------------
PB_OLD = (
    "        self._img_context = {\"image_path\": image_path, \"inode\": inode}\n"
    "        ifs = ForensicImageFS.get(image_path)"
)
PB_NEW = (
    "        self._in_image_mode = True    # forensic-image navigation\n"
    "        self._img_context = {\"image_path\": image_path, \"inode\": inode}\n"
    "        ifs = ForensicImageFS.get(image_path)"
)

# ---------------------------------------------------------------------------
# C  _go_up: bail out when viewing a forensic image directory
# ---------------------------------------------------------------------------
PC_OLD = (
    "    def _go_up(self):\n"
    "        self._load_dir(self.current_dir.parent)"
)
PC_NEW = (
    "    def _go_up(self):\n"
    "        if getattr(self, \"_in_image_mode\", False):\n"
    "            return  # no host-fs parent when browsing a forensic image\n"
    "        self._load_dir(self.current_dir.parent)"
)

# ---------------------------------------------------------------------------
# D  _on_file_double: use col-6 absolute path, not current_dir / name
# ---------------------------------------------------------------------------
PD_OLD = (
    "        # Host filesystem entry\n"
    "        name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "        if name == \"..\":\n"
    "            self._go_up(); return\n"
    "        path = self.current_dir / name\n"
    "        if path.is_dir():\n"
    "            self._load_dir(path)"
)
PD_NEW = (
    "        # Host filesystem entry\n"
    "        name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "        if name == \"..\":\n"
    "            self._go_up(); return\n"
    "        # Prefer absolute path from col 6 (set by _add_file_row) over\n"
    "        # current_dir / name which is stale when in image mode.\n"
    "        _p6d = self.file_table.item(index.row(), 6)\n"
    "        path = Path(_p6d.text()) if (_p6d and _p6d.text()) \\\n"
    "               else self.current_dir / name\n"
    "        if path.is_dir():\n"
    "            self._load_dir(path)"
)

# ---------------------------------------------------------------------------
# E  _on_file_select: use col-6 absolute path, not current_dir / name
# ---------------------------------------------------------------------------
PE_OLD = (
    "        # Host filesystem entry\n"
    "        name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "        path = self.current_dir / name\n"
    "        if path.is_file():\n"
    "            self.content.load_path(str(path))"
)
PE_NEW = (
    "        # Host filesystem entry\n"
    "        name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "        # Prefer absolute path from col 6 over current_dir / name\n"
    "        _p6s = self.file_table.item(row, 6)\n"
    "        path = Path(_p6s.text()) if (_p6s and _p6s.text()) \\\n"
    "               else self.current_dir / name\n"
    "        if path.is_file():\n"
    "            self.content.load_path(str(path))"
)

# ---------------------------------------------------------------------------
# F  _file_ctx (EvidenceBrowser else-branch): use col-6 absolute path
# There are two variants of this pattern in the wild depending on which
# previous patches were applied; we try both.
# ---------------------------------------------------------------------------

# Variant 1 — original source form
PF1_OLD = (
    "        else:\n"
    "            name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "            path = self.current_dir / name\n"
    "            menu.addAction(\"Open / Navigate\","
)
PF1_NEW = (
    "        else:\n"
    "            name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "            # Prefer absolute path from col 6 over current_dir / name\n"
    "            _p6f = self.file_table.item(row, 6)\n"
    "            path = Path(_p6f.text()) if (_p6f and _p6f.text()) \\\n"
    "                   else self.current_dir / name\n"
    "            menu.addAction(\"Open / Navigate\","
)

# Variant 2 — alternative source form seen in some builds
PF2_OLD = (
    "        else:\n"
    "            name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "            path = self.current_dir / name\n"
    "            is_dir = path.is_dir()"
)
PF2_NEW = (
    "        else:\n"
    "            name = item_data if isinstance(item_data, str) else name_item.text()\n"
    "            _p6f = self.file_table.item(row, 6)\n"
    "            path = Path(_p6f.text()) if (_p6f and _p6f.text()) \\\n"
    "                   else self.current_dir / name\n"
    "            is_dir = path.is_dir()"
)

# ---------------------------------------------------------------------------
# G  _switch_file_view (injected by fix_tree_thumbs.py):
#    guard thumbnail load against image mode
# ---------------------------------------------------------------------------
PG_OLD = (
    "            self._view_stack.setCurrentIndex(1)\n"
    "            self._load_dir_thumbnails(self.current_dir)\n"
    "        else:\n"
    "            self._btn_list.setChecked(True)\n"
    "            self._btn_thumb.setChecked(False)\n"
    "            self._view_stack.setCurrentIndex(0)"
)
PG_NEW = (
    "            self._view_stack.setCurrentIndex(1)\n"
    "            if getattr(self, \"_in_image_mode\", False):\n"
    "                self.thumb_list.clear()\n"
    "                _mi = QListWidgetItem(\n"
    "                    \"Thumbnail view is not available\"\n"
    "                    \" for forensic image entries.\\n\"\n"
    "                    \"Switch to List view to browse.\")\n"
    "                self.thumb_list.addItem(_mi)\n"
    "            else:\n"
    "                self._load_dir_thumbnails(self.current_dir)\n"
    "        else:\n"
    "            self._btn_list.setChecked(True)\n"
    "            self._btn_thumb.setChecked(False)\n"
    "            self._view_stack.setCurrentIndex(0)"
)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_current_dir.py <forensic_qt.py>")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.isfile(src):
        print("Error: not found - " + src)
        sys.exit(1)

    bak = src + ".bak_cd"
    shutil.copy2(src, bak)
    print("Backup : " + bak + "\n")

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    print("Applying patches...")
    code = patch(code, PA_OLD, PA_NEW,
                 "A - _load_dir: set _in_image_mode = False")
    code = patch(code, PB_OLD, PB_NEW,
                 "B - _load_image_dir: set _in_image_mode = True")
    code = patch(code, PC_OLD, PC_NEW,
                 "C - _go_up: bail when in image mode")
    code = patch(code, PD_OLD, PD_NEW,
                 "D - _on_file_double: use col-6 absolute path")
    code = patch(code, PE_OLD, PE_NEW,
                 "E - _on_file_select: use col-6 absolute path")

    # Try both variants for _file_ctx
    before_f = code
    code = patch(code, PF1_OLD, PF1_NEW,
                 "F - _file_ctx variant 1 (Open/Navigate form)")
    if code is before_f or PF1_OLD not in before_f:
        code = patch(code, PF2_OLD, PF2_NEW,
                     "F - _file_ctx variant 2 (is_dir form)")

    code = patch(code, PG_OLD, PG_NEW,
                 "G - _switch_file_view: guard thumbnails in image mode")

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(code)

    print("\nDone  : " + src)
    print("Restore: " + bak)
    print()
    print("Summary of root causes fixed:")
    print("  A+B  _in_image_mode flag — tracks host-fs vs image-fs mode")
    print("  C    _go_up     — no longer navigates into host-fs from image view")
    print("  D    double-click — uses col-6 absolute path, not current_dir/name")
    print("  E    selection    — uses col-6 absolute path, not current_dir/name")
    print("  F    right-click  — uses col-6 absolute path, not current_dir/name")
    print("  G    thumb view   — shows notice instead of wrong dir in image mode")


if __name__ == "__main__":
    main()
