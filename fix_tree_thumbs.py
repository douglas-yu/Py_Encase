
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_tree_thumbs.py  v3
======================
Patches forensic_qt.py with two features:

  1. Evidence tree (left panel) - FOLDERS ONLY.
     File nodes removed from _populate_dir_children (host fs)
     and _populate_image_children (forensic image).

  2. Thumbnail view - adds a  [List] [Thumbs]  toggle to the
     file-list path bar.  Real thumbnails for images, colour
     tiles for folders and other file types.

All patch strings are built line-by-line with  "..." + "..."
concatenation so there are zero multiline triple-quoted strings
that could hide bad escape sequences.

Usage:
    python fix_tree_thumbs.py  path/to/forensic_qt.py
"""

import sys, os, shutil


def patch(code, old, new, tag):
    if old not in code:
        print("  [SKIP] not found - " + tag)
        return code
    print("  [OK]   " + tag)
    return code.replace(old, new, 1)


# ---------------------------------------------------------------------------
# P1  Remove file nodes from _populate_dir_children  (host filesystem tree)
# ---------------------------------------------------------------------------
P1_OLD = (
    "        for entry in files[:300]:\n"
    "            icon = self._file_icon(entry.name)\n"
    "            try:    sz = fmt_size(entry.stat().st_size)\n"
    "            except: sz = \"\"\n"
    "            child = self._make_item(\"%s  %s  (%s)\" % (icon, entry.name, sz),\n"
    "                                    color=C['fg2'],\n"
    "                                    data={\"type\": \"file\", \"path\": str(entry)})\n"
    "            parent_item.addChild(child)\n"
    "        if not dirs and not files:\n"
    "            parent_item.addChild(self._make_item(\"  [Empty]\", color=C['fg3']))"
)
P1_NEW = (
    "        # File nodes omitted from tree - shown in right-panel file list.\n"
    "        if not dirs:\n"
    "            parent_item.addChild(\n"
    "                self._make_item(\"  [No subfolders]\", color=C['fg3']))"
)

# ---------------------------------------------------------------------------
# P2  Remove file nodes from _populate_image_children  (forensic image tree)
# ---------------------------------------------------------------------------
P2_OLD = (
    "        for e in files[:500]:\n"
    "            icon = self._file_icon(e['name'])\n"
    "            sz   = fmt_size(e['size']) if e['size'] else \"\"\n"
    "            child = self._make_item(\"%s  %s  (%s)\" % (icon, e['name'], sz),\n"
    "                                    color=C['fg2'],\n"
    "                                    data={\"type\":       \"img_file\",\n"
    "                                          \"image_path\": image_path,\n"
    "                                          \"inode\":      e['inode'],\n"
    "                                          \"name\":       e['name'],\n"
    "                                          \"size\":       e['size'],\n"
    "                                          \"mtime\":      e['mtime']})\n"
    "            parent_item.addChild(child)"
)
P2_NEW = (
    "        # File nodes omitted from image tree - shown in right-panel file list."
)

# ---------------------------------------------------------------------------
# P3  Add QListView to the PyQt6 imports
# ---------------------------------------------------------------------------
P3_OLD = (
    "    QStackedWidget, QFormLayout, QSpinBox, QToolButton, QAbstractItemView,\n"
    "    QScrollBar,\n"
    ")"
)
P3_NEW = (
    "    QStackedWidget, QFormLayout, QSpinBox, QToolButton, QAbstractItemView,\n"
    "    QScrollBar, QListView,\n"
    ")"
)

# ---------------------------------------------------------------------------
# P4  Add [List] [Thumbs] toggle buttons to the path bar in _setup()
# ---------------------------------------------------------------------------
P4_OLD = (
    "        go_btn = QPushButton(\"Go\")\n"
    "        go_btn.setFixedWidth(36)\n"
    "        go_btn.clicked.connect(self._go_path)\n"
    "        pbl.addWidget(go_btn)\n"
    "        rtl.addWidget(pb)"
)
P4_NEW = (
    "        go_btn = QPushButton(\"Go\")\n"
    "        go_btn.setFixedWidth(36)\n"
    "        go_btn.clicked.connect(self._go_path)\n"
    "        pbl.addWidget(go_btn)\n"
    "\n"
    "        # View-mode toggle buttons\n"
    "        _vsep = QFrame()\n"
    "        _vsep.setFrameShape(QFrame.Shape.VLine)\n"
    "        _vsep.setFixedWidth(2)\n"
    "        _vsep.setStyleSheet(f\"background:{C['border']};\")\n"
    "        pbl.addWidget(_vsep)\n"
    "        _tss = (\n"
    "            f\"QPushButton{{background:{C['btn']};color:{C['fg2']};\"\n"
    "            f\"border:1px solid {C['border']};border-radius:3px;\"\n"
    "            f\"padding:2px 8px;font-size:9pt;}}\"\n"
    "            f\"QPushButton:checked{{background:{C['sel']};color:{C['accent']};\"\n"
    "            f\"border-color:{C['accent']};}}\"\n"
    "        )\n"
    "        self._btn_list  = QPushButton(\"\u2630 List\")\n"
    "        self._btn_thumb = QPushButton(\"\u229e Thumbs\")\n"
    "        for _b in (self._btn_list, self._btn_thumb):\n"
    "            _b.setCheckable(True)\n"
    "            _b.setFixedHeight(24)\n"
    "            _b.setStyleSheet(_tss)\n"
    "        self._btn_list.setChecked(True)\n"
    "        self._btn_list.clicked.connect(\n"
    "            lambda: self._switch_file_view(\"list\"))\n"
    "        self._btn_thumb.clicked.connect(\n"
    "            lambda: self._switch_file_view(\"thumb\"))\n"
    "        pbl.addWidget(self._btn_list)\n"
    "        pbl.addWidget(self._btn_thumb)\n"
    "        rtl.addWidget(pb)"
)

# ---------------------------------------------------------------------------
# P5  Wrap file_table + new thumb_list in a QStackedWidget
# ---------------------------------------------------------------------------
P5_OLD = (
    "        self.file_table.customContextMenuRequested.connect(self._file_ctx)\n"
    "        rtl.addWidget(self.file_table)\n"
    "        v_split.addWidget(right_top)"
)
P5_NEW = (
    "        self.file_table.customContextMenuRequested.connect(self._file_ctx)\n"
    "\n"
    "        # Thumbnail grid widget\n"
    "        self.thumb_list = QListWidget()\n"
    "        self.thumb_list.setViewMode(QListView.ViewMode.IconMode)\n"
    "        self.thumb_list.setIconSize(QSize(112, 112))\n"
    "        self.thumb_list.setGridSize(QSize(138, 158))\n"
    "        self.thumb_list.setResizeMode(QListView.ResizeMode.Adjust)\n"
    "        self.thumb_list.setMovement(QListView.Movement.Static)\n"
    "        self.thumb_list.setSpacing(6)\n"
    "        self.thumb_list.setUniformItemSizes(True)\n"
    "        self.thumb_list.setWordWrap(True)\n"
    "        self.thumb_list.setStyleSheet(\n"
    "            f\"QListWidget{{background:{C['bg']};border:none;outline:none;}}\"\n"
    "            f\"QListWidget::item{{color:{C['fg']};font-size:8pt;padding:2px;\"\n"
    "            f\"border-radius:4px;}}\"\n"
    "            f\"QListWidget::item:selected{{background:{C['sel']};\"\n"
    "            f\"color:{C['accent']};}}\"\n"
    "            f\"QListWidget::item:hover:!selected{{background:{C['bg3']};}}\")\n"
    "        self.thumb_list.doubleClicked.connect(self._on_thumb_double)\n"
    "        self.thumb_list.setContextMenuPolicy(\n"
    "            Qt.ContextMenuPolicy.CustomContextMenu)\n"
    "        self.thumb_list.customContextMenuRequested.connect(self._thumb_ctx)\n"
    "\n"
    "        # Stack: index 0 = table list, index 1 = thumbnail grid\n"
    "        self._view_stack = QStackedWidget()\n"
    "        self._view_stack.addWidget(self.file_table)\n"
    "        self._view_stack.addWidget(self.thumb_list)\n"
    "        self._view_mode  = \"list\"\n"
    "        self._thumb_stop = [False]\n"
    "\n"
    "        rtl.addWidget(self._view_stack)\n"
    "        v_split.addWidget(right_top)"
)

# ---------------------------------------------------------------------------
# P6  Inject thumbnail helper methods before _file_icon()
#
#     Outer delimiter: '''  (single-quoted triple string)
#     Inside: only double-quoted strings and # comments — no ''' anywhere.
#     No \U \S \C escape sequences anywhere in this block.
# ---------------------------------------------------------------------------
P6_OLD = "    def _file_icon(self, name):"
P6_NEW = (
'''    # ── Thumbnail view helpers ──────────────────────────────────────────────

    def _switch_file_view(self, mode):
        # Switch between list (table) and thumb (grid) views.
        self._view_mode = mode
        if mode == "thumb":
            self._btn_list.setChecked(False)
            self._btn_thumb.setChecked(True)
            self._view_stack.setCurrentIndex(1)
            self._load_dir_thumbnails(self.current_dir)
        else:
            self._btn_list.setChecked(True)
            self._btn_thumb.setChecked(False)
            self._view_stack.setCurrentIndex(0)

    def _load_dir_thumbnails(self, path):
        # Fill the thumbnail grid for the given directory path.
        self._thumb_stop[0] = True
        self._thumb_stop = [False]
        self.thumb_list.clear()
        IMG_EXTS = {".jpg", ".jpeg", ".png", ".gif",
                    ".bmp", ".tiff", ".tif", ".webp", ".ico"}
        try:
            entries = sorted(
                path.iterdir(),
                key=lambda x: (not x.is_dir(), x.name.lower()))
        except Exception:
            entries = []
        up = QListWidgetItem("\u2b06  ..")
        up.setData(Qt.ItemDataRole.UserRole,     str(path.parent))
        up.setData(Qt.ItemDataRole.UserRole + 1, "dir")
        up.setToolTip("Go to parent directory")
        up.setIcon(self._make_thumb_icon(C["bg3"], "UP"))
        self.thumb_list.addItem(up)
        img_n = 0
        stop  = self._thumb_stop
        for entry in entries:
            if stop[0]:
                break
            raw   = entry.name
            label = (raw[:20] + "\u2026") if len(raw) > 20 else raw
            item  = QListWidgetItem(label)
            item.setToolTip(raw)
            item.setData(Qt.ItemDataRole.UserRole,     str(entry))
            item.setData(Qt.ItemDataRole.UserRole + 1,
                         "dir" if entry.is_dir() else "file")
            if entry.is_dir():
                item.setIcon(self._make_thumb_icon(C["orange"], "DIR"))
            else:
                ext = entry.suffix.lower()
                if ext in IMG_EXTS:
                    try:
                        pix = QPixmap(str(entry))
                        if not pix.isNull():
                            pix = pix.scaled(
                                112, 112,
                                Qt.AspectRatioMode.KeepAspectRatio,
                                Qt.TransformationMode.SmoothTransformation)
                            item.setIcon(QIcon(pix))
                        else:
                            item.setIcon(
                                self._make_thumb_icon(C["bg3"], "IMG"))
                    except Exception:
                        item.setIcon(self._make_thumb_icon(C["bg3"], "IMG"))
                    img_n += 1
                else:
                    abbr = entry.suffix.upper().lstrip(".")[:4] or "FILE"
                    item.setIcon(self._make_thumb_icon(C["bg2"], abbr))
            self.thumb_list.addItem(item)
            if img_n and img_n % 12 == 0:
                QApplication.processEvents()

    def _make_thumb_icon(self, bg_color, label=""):
        # Return a solid-colour QIcon with optional centred text label.
        pix = QPixmap(112, 96)
        pix.fill(QColor(bg_color))
        if label:
            painter = QPainter(pix)
            painter.setPen(QColor(C["fg"]))
            f = QFont()
            f.setPointSize(9)
            f.setBold(True)
            painter.setFont(f)
            painter.drawText(pix.rect(), Qt.AlignmentFlag.AlignCenter, label)
            painter.end()
        return QIcon(pix)

    def _on_thumb_double(self, _index):
        # Navigate folder or open file in content viewer on double-click.
        item = self.thumb_list.currentItem()
        if not item:
            return
        p    = item.data(Qt.ItemDataRole.UserRole)
        kind = item.data(Qt.ItemDataRole.UserRole + 1)
        if not p:
            return
        entry = Path(p)
        if kind == "dir" or entry.is_dir():
            self._load_dir(entry)
        elif entry.is_file():
            self.content.load_path(str(entry))

    def _thumb_ctx(self, pos):
        # Right-click context menu for thumbnail grid items.
        item = self.thumb_list.itemAt(pos)
        if not item:
            return
        p    = item.data(Qt.ItemDataRole.UserRole)
        kind = item.data(Qt.ItemDataRole.UserRole + 1)
        if not p:
            return
        entry  = Path(p)
        is_dir = (kind == "dir" or entry.is_dir())
        menu   = QMenu(self)
        menu.addAction("Open",
            lambda: self._load_dir(entry) if is_dir
                    else self.content.load_path(str(entry)))
        if entry.is_file():
            menu.addSeparator()
            menu.addAction("Save As\u2026",
                lambda: self._save_host_file_as(entry))
        menu.addSeparator()
        bm_sub = menu.addMenu("Add to Bookmark\u2026")
        try:
            _sz = fmt_size(entry.stat().st_size) if entry.is_file() else ""
        except Exception:
            _sz = ""
        _bm = {
            "Name": item.toolTip(),
            "Path": str(entry),
            "Type": "Directory" if is_dir else detect_type(str(entry)),
            "Size": _sz,
        }
        for tag in ["Key Finding", "File of Interest",
                    "Malware Indicator", "Suspicious", "IOC"]:
            bm_sub.addAction(tag,
                lambda t=tag, d=_bm: self.main._on_bookmark(
                    "File Browser", dict(d), t))
        menu.exec(self.thumb_list.viewport().mapToGlobal(pos))

    def _file_icon(self, name):'''
)

# ---------------------------------------------------------------------------
# P7  _load_dir(): auto-refresh thumbnail grid when thumb mode is active
#     The em-dash in the status string is U+2014 written as \u2014.
# ---------------------------------------------------------------------------
P7_OLD = (
    "        self.file_table.setSortingEnabled(True)\n"
    "        self.main.set_status(f\"  {path}  \u2014  {len(entries)} item(s)\")\n"
    "\n"
    "        # Sync tree selection\n"
    "        self._sync_tree_to_path(path)"
)
P7_NEW = (
    "        self.file_table.setSortingEnabled(True)\n"
    "        self.main.set_status(f\"  {path}  \u2014  {len(entries)} item(s)\")\n"
    "\n"
    "        # Refresh thumbnail grid if it is the active view\n"
    "        if getattr(self, \"_view_mode\", \"list\") == \"thumb\":\n"
    "            self._load_dir_thumbnails(path)\n"
    "\n"
    "        # Sync tree selection\n"
    "        self._sync_tree_to_path(path)"
)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_tree_thumbs.py <forensic_qt.py>")
        sys.exit(1)
    src = sys.argv[1]
    if not os.path.isfile(src):
        print("Error: not found - " + src)
        sys.exit(1)

    bak = src + ".bak_tt"
    shutil.copy2(src, bak)
    print("Backup : " + bak + "\n")

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    print("Applying patches...")
    code = patch(code, P1_OLD, P1_NEW, "1 - Remove files from host-filesystem tree")
    code = patch(code, P2_OLD, P2_NEW, "2 - Remove files from forensic-image tree")
    code = patch(code, P3_OLD, P3_NEW, "3 - Add QListView to imports")
    code = patch(code, P4_OLD, P4_NEW, "4 - Add List/Thumbs toggle buttons to path bar")
    code = patch(code, P5_OLD, P5_NEW, "5 - Add thumb_list + QStackedWidget to _setup()")
    code = patch(code, P6_OLD, P6_NEW, "6 - Inject thumbnail helper methods")
    code = patch(code, P7_OLD, P7_NEW, "7 - _load_dir() auto-refresh thumbnails")

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(code)

    print("\nDone  : " + src)
    print("Restore: " + bak)
    print("\nChanges:")
    print("  Tree        : folders only (file nodes removed)")
    print("  Path bar    : [List] [Thumbs] toggle added")
    print("  Thumb grid  : real thumbnails for images, colour tiles for others")
    print("  Double-click: navigate dirs / open files in content viewer")
    print("  Right-click : Open / Save As / Add to Bookmark")


if __name__ == "__main__":
    main()
