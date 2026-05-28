#!/usr/bin/env python3
# THIS LINE IS A REWRITE MARKER — REPLACED BY FULL REWRITE BELOW
# (actual content starts at the next rewrite block)
"""
fix_tree_thumb_usb.py
=====================
Three targeted enhancements for forensic_qt.py:

  1. Evidence tree (left panel) shows FOLDERS ONLY — files are removed.
  2. Thumbnail view toggle added to the file-list panel (☰ List | ⊞ Thumbs).
       • Folders show an orange "DIR" tile.
       • Image files (.jpg .jpeg .png .gif .bmp .tiff .webp .ico) show real
         thumbnails loaded synchronously with processEvents() every 12 images.
       • All other files show a coloured tile labelled with their extension.
       • Double-click navigates into folders / opens files in the content viewer.
       • Right-click exposes Open / Save As / Add to Bookmark.
  3. New "Removable Media & USB" artifact category with four sub-artifacts:
       • USB Device History          (USBSTOR registry / udevadm / dmesg)
       • USB First/Last Connection Times (SetupAPI log / Event Log)
       • Drive Letter Assignments    (psutil partitions + MountPoints2)
       • Volume Serial Numbers       (MountedDevices registry / lsblk / blkid)

Usage
-----
    python fix_tree_thumb_usb.py  path/to/forensic_qt.py
"""

import sys, os, shutil

# ── helpers ──────────────────────────────────────────────────────────────────

def patch(code: str, old: str, new: str, tag: str,
          replace_all: bool = False) -> str:
    count = code.count(old)
    if count == 0:
        print(f"  [SKIP] not found — {tag}")
        print( "         (may already be applied or source differs)")
        return code
    result = (code.replace(old, new) if replace_all
              else code.replace(old, new, 1))
    applied = count - result.count(old)
    print(f"  [OK]   {tag}  ({applied}× replaced)")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 1 — Remove files from the left-panel tree (host filesystem)
# ─────────────────────────────────────────────────────────────────────────────

P1_OLD = """\
        for entry in files[:300]:
            icon = self._file_icon(entry.name)
            try:    sz = fmt_size(entry.stat().st_size)
            except: sz = ""
            child = self._make_item("%s  %s  (%s)" % (icon, entry.name, sz),
                                    color=C['fg2'],
                                    data={"type": "file", "path": str(entry)})
            parent_item.addChild(child)
        if not dirs and not files:
            parent_item.addChild(self._make_item("  [Empty]", color=C['fg3']))"""

P1_NEW = """\
        # Files intentionally omitted from the tree — they appear in the
        # right-panel file list when a folder is selected.
        if not dirs:
            parent_item.addChild(
                self._make_item("  [No subfolders]", color=C['fg3']))"""


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 2 — Remove files from the left-panel tree (forensic image)
# ─────────────────────────────────────────────────────────────────────────────

P2_OLD = """\
        for e in files[:500]:
            icon = self._file_icon(e['name'])
            sz   = fmt_size(e['size']) if e['size'] else ""
            child = self._make_item("%s  %s  (%s)" % (icon, e['name'], sz),
                                    color=C['fg2'],
                                    data={"type":       "img_file",
                                          "image_path": image_path,
                                          "inode":      e['inode'],
                                          "name":       e['name'],
                                          "size":       e['size'],
                                          "mtime":      e['mtime']})
            parent_item.addChild(child)"""

P2_NEW = """\
        # Files omitted from the image tree — shown in the right-panel list."""


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 3 — Add QListView to PyQt6 imports
# ─────────────────────────────────────────────────────────────────────────────

P3_OLD = """\
    QStackedWidget, QFormLayout, QSpinBox, QToolButton, QAbstractItemView,
    QScrollBar,
)"""

P3_NEW = """\
    QStackedWidget, QFormLayout, QSpinBox, QToolButton, QAbstractItemView,
    QScrollBar, QListView,
)"""


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 4 — Add view-toggle buttons (☰ List | ⊞ Thumbs) to the path bar
# ─────────────────────────────────────────────────────────────────────────────

P4_OLD = """\
        go_btn = QPushButton("Go")
        go_btn.setFixedWidth(36)
        go_btn.clicked.connect(self._go_path)
        pbl.addWidget(go_btn)
        rtl.addWidget(pb)"""

P4_NEW = """\
        go_btn = QPushButton("Go")
        go_btn.setFixedWidth(36)
        go_btn.clicked.connect(self._go_path)
        pbl.addWidget(go_btn)

        # ── View-mode toggle buttons ──────────────────────────────────
        _vsep = QFrame()
        _vsep.setFrameShape(QFrame.Shape.VLine)
        _vsep.setFixedWidth(2)
        _vsep.setStyleSheet(f"background:{C['border']};")
        pbl.addWidget(_vsep)

        _tgl_ss = (
            f"QPushButton{{background:{C['btn']};color:{C['fg2']};"
            f"border:1px solid {C['border']};border-radius:3px;"
            f"padding:2px 8px;font-size:9pt;}}"
            f"QPushButton:checked{{background:{C['sel']};color:{C['accent']};"
            f"border-color:{C['accent']};}}"
        )
        self._btn_list  = QPushButton("☰ List")
        self._btn_thumb = QPushButton("⊞ Thumbs")
        for _b in (self._btn_list, self._btn_thumb):
            _b.setCheckable(True)
            _b.setFixedHeight(24)
            _b.setStyleSheet(_tgl_ss)
        self._btn_list.setChecked(True)
        self._btn_list.clicked.connect(
            lambda: self._switch_file_view("list"))
        self._btn_thumb.clicked.connect(
            lambda: self._switch_file_view("thumb"))
        pbl.addWidget(self._btn_list)
        pbl.addWidget(self._btn_thumb)
        rtl.addWidget(pb)"""


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 5 — Add QListWidget (thumbnail grid) + QStackedWidget in _setup()
#            replaces the bare  rtl.addWidget(self.file_table)
# ─────────────────────────────────────────────────────────────────────────────

P5_OLD = """\
        self.file_table.customContextMenuRequested.connect(self._file_ctx)
        rtl.addWidget(self.file_table)
        v_split.addWidget(right_top)"""

P5_NEW = """\
        self.file_table.customContextMenuRequested.connect(self._file_ctx)

        # ── Thumbnail list widget (icon / grid mode) ──────────────────
        self.thumb_list = QListWidget()
        self.thumb_list.setViewMode(QListView.ViewMode.IconMode)
        self.thumb_list.setIconSize(QSize(112, 112))
        self.thumb_list.setGridSize(QSize(138, 158))
        self.thumb_list.setResizeMode(QListView.ResizeMode.Adjust)
        self.thumb_list.setMovement(QListView.Movement.Static)
        self.thumb_list.setSpacing(6)
        self.thumb_list.setUniformItemSizes(True)
        self.thumb_list.setWordWrap(True)
        self.thumb_list.setStyleSheet(
            f"QListWidget{{background:{C['bg']};border:none;outline:none;}}"
            f"QListWidget::item{{color:{C['fg']};font-size:8pt;padding:2px;"
            f"border-radius:4px;text-align:center;}}"
            f"QListWidget::item:selected{{background:{C['sel']};"
            f"color:{C['accent']};}}"
            f"QListWidget::item:hover:!selected{{background:{C['bg3']};}}")
        self.thumb_list.doubleClicked.connect(self._on_thumb_double)
        self.thumb_list.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.thumb_list.customContextMenuRequested.connect(self._thumb_ctx)

        # ── Stacked container: index 0 = table, index 1 = thumbnails ──
        self._view_stack = QStackedWidget()
        self._view_stack.addWidget(self.file_table)   # 0
        self._view_stack.addWidget(self.thumb_list)   # 1
        self._view_mode  = "list"
        self._thumb_stop = [False]   # cooperative stop-flag for thumb loader

        rtl.addWidget(self._view_stack)
        v_split.addWidget(right_top)"""


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 6 — Inject new methods immediately before  def _file_icon(self, name):
#
# NOTE: outer string uses  '''  so the inner  """docstrings"""  are safe.
# ─────────────────────────────────────────────────────────────────────────────

P6_OLD = "    def _file_icon(self, name):"

P6_NEW = '''    # ── Thumbnail view helpers ───────────────────────────────────────────────

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
        # Populate the thumbnail grid for path.
        self._thumb_stop[0] = True          # stop any in-flight loader
        self._thumb_stop = [False]          # fresh flag for this load
        self.thumb_list.clear()

        IMG_EXTS = {".jpg", ".jpeg", ".png", ".gif",
                    ".bmp", ".tiff", ".tif", ".webp", ".ico"}
        try:
            entries = sorted(
                path.iterdir(),
                key=lambda x: (not x.is_dir(), x.name.lower()))
        except Exception:
            entries = []

        # "Up" tile
        up_item = QListWidgetItem("\u2b06  ..")
        up_item.setData(Qt.ItemDataRole.UserRole,     str(path.parent))
        up_item.setData(Qt.ItemDataRole.UserRole + 1, "dir")
        up_item.setToolTip("Go to parent directory")
        up_item.setIcon(self._make_thumb_icon(C["bg3"], "UP"))
        self.thumb_list.addItem(up_item)

        img_n = 0
        stop  = self._thumb_stop
        for entry in entries:
            if stop[0]:
                break
            raw_name = entry.name
            label    = (raw_name[:20] + "\u2026") if len(raw_name) > 20 \
                       else raw_name
            item = QListWidgetItem(label)
            item.setToolTip(raw_name)
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
            # Keep UI responsive while loading real image thumbnails
            if img_n and img_n % 12 == 0:
                QApplication.processEvents()

    def _make_thumb_icon(self, bg_color, label=""):
        # Solid-colour placeholder icon with an optional centred text label.
        pix = QPixmap(112, 96)
        pix.fill(QColor(bg_color))
        if label:
            painter = QPainter(pix)
            painter.setPen(QColor(C["fg"]))
            f = QFont()
            f.setPointSize(9)
            f.setBold(True)
            painter.setFont(f)
            painter.drawText(
                pix.rect(), Qt.AlignmentFlag.AlignCenter, label)
            painter.end()
        return QIcon(pix)

    def _on_thumb_double(self, _index):
        # Navigate into folder / open file on thumbnail double-click.
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
        # Right-click context menu for the thumbnail grid.
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
            menu.addAction("\U0001f4be Save As\u2026",
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


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 7 — _load_dir(): refresh thumbnail grid when thumb mode is active
# ─────────────────────────────────────────────────────────────────────────────

P7_OLD = """\
        self.file_table.setSortingEnabled(True)
        self.main.set_status(f"  {path}  —  {len(entries)} item(s)")

        # Sync tree selection
        self._sync_tree_to_path(path)"""

P7_NEW = """\
        self.file_table.setSortingEnabled(True)
        self.main.set_status(f"  {path}  —  {len(entries)} item(s)")

        # Refresh thumbnail grid if that view is currently active
        if getattr(self, "_view_mode", "list") == "thumb":
            self._load_dir_thumbnails(path)

        # Sync tree selection
        self._sync_tree_to_path(path)"""


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 8 — Add "Removable Media & USB" to ARTIFACT_CATEGORIES
# ─────────────────────────────────────────────────────────────────────────────

P8_OLD = """\
    "Credentials & Secrets": [
        "SAM Database Hash Dump","LSA Secrets","DPAPI Master Keys",
        "Browser Saved Passwords","Certificate Store",
    ],
}"""

P8_NEW = """\
    "Credentials & Secrets": [
        "SAM Database Hash Dump","LSA Secrets","DPAPI Master Keys",
        "Browser Saved Passwords","Certificate Store",
    ],
    "Removable Media & USB": [
        "USB Device History",
        "USB First/Last Connection Times",
        "Drive Letter Assignments",
        "Volume Serial Numbers",
    ],
}"""


# ─────────────────────────────────────────────────────────────────────────────
# PATCH 9 — Add USB collection logic inside collect_artifact()
#            Inserted before the generic fallback  else:  block.
# ─────────────────────────────────────────────────────────────────────────────

P9_OLD = """\
        # ── GENERIC FALLBACK for any uncaught names ───────────────────
        else:
            results.append({
                "Artifact":  name,
                "Status":    "Not Implemented","""

P9_NEW = """\
        # ── REMOVABLE MEDIA & USB ─────────────────────────────────────

        elif name == "USB Device History":
            if OS == "Windows":
                try:
                    import winreg as _wr
                    usbstor = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
                    with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, usbstor) as root:
                        i = 0
                        while True:
                            try:
                                dev_class = _wr.EnumKey(root, i); i += 1
                                with _wr.OpenKey(root, dev_class) as ckey:
                                    j = 0
                                    while True:
                                        try:
                                            serial = _wr.EnumKey(ckey, j)
                                            j += 1
                                            with _wr.OpenKey(
                                                    ckey, serial) as skey:
                                                def _qv(k):
                                                    try:
                                                        return _wr.QueryValueEx(
                                                            skey, k)[0]
                                                    except Exception:
                                                        return ""
                                                results.append({
                                                    "DeviceClass":  dev_class,
                                                    "SerialNumber": serial,
                                                    "FriendlyName": _qv("FriendlyName"),
                                                    "Manufacturer": _qv("Mfg"),
                                                    "Service":      _qv("Service"),
                                                    "Driver":       _qv("Driver"),
                                                })
                                        except OSError:
                                            break
                            except OSError:
                                break
                except PermissionError:
                    results.append({
                        "Note": "Access denied — run as Administrator for USB registry."})
                except Exception as e:
                    results.append({"Error": str(e), "Source": "USBSTOR Registry"})
            else:
                # Linux — udevadm export-db
                try:
                    import subprocess as _sp
                    r = _sp.run(
                        ["udevadm", "info", "--export-db"],
                        capture_output=True, text=True, timeout=20)
                    for block in r.stdout.split("\n\n"):
                        if "ID_BUS=usb" in block and "ID_TYPE=disk" in block:
                            info = {}
                            for line in block.splitlines():
                                if "E: " in line and "=" in line:
                                    rest = line.partition("E: ")[2]
                                    k, _, v = rest.partition("=")
                                    info[k.strip()] = v.strip()
                            if info:
                                results.append({
                                    "Device":     info.get("DEVNAME", ""),
                                    "Vendor":     info.get("ID_VENDOR", ""),
                                    "Model":      info.get("ID_MODEL", ""),
                                    "Serial":     info.get("ID_SERIAL_SHORT", ""),
                                    "Filesystem": info.get("ID_FS_TYPE", ""),
                                    "Label":      info.get("ID_FS_LABEL", ""),
                                })
                except Exception:
                    pass
                # Also scan dmesg for connect/disconnect messages
                try:
                    import subprocess as _sp
                    dm = _sp.run(
                        ["dmesg"], capture_output=True, text=True, timeout=10)
                    for line in dm.stdout.splitlines():
                        ll = line.lower()
                        if "usb" in ll and any(
                                x in ll for x in
                                ("new usb", "attached", "disconnect",
                                 "product:", "manufacturer:")):
                            results.append({"dmesg": line.strip()})
                except Exception:
                    pass
            if not results:
                results.append({
                    "Note": "No USB records found. Run as Administrator/root."})

        elif name == "USB First/Last Connection Times":
            if OS == "Windows":
                import re as _re
                # ── SetupAPI dev log — records first-install timestamps ──
                setupapi = os.path.join(
                    os.environ.get("SystemRoot", r"C:\Windows"),
                    "INF", "setupapi.dev.log")
                if os.path.isfile(setupapi):
                    try:
                        with open(setupapi, "r",
                                  encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        for m in list(_re.finditer(
                                r">>>.*?USBSTOR.*?<<<.*?start.*?\n.*?time.*?\n",
                                content,
                                _re.DOTALL | _re.IGNORECASE))[:60]:
                            blk   = m.group(0)
                            ts_m  = _re.search(
                                r"start\s+(\d{4}/\d{2}/\d{2}[^\n]+)", blk)
                            dev_m = _re.search(
                                r"USBSTOR\\[^\\]+\\([^\s\]\\]+)", blk)
                            results.append({
                                "FirstConnected": ts_m.group(1).strip()
                                                  if ts_m else "",
                                "DeviceID":       dev_m.group(1).strip()
                                                  if dev_m else "",
                                "Source":         "SetupAPI.dev.log",
                            })
                    except Exception as e:
                        results.append({"Source": "SetupAPI", "Error": str(e)})

                # ── Event Log (DriverFrameworks, ID 2003/2100) ──────────
                try:
                    import subprocess as _sp
                    out = _sp.run(
                        ["wevtutil", "qe",
                         "Microsoft-Windows-DriverFrameworks-UserMode/"
                         "Operational",
                         "/q:*[System[(EventID=2003 or EventID=2100)]]",
                         "/f:text", "/c:200"],
                        capture_output=True, text=True, timeout=25)
                    for line in out.stdout.splitlines():
                        ls = line.strip()
                        if ls:
                            results.append({"EventLog": ls})
                except Exception:
                    pass
            else:
                results.append({
                    "Note": "USB connection-time registry keys are "
                            "Windows-only.  Use 'USB Device History' on "
                            "Linux/macOS."})
            if not results:
                results.append({"Note": "No USB connection-time records found."})

        elif name == "Drive Letter Assignments":
            # Cross-platform: live partition table via psutil
            try:
                for p in psutil.disk_partitions(all=True):
                    try:
                        u = psutil.disk_usage(p.mountpoint)
                        results.append({
                            "Device":     p.device,
                            "Mountpoint": p.mountpoint,
                            "Filesystem": p.fstype,
                            "Options":    p.opts,
                            "Total":      fmt_size(u.total),
                            "Used":       fmt_size(u.used),
                            "Free":       fmt_size(u.free),
                            "UsedPct":    f"{u.percent:.1f}%",
                        })
                    except Exception:
                        results.append({
                            "Device":     p.device,
                            "Mountpoint": p.mountpoint,
                            "Filesystem": p.fstype,
                        })
            except Exception as e:
                results.append({"Error": str(e)})
            # Windows: MountPoints2 (per-user historical volume GUIDs)
            if OS == "Windows":
                try:
                    import winreg as _wr
                    mp2 = (r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                           r"\Explorer\MountPoints2")
                    with _wr.OpenKey(_wr.HKEY_CURRENT_USER, mp2) as key:
                        i = 0
                        while True:
                            try:
                                guid = _wr.EnumKey(key, i); i += 1
                                results.append(
                                    {"MountPoints2_GUID": guid,
                                     "Source": "HKCU MountPoints2"})
                            except OSError:
                                break
                except Exception:
                    pass
            if not results:
                results.append({"Note": "No drive assignment records found."})

        elif name == "Volume Serial Numbers":
            if OS == "Windows":
                try:
                    import winreg as _wr, struct as _st
                    with _wr.OpenKey(
                            _wr.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\MountedDevices") as key:
                        i = 0
                        while True:
                            try:
                                vname, data, _ = _wr.EnumValue(key, i)
                                i += 1
                                if (data and len(data) >= 12
                                        and ("DosDevices" in vname
                                             or "#" in vname)):
                                    try:
                                        vsn = _st.unpack_from(
                                            "<I", data, 8)[0]
                                        results.append({
                                            "MountPoint":   vname,
                                            "VolumeSerial": "%08X" % vsn,
                                            "RawBytes":     len(data),
                                        })
                                    except Exception:
                                        results.append({
                                            "MountPoint": vname,
                                            "RawBytes":   len(data),
                                        })
                            except OSError:
                                break
                except PermissionError:
                    results.append(
                        {"Note": "Access denied — run as Administrator."})
                except Exception as e:
                    results.append({"Error": str(e)})
            else:
                # Linux/macOS — lsblk then blkid fallback
                import subprocess as _sp
                done = False
                for cmd in (
                    ["lsblk", "-o",
                     "NAME,UUID,FSTYPE,LABEL,SIZE,MOUNTPOINT"],
                    ["blkid"],
                ):
                    try:
                        r = _sp.run(
                            cmd, capture_output=True,
                            text=True, timeout=10)
                        if r.returncode == 0:
                            for line in r.stdout.splitlines():
                                if line.strip():
                                    results.append(
                                        {"Output": line.strip(),
                                         "Source": cmd[0]})
                            done = True
                            break
                    except Exception:
                        pass
                if not done:
                    results.append(
                        {"Note": "lsblk/blkid not available on this system."})
            if not results:
                results.append(
                    {"Note": "No volume serial number records found."})

        # ── GENERIC FALLBACK for any uncaught names ───────────────────
        else:
            results.append({
                "Artifact":  name,
                "Status":    "Not Implemented","""


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_tree_thumb_usb.py <forensic_qt.py>")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"Error: not found — {src}")
        sys.exit(1)

    bak = src + ".bak_ttu"
    shutil.copy2(src, bak)
    print(f"Backup : {bak}\n")

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    print("Applying patches …")
    code = patch(code, P1_OLD, P1_NEW,
                 "1 — Remove files from host-filesystem tree")
    code = patch(code, P2_OLD, P2_NEW,
                 "2 — Remove files from forensic-image tree")
    code = patch(code, P3_OLD, P3_NEW,
                 "3 — Add QListView to PyQt6 imports")
    code = patch(code, P4_OLD, P4_NEW,
                 "4 — Add ☰/⊞ toggle buttons to path bar")
    code = patch(code, P5_OLD, P5_NEW,
                 "5 — Add thumb_list + QStackedWidget to _setup()")
    code = patch(code, P6_OLD, P6_NEW,
                 "6 — Inject thumbnail-view methods")
    code = patch(code, P7_OLD, P7_NEW,
                 "7 — _load_dir(): refresh thumbnails when active")
    code = patch(code, P8_OLD, P8_NEW,
                 "8 — Add 'Removable Media & USB' to ARTIFACT_CATEGORIES")
    code = patch(code, P9_OLD, P9_NEW,
                 "9 — USB collection logic in collect_artifact()")

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(code)

    print(f"\nDone — patched: {src}")
    print(f"Restore with:   {bak}\n")
    print("Summary")
    print("  Tree left panel  : folders only (files removed from both host and image trees)")
    print("  File list        : ☰ List  |  ⊞ Thumbs  toggle added to path bar")
    print("    Thumbnail grid : real image previews (112×112) + colour tiles for other types")
    print("    Double-click   : navigate dirs, open files in content viewer")
    print("    Right-click    : Open / Save As / Add to Bookmark")
    print("  New USB artifacts: USB Device History, USB First/Last Connection Times,")
    print("                     Drive Letter Assignments, Volume Serial Numbers")
    print("                     (Windows: registry + SetupAPI + event log;")
    print("                      Linux: udevadm + dmesg + lsblk/blkid)")


if __name__ == "__main__":
    main()