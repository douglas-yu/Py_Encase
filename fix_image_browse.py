
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_image_browse.py  v4
=======================
Regex-based method replacement. Works regardless of prior patch state.
ALL injected code is built with "\n".join([...]) line lists —
zero triple-quoted blocks, zero backslash-escape issues in output.

Fixes:
  1. Go-to-parent button inside forensic image directories
  2. Thumbnail view for forensic image folders (real pixel thumbnails)
  3. Hash computation for files inside forensic images

Run after fix_tree_thumbs.py and fix_current_dir.py.
Usage: python fix_image_browse.py  path/to/forensic_qt.py
"""

import sys, os, shutil, re


# =============================================================================
# Helpers
# =============================================================================

def re_replace(code, pattern, new_text, tag, flags=re.DOTALL):
    new_code, n = re.subn(
        pattern, lambda m: new_text, code, count=1, flags=flags)
    print(("  [OK]   " if n else "  [SKIP] ") + tag)
    return new_code

def str_try(code, candidates, new_text, tag):
    for old in candidates:
        if old in code:
            print("  [OK]   " + tag)
            return code.replace(old, new_text, 1)
    print("  [SKIP] " + tag)
    return code


# =============================================================================
# A  _load_image_dir — push old location to nav stack
# =============================================================================

LID_OLD_A = (
    "        self._in_image_mode = True    # forensic-image navigation\n"
    "        self._img_context = {\"image_path\": image_path, \"inode\": inode}\n"
    "        ifs = ForensicImageFS.get(image_path)"
)
LID_OLD_B = (
    "        # Store context so double-click / select knows we're in image mode\n"
    "        self._img_context = {\"image_path\": image_path, \"inode\": inode}\n"
    "        ifs = ForensicImageFS.get(image_path)"
)
LID_NEW = "\n".join([
    "        # Nav stack: push previous location before descending",
    "        if not hasattr(self, '_img_nav_stack'):",
    "            self._img_nav_stack = []",
    "        if (getattr(self, '_in_image_mode', False)",
    "                and getattr(self, '_img_nav_push', True)):",
    "            _prev = getattr(self, '_img_context', {})",
    "            if _prev:",
    "                self._img_nav_stack.append((",
    "                    _prev['image_path'],",
    "                    _prev['inode'],",
    "                    getattr(self, '_img_context_name', '')))",
    "        elif not getattr(self, '_in_image_mode', False):",
    "            self._img_nav_stack = []   # fresh entry into image mode",
    "        self._img_nav_push     = True",
    "        self._in_image_mode    = True   # forensic-image navigation",
    "        self._img_context      = {\"image_path\": image_path, \"inode\": inode}",
    "        self._img_context_name = name",
    "        ifs = ForensicImageFS.get(image_path)",
])


# =============================================================================
# B  _go_up — pop nav stack + refresh thumbnails
# =============================================================================

PAT_GO_UP = r"    def _go_up\(self\):.*?(?=    def _go_path\(self\):)"

NEW_GO_UP = "\n".join([
    "    def _go_up(self):",
    "        if getattr(self, '_in_image_mode', False):",
    "            stack = getattr(self, '_img_nav_stack', [])",
    "            if stack:",
    "                img_path, inode, iname = stack[-1]",
    "                self._img_nav_stack = stack[:-1]",
    "                self._img_nav_push  = False",
    "                self._load_image_dir(img_path, inode, iname)",
    "                if getattr(self, '_view_mode', 'list') == 'thumb':",
    "                    self._load_img_thumbnails()",
    "            return",
    "        self._load_dir(self.current_dir.parent)",
    "",
    "",
])


# =============================================================================
# C  _switch_file_view — route image mode to _load_img_thumbnails
# =============================================================================

PAT_SWITCH = (
    r"    def _switch_file_view\(self, mode\):"
    r".*?(?=    def _load_dir_thumbnails\()"
)

NEW_SWITCH = "\n".join([
    "    def _switch_file_view(self, mode):",
    "        # Switch between list (table) and thumb (grid) views.",
    "        self._view_mode = mode",
    "        if mode == 'thumb':",
    "            self._btn_list.setChecked(False)",
    "            self._btn_thumb.setChecked(True)",
    "            self._view_stack.setCurrentIndex(1)",
    "            if getattr(self, '_in_image_mode', False):",
    "                self._load_img_thumbnails()",
    "            else:",
    "                self._load_dir_thumbnails(self.current_dir)",
    "        else:",
    "            self._btn_list.setChecked(True)",
    "            self._btn_thumb.setChecked(False)",
    "            self._view_stack.setCurrentIndex(0)",
    "",
    "",
])


# =============================================================================
# D  Inject _load_img_thumbnails + _hash_image_file before _make_thumb_icon
#    Key: _hash_image_file uses  _nl = chr(10)  so NO \n appears in any
#    string literal — that is what caused every previous SyntaxError.
# =============================================================================

D_ANCHOR = (
    "    def _make_thumb_icon(self, bg_color, label=\"\"):\n"
    "        # Return a solid-colour QIcon with optional centred text label."
)

NEW_IMG_METHODS = "\n".join([
    "    def _load_img_thumbnails(self):",
    "        # Fill thumbnail grid from current forensic image directory.",
    "        self._thumb_stop[0] = True",
    "        self._thumb_stop = [False]",
    "        self.thumb_list.clear()",
    "        ctx = getattr(self, '_img_context', {})",
    "        if not ctx:",
    "            return",
    "        image_path = ctx['image_path']",
    "        inode      = ctx['inode']",
    "        IMG_EXTS   = {'.jpg', '.jpeg', '.png', '.gif',",
    "                      '.bmp', '.tiff', '.tif', '.webp', '.ico'}",
    "        try:",
    "            ifs     = ForensicImageFS.get(image_path)",
    "            entries = ifs.list_dir(inode=inode) if (ifs and ifs.fs) else []",
    "        except Exception:",
    "            entries = []",
    "        up = QListWidgetItem('\u2b06  ..')",
    "        up.setData(Qt.ItemDataRole.UserRole,     None)",
    "        up.setData(Qt.ItemDataRole.UserRole + 1, 'img_up')",
    "        up.setToolTip('Go to parent directory')",
    "        up.setIcon(self._make_thumb_icon(C['bg3'], 'UP'))",
    "        self.thumb_list.addItem(up)",
    "        img_n = 0",
    "        stop  = self._thumb_stop",
    "        for e in entries:",
    "            if stop[0]:",
    "                break",
    "            raw   = e['name']",
    "            label = (raw[:20] + '\u2026') if len(raw) > 20 else raw",
    "            item  = QListWidgetItem(label)",
    "            item.setToolTip(raw)",
    "            item.setData(Qt.ItemDataRole.UserRole, {",
    "                'is_img':     True,",
    "                'image_path': image_path,",
    "                'inode':      e['inode'],",
    "                'is_dir':     e['is_dir'],",
    "                'name':       e['name'],",
    "                'size':       e.get('size', 0),",
    "            })",
    "            item.setData(Qt.ItemDataRole.UserRole + 1,",
    "                         'img_dir' if e['is_dir'] else 'img_file')",
    "            if e['is_dir']:",
    "                item.setIcon(self._make_thumb_icon(C['orange'], 'DIR'))",
    "            else:",
    "                ext = Path(e['name']).suffix.lower()",
    "                if ext in IMG_EXTS:",
    "                    try:",
    "                        ifs2 = ForensicImageFS.get(image_path)",
    "                        data = ifs2.read_file(e['inode'],",
    "                                              max_bytes=4 * 1024 * 1024)",
    "                        pix = QPixmap()",
    "                        if pix.loadFromData(data) and not pix.isNull():",
    "                            pix = pix.scaled(",
    "                                112, 112,",
    "                                Qt.AspectRatioMode.KeepAspectRatio,",
    "                                Qt.TransformationMode.SmoothTransformation)",
    "                            item.setIcon(QIcon(pix))",
    "                        else:",
    "                            item.setIcon(",
    "                                self._make_thumb_icon(C['bg3'], 'IMG'))",
    "                    except Exception:",
    "                        item.setIcon(self._make_thumb_icon(C['bg3'], 'IMG'))",
    "                    img_n += 1",
    "                    if img_n % 6 == 0:",
    "                        QApplication.processEvents()",
    "                else:",
    "                    abbr = Path(e['name']).suffix.upper().lstrip('.')[:4] or 'FILE'",
    "                    item.setIcon(self._make_thumb_icon(C['bg2'], abbr))",
    "            self.thumb_list.addItem(item)",
    "",
    "    def _hash_image_file(self, image_path, inode, name):",
    "        # Compute MD5 + SHA-256 for a file inside a forensic image.",
    "        # Use chr(10) for newlines — avoids \\n in string literals.",
    "        _nl = chr(10)",
    "        dlg = QMessageBox(self)",
    "        dlg.setWindowTitle('Computing hashes...')",
    "        dlg.setText('Computing MD5 & SHA-256 for:' + _nl + name +",
    "                    _nl + 'Reading from image, please wait...')",
    "        dlg.setStandardButtons(QMessageBox.StandardButton.NoButton)",
    "        dlg.show()",
    "        QApplication.processEvents()",
    "        try:",
    "            ifs  = ForensicImageFS.get(image_path)",
    "            data = ifs.read_file(inode, max_bytes=512 * 1024 * 1024)",
    "            import hashlib as _hl",
    "            md5 = _hl.md5(data).hexdigest()",
    "            sha = _hl.sha256(data).hexdigest()",
    "        except Exception as ex:",
    "            dlg.hide()",
    "            QMessageBox.critical(self, 'Hash Error', str(ex))",
    "            return",
    "        dlg.hide()",
    "        QMessageBox.information(",
    "            self, 'Hash Result',",
    "            'File: ' + name + _nl +",
    "            'Size: ' + fmt_size(len(data)) + _nl + _nl +",
    "            'MD5:' + _nl + md5 + _nl + _nl +",
    "            'SHA-256:' + _nl + sha)",
    "",
    "    def _make_thumb_icon(self, bg_color, label=''):",
    "        # Return a solid-colour QIcon with optional centred text label.",
]) + "\n"


# =============================================================================
# E  _on_thumb_double — handle img_up / img_dir / img_file / host entries
# =============================================================================

PAT_DBL = (
    r"    def _on_thumb_double\(self, _index\):"
    r".*?(?=    def _thumb_ctx\(self, pos\):)"
)

NEW_DBL = "\n".join([
    "    def _on_thumb_double(self, _index):",
    "        # Navigate / open on double-click — host-fs and forensic image mode.",
    "        item = self.thumb_list.currentItem()",
    "        if not item:",
    "            return",
    "        p    = item.data(Qt.ItemDataRole.UserRole)",
    "        kind = item.data(Qt.ItemDataRole.UserRole + 1)",
    "        if kind == 'img_up':",
    "            self._go_up()",
    "            return",
    "        if kind == 'img_dir' and isinstance(p, dict):",
    "            self._load_image_dir(p['image_path'], p['inode'], p['name'])",
    "            self._load_img_thumbnails()",
    "            return",
    "        if kind == 'img_file' and isinstance(p, dict):",
    "            self._load_image_file(p['image_path'], p['inode'], p['name'])",
    "            return",
    "        if not isinstance(p, str):",
    "            return",
    "        entry = Path(p)",
    "        if kind == 'dir' or entry.is_dir():",
    "            self._load_dir(entry)",
    "        elif entry.is_file():",
    "            self.content.load_path(str(entry))",
    "",
    "",
])


# =============================================================================
# F  _thumb_ctx — full right-click menu for image and host entries
# =============================================================================

PAT_CTX = (
    r"    def _thumb_ctx\(self, pos\):"
    r".*?(?=    def _file_icon\(self, name\):)"
)

NEW_CTX = "\n".join([
    "    def _thumb_ctx(self, pos):",
    "        # Right-click menu — host-fs and forensic image mode.",
    "        item = self.thumb_list.itemAt(pos)",
    "        if not item:",
    "            return",
    "        p    = item.data(Qt.ItemDataRole.UserRole)",
    "        kind = item.data(Qt.ItemDataRole.UserRole + 1)",
    "        menu = QMenu(self)",
    "        # Forensic image entries",
    "        if kind in ('img_up', 'img_dir', 'img_file'):",
    "            if kind == 'img_up':",
    "                menu.addAction('Go Up', self._go_up)",
    "                menu.exec(self.thumb_list.viewport().mapToGlobal(pos))",
    "                return",
    "            d = p if isinstance(p, dict) else {}",
    "            if kind == 'img_dir':",
    "                def _open_img(dd=d):",
    "                    self._load_image_dir(dd['image_path'],",
    "                                         dd['inode'], dd['name'])",
    "                    self._load_img_thumbnails()",
    "                menu.addAction('Open', _open_img)",
    "            else:",
    "                menu.addAction('Open',",
    "                    lambda dd=d: self._load_image_file(",
    "                        dd['image_path'], dd['inode'], dd['name']))",
    "                menu.addSeparator()",
    "                menu.addAction('Save As\u2026',",
    "                    lambda dd=d: self._save_image_file_as(",
    "                        dd['image_path'], dd['inode'], dd['name']))",
    "                menu.addAction('Compute Hashes\u2026',",
    "                    lambda dd=d: self._hash_image_file(",
    "                        dd['image_path'], dd['inode'], dd['name']))",
    "            menu.addSeparator()",
    "            bm_sub = menu.addMenu('Add to Bookmark\u2026')",
    "            _bm = {",
    "                'Name':  d.get('name', item.toolTip()),",
    "                'Image': d.get('image_path', ''),",
    "                'Inode': str(d.get('inode', '')),",
    "                'Size':  fmt_size(d.get('size', 0)),",
    "            }",
    "            for _t in ['Key Finding', 'File of Interest',",
    "                        'Malware Indicator', 'Suspicious', 'IOC']:",
    "                bm_sub.addAction(_t,",
    "                    lambda t=_t, bm=_bm: self.main._on_bookmark(",
    "                        'Image Browser', dict(bm), t))",
    "            menu.exec(self.thumb_list.viewport().mapToGlobal(pos))",
    "            return",
    "        # Host-fs entries",
    "        if not isinstance(p, str):",
    "            return",
    "        entry  = Path(p)",
    "        is_dir = (kind == 'dir' or entry.is_dir())",
    "        menu.addAction('Open',",
    "            lambda: self._load_dir(entry) if is_dir",
    "                    else self.content.load_path(str(entry)))",
    "        if entry.is_file():",
    "            menu.addSeparator()",
    "            menu.addAction('Save As\u2026',",
    "                lambda: self._save_host_file_as(entry))",
    "            menu.addAction('Compute Hashes\u2026',",
    "                lambda: self._hash_file(entry))",
    "        menu.addSeparator()",
    "        bm_sub = menu.addMenu('Add to Bookmark\u2026')",
    "        try:",
    "            _sz = fmt_size(entry.stat().st_size) if entry.is_file() else ''",
    "        except Exception:",
    "            _sz = ''",
    "        _bm = {",
    "            'Name': item.toolTip(),",
    "            'Path': str(entry),",
    "            'Type': 'Directory' if is_dir else detect_type(str(entry)),",
    "            'Size': _sz,",
    "        }",
    "        for _t in ['Key Finding', 'File of Interest',",
    "                    'Malware Indicator', 'Suspicious', 'IOC']:",
    "            bm_sub.addAction(_t,",
    "                lambda t=_t, d=_bm: self.main._on_bookmark(",
    "                    'File Browser', dict(d), t))",
    "        menu.exec(self.thumb_list.viewport().mapToGlobal(pos))",
    "",
    "",
])


# =============================================================================
# Main
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_image_browse.py <forensic_qt.py>")
        sys.exit(1)
    src = sys.argv[1]
    if not os.path.isfile(src):
        print("Error: not found - " + src)
        sys.exit(1)

    bak = src + ".bak_ib4"
    shutil.copy2(src, bak)
    print("Backup : " + bak + "\n")

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    print("Applying patches...")

    if "_img_nav_stack" in code:
        print("  [SKIP] A - nav stack already present")
    else:
        code = str_try(code, [LID_OLD_A, LID_OLD_B], LID_NEW,
                       "A - _load_image_dir: nav stack + _img_context_name")

    code = re_replace(code, PAT_GO_UP, NEW_GO_UP,
                      "B - _go_up: pop nav stack, refresh thumbnails")

    if "def _switch_file_view" not in code:
        print("  [SKIP] C - _switch_file_view (run fix_tree_thumbs.py first)")
    else:
        code = re_replace(code, PAT_SWITCH, NEW_SWITCH,
                          "C - _switch_file_view: image mode -> _load_img_thumbnails")

    if "def _load_img_thumbnails" in code:
        print("  [SKIP] D - _load_img_thumbnails already present")
    elif D_ANCHOR not in code:
        print("  [SKIP] D - anchor not found (run fix_tree_thumbs.py first)")
    else:
        code = code.replace(D_ANCHOR, NEW_IMG_METHODS, 1)
        print("  [OK]   D - injected _load_img_thumbnails + _hash_image_file")

    if "def _on_thumb_double" not in code:
        print("  [SKIP] E - _on_thumb_double (run fix_tree_thumbs.py first)")
    else:
        code = re_replace(code, PAT_DBL, NEW_DBL,
                          "E - _on_thumb_double: img_up/img_dir/img_file/host")

    if "def _thumb_ctx" not in code:
        print("  [SKIP] F - _thumb_ctx (run fix_tree_thumbs.py first)")
    else:
        code = re_replace(code, PAT_CTX, NEW_CTX,
                          "F - _thumb_ctx: image + host-fs right-click menu")

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(code)

    print("\nDone  : " + src)
    print("Restore: " + bak)
    print("\nIf C/E/F show [SKIP], run fix_tree_thumbs.py first, then re-run.")


if __name__ == "__main__":
    main()
