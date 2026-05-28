
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_hash_image_file.py
======================
Replaces the broken _hash_image_file method (which contains unterminated
string literals from a previous patcher) with a correct version that uses
chr(10) for newlines — zero backslash-n in any string literal.

Usage: python fix_hash_image_file.py  path/to/forensic_qt.py
"""

import sys, os, shutil, re

NEW_METHOD = "\n".join([
    "    def _hash_image_file(self, image_path, inode, name):",
    "        # Compute MD5 + SHA-256 for a file inside a forensic image.",
    "        # chr(10) used for newlines to avoid backslash-n in string literals.",
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
    "",
])

PAT = (
    r"    def _hash_image_file\(self, image_path, inode, name\):"
    r".*?(?=    def _make_thumb_icon\(self,)"
)

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_hash_image_file.py <forensic_qt.py>")
        sys.exit(1)
    src = sys.argv[1]
    if not os.path.isfile(src):
        print("Error: not found - " + src)
        sys.exit(1)

    bak = src + ".bak_hif"
    shutil.copy2(src, bak)
    print("Backup : " + bak)

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    if "def _hash_image_file" not in code:
        print("ERROR: _hash_image_file not found in file.")
        sys.exit(1)

    new_code, n = re.subn(
        PAT, lambda m: NEW_METHOD, code, count=1, flags=re.DOTALL)

    if n == 0:
        print("ERROR: regex did not match — pattern may need adjustment.")
        print("       Trying fallback: searching for the broken string literal...")
        # Fallback: find the method start and next method start manually
        start = code.find("    def _hash_image_file(self, image_path, inode, name):")
        end   = code.find("    def _make_thumb_icon(self,", start)
        if start == -1 or end == -1:
            print("ERROR: fallback also failed. Please paste 5 lines around")
            print("       line 4260 of your file so I can adjust the pattern.")
            sys.exit(1)
        new_code = code[:start] + NEW_METHOD + code[end:]
        print("  [OK]   _hash_image_file replaced (fallback method)")
    else:
        print("  [OK]   _hash_image_file replaced (regex method)")

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(new_code)

    print("Done  : " + src)
    print("Restore: " + bak)


if __name__ == "__main__":
    main()
