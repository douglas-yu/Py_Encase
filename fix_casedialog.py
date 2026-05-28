
#!/usr/bin/env python3
"""
fix_casedialog.py
=================
Fixes the crash on File → New Case:

    NameError: name 'CaseDialog' is not defined

Root cause
----------
CaseDialog is called in MainWindow._new_case() but was never defined anywhere
in the file.  This patcher injects the full class definition immediately before
'class MainWindow'.

The dialog exposes:
  • Four fields matching self.case_info:
      name, number, examiner, notes
  • .values() → dict  (consumed by _new_case)
  • Pre-populates from parent.case_info when parent is a MainWindow so that
    "Edit Case Info…" reuse is also supported in the future.

Usage
-----
    python fix_casedialog.py path/to/forensic_qt.py
"""

import sys, os, shutil

# ── The class to inject ───────────────────────────────────────────────────────

CASE_DIALOG_CODE = '''
# ══════════════════════════════════════════════════════════════
#  CASE DIALOG  (New Case / Edit Case Info)
# ══════════════════════════════════════════════════════════════
class CaseDialog(QDialog):
    """Dialog for creating or editing a forensic case.

    Exposes .values() -> dict with keys:
        name, number, examiner, notes
    matching the structure of MainWindow.case_info.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Case Information")
        self.setFixedSize(480, 320)
        self.setStyleSheet(STYLESHEET)
        self._build(parent)

    def _build(self, parent):
        # Pre-populate from parent.case_info if available
        existing = {}
        if hasattr(parent, "case_info") and isinstance(parent.case_info, dict):
            existing = parent.case_info

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        # ── Title bar ──────────────────────────────────────────
        title = QLabel("  NEW CASE")
        title.setStyleSheet(
            f"color:{C['accent']};font-weight:bold;font-size:11pt;"
            f"background:{C['bg3']};padding:6px 10px;"
            f"border-bottom:1px solid {C['border']};")
        lay.addWidget(title)

        # ── Form ───────────────────────────────────────────────
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(8)

        def _le(default=""):
            w = QLineEdit(default)
            w.setStyleSheet(
                f"background:{C['bg2']};color:{C['fg']};"
                f"border:1px solid {C['border']};border-radius:3px;padding:4px 6px;")
            return w

        self._f_name     = _le(existing.get("name",     "New Case"))
        self._f_number   = _le(existing.get("number",   "FC-2025-001"))
        self._f_examiner = _le(existing.get("examiner", ""))

        self._f_notes = QPlainTextEdit(existing.get("notes", ""))
        self._f_notes.setFixedHeight(70)
        self._f_notes.setStyleSheet(
            f"background:{C['bg2']};color:{C['fg']};"
            f"border:1px solid {C['border']};border-radius:3px;padding:4px 6px;")
        self._f_notes.setPlaceholderText("Optional case notes…")

        lbl_style = f"color:{C['fg2']};font-size:9pt;"
        for label, widget in [
            ("Case Name:",   self._f_name),
            ("Case Number:", self._f_number),
            ("Examiner:",    self._f_examiner),
            ("Notes:",       self._f_notes),
        ]:
            lbl = QLabel(label)
            lbl.setStyleSheet(lbl_style)
            form.addRow(lbl, widget)

        lay.addLayout(form)
        lay.addStretch()

        # ── Buttons ────────────────────────────────────────────
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Create Case")
        btns.button(QDialogButtonBox.StandardButton.Ok).setStyleSheet(
            f"background:{C['accent']};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:5px 18px;")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setStyleSheet(
            f"background:{C['btn']};color:{C['fg']};"
            f"border:1px solid {C['border']};border-radius:4px;padding:5px 18px;")
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def _on_accept(self):
        if not self._f_name.text().strip():
            QMessageBox.warning(self, "Required", "Case Name cannot be empty.")
            return
        self.accept()

    def values(self) -> dict:
        """Return the filled-in case info dict."""
        return {
            "name":     self._f_name.text().strip()     or "New Case",
            "number":   self._f_number.text().strip()   or "FC-001",
            "examiner": self._f_examiner.text().strip(),
            "notes":    self._f_notes.toPlainText().strip(),
        }

'''

# ── Insertion anchor — inject immediately before 'class MainWindow' ───────────

ANCHOR = "class MainWindow(QMainWindow):"

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_casedialog.py <forensic_qt.py>")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"Error: file not found — {src}")
        sys.exit(1)

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    # Guard: don't inject twice
    if "class CaseDialog" in code:
        print("CaseDialog already defined in the file — nothing to do.")
        sys.exit(0)

    if ANCHOR not in code:
        print(f"Error: anchor not found — '{ANCHOR}'")
        print("       Cannot determine safe insertion point.")
        sys.exit(1)

    bak = src + ".bak_casedlg"
    shutil.copy2(src, bak)
    print(f"Backup: {bak}")

    # Insert CaseDialog right before the first occurrence of 'class MainWindow'
    patched = code.replace(ANCHOR, CASE_DIALOG_CODE + ANCHOR, 1)

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(patched)

    print(f"Injected CaseDialog class before 'class MainWindow'.")
    print(f"Patched : {src}")
    print()
    print("Fields exposed by CaseDialog.values():")
    print("  name, number, examiner, notes")
    print("  — matches the MainWindow.case_info dict structure exactly.")


if __name__ == "__main__":
    main()
