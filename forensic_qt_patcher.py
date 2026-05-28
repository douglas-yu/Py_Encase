
#!/usr/bin/env python3
"""
forensic_qt_patcher.py
=======================
Applies targeted bug fixes to forensic_qt.py (keeps everything else intact).

  Fix 1  – "Add to Bookmark" KeyError crash in the Image Browser right-click menu.
  Fix 2a – Bonus: NameError on 'zpath' in the generated AGENT_TEMPLATE main().
  Fix 2b – Adds an "Agent Format" combo box to AgentTab (Python / Shell / Batch /
            PowerShell / Windows EXE via PyInstaller).
  Fix 2c – Replaces _save() with a format-aware version.
  Fix 2d – Adds _make_sh_wrapper(), _make_bat_wrapper(), _make_ps1_wrapper(),
            and _compile_exe() methods to AgentTab.

Usage
-----
    python forensic_qt_patcher.py path/to/forensic_qt.py

A backup (forensic_qt.py.bak) is created before any changes are written.
"""

import sys, os, shutil

# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def apply(code: str, old: str, new: str, tag: str) -> str:
    if old not in code:
        print(f"  [SKIP] Target not found — {tag}")
        print(        "         (patch may already be applied, or source differs)")
        return code
    print(f"  [OK]   {tag}")
    return code.replace(old, new, 1)


# ─────────────────────────────────────────────────────────────────────────────
# FIX 1 — Image-browser "Add to Bookmark" KeyError crash
# Root cause: lambda uses dd["name"] / dd["image_path"] / dd["inode"] — direct
# key access on item_data.  If any key is absent the app crashes at click-time.
# Fix: pre-compute a .get()-safe snapshot (_bm2) before building the lambdas,
#      identical to what the host-file branch already does.
# ─────────────────────────────────────────────────────────────────────────────

FIX1_OLD = """\
                bm_sub2 = menu.addMenu("Add to Bookmark\u2026")
                for tag in ["Key Finding","File of Interest","Malware Indicator",
                            "Suspicious","IOC"]:
                    bm_sub2.addAction(tag,
                        lambda _, t=tag, dd=d: self.main._on_bookmark(
                            "Image Browser",
                            {"Name": dd["name"], "Image": dd["image_path"],
                             "Inode": str(dd["inode"]),
                             "Size": fmt_size(dd.get("size",0))}, t))"""

FIX1_NEW = """\
                bm_sub2 = menu.addMenu("Add to Bookmark\u2026")
                # Pre-compute a safe snapshot before building lambdas — same
                # pattern the host-file branch already uses — prevents KeyError
                # / crash when any field is absent in item_data.
                _bm2 = {
                    "name":       d.get("name", ""),
                    "image_path": d.get("image_path", ""),
                    "inode":      str(d.get("inode", "")),
                    "size":       d.get("size", 0),
                }
                for tag in ["Key Finding","File of Interest","Malware Indicator",
                            "Suspicious","IOC"]:
                    bm_sub2.addAction(tag,
                        lambda _, t=tag, dd=_bm2: self.main._on_bookmark(
                            "Image Browser",
                            {"Name":  dd["name"],
                             "Image": dd["image_path"],
                             "Inode": dd["inode"],
                             "Size":  fmt_size(dd["size"])}, t))"""


# ─────────────────────────────────────────────────────────────────────────────
# FIX 2a — AGENT_TEMPLATE: undefined 'zpath' NameError in main()
# The generated agent crashes at the final print because zpath is a local
# variable inside save_results(), never returned to main().
# ─────────────────────────────────────────────────────────────────────────────

FIX2A_OLD = """\
    out = save_results(data)
    if out:
        print(f"[+] Saved: {{out}}")
    print(f"[+] Archive: {{zpath}}")"""

FIX2A_NEW = """\
    out = save_results(data)
    if out:
        print(f"[+] Output: {{out}}")"""


# ─────────────────────────────────────────────────────────────────────────────
# FIX 2b — Add "Agent Format" combo box to AgentTab._setup()
# ─────────────────────────────────────────────────────────────────────────────

FIX2B_OLD = """\
        section("AGENT OPTIONS")
        cl.addWidget(QLabel("Artifact Preset"))
        self.f_preset = QComboBox()
        self.f_preset.addItems([
            "Use Current Selection", "Quick Triage",
            "Full Collection", "Incident Response", "Malware Hunt"])
        cl.addWidget(self.f_preset)"""

FIX2B_NEW = """\
        section("AGENT OPTIONS")
        cl.addWidget(QLabel("Artifact Preset"))
        self.f_preset = QComboBox()
        self.f_preset.addItems([
            "Use Current Selection", "Quick Triage",
            "Full Collection", "Incident Response", "Malware Hunt"])
        cl.addWidget(self.f_preset)

        cl.addWidget(QLabel("Agent Format"))
        self.f_format = QComboBox()
        self.f_format.addItems([
            "\U0001f40d  Python Script  (.py)   \u2014 universal",
            "\U0001f4dc  Shell Script   (.sh)   \u2014 Linux / macOS",
            "\U0001f4dc  Batch Script   (.bat)  \u2014 Windows",
            "\U0001f4dc  PowerShell     (.ps1)  \u2014 Windows",
            "\u26a1  Windows EXE    (.exe)  \u2014 via PyInstaller",
        ])
        cl.addWidget(self.f_format)"""


# ─────────────────────────────────────────────────────────────────────────────
# FIX 2c/2d — Replace _save() with format-aware version + add helper methods
# ─────────────────────────────────────────────────────────────────────────────

FIX2C_OLD = """\
    def _save(self):
        if not self._code:
            QMessageBox.warning(self,"Generate First","Generate the agent code first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,"Save Agent","forensic_agent.py",
            "Python (*.py);;Shell (*.sh);;All (*)")
        if path:
            with open(path,"w") as f:
                f.write(self._code)
            try:
                shutil.copy(path, "/mnt/user-data/outputs/" + os.path.basename(path))
            except Exception:
                pass
            QMessageBox.information(self,"Saved","Agent saved:\\n" + path)"""

FIX2C_NEW = '''\
    def _save(self):
        """Save the generated agent in the format chosen by the Agent Format combo."""
        if not self._code:
            QMessageBox.warning(self, "Generate First",
                "Generate the agent code first.")
            return
        fmt = getattr(self, "f_format", None)
        fmt_idx = fmt.currentIndex() if fmt else 0   # default: Python
        cid = (self.f_case_id.text() or "FC001").replace(" ", "_")
        ver = APP_VERSION
        _meta = {
            0: ("forensic_agent_%s.py"  % cid, "Python Script (*.py);;All (*)"),
            1: ("forensic_agent_%s.sh"  % cid, "Shell Script (*.sh);;All (*)"),
            2: ("forensic_agent_%s.bat" % cid, "Batch Script (*.bat);;All (*)"),
            3: ("forensic_agent_%s.ps1" % cid, "PowerShell (*.ps1);;All (*)"),
            4: ("forensic_agent_%s.exe" % cid, "Windows EXE (*.exe);;All (*)"),
        }
        default_name, filt = _meta.get(fmt_idx, _meta[0])
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Agent", default_name, filt)
        if not path:
            return
        try:
            if fmt_idx == 0:
                content = self._code
            elif fmt_idx == 1:
                content = self._make_sh_wrapper(self._code, cid, ver)
            elif fmt_idx == 2:
                content = self._make_bat_wrapper(self._code, cid, ver)
            elif fmt_idx == 3:
                content = self._make_ps1_wrapper(self._code, cid, ver)
            elif fmt_idx == 4:
                self._compile_exe(path, cid)
                return   # _compile_exe shows its own dialog
            # Write text content (use newline="" to preserve \\r\\n in BAT wrappers)
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(content)
            try:
                shutil.copy(path,
                    "/mnt/user-data/outputs/" + os.path.basename(path))
            except Exception:
                pass
            QMessageBox.information(self, "Saved", "Agent saved:\\n" + path)
        except Exception as ex:
            QMessageBox.critical(self, "Save Error", str(ex))

    # ── Agent format wrapper / compile helpers ────────────────────────────────

    def _make_sh_wrapper(self, python_code, case_id, version):
        """
        Embed the Python source in a self-executing shell script via heredoc.
        The heredoc delimiter uses a unique case-based string to avoid conflicts.
        Deploy on Linux/macOS as root:  sh <script>
        """
        delim = "FORENSICPRO_%s_HEREDOC_END" % case_id.replace("-", "_").upper()
        return (
            "#!/bin/sh\\n"
            "# ForensicPro Remote Agent Launcher  [Shell Script]\\n"
            "# Generated by ForensicPro v%s  |  Case: %s\\n"
            "# Deploy on Linux / macOS target (run as root):\\n"
            "#   chmod +x <script> && ./<script>\\n"
            "_TMP=$(mktemp /tmp/fpa_XXXX.py 2>/dev/null"
            " || echo /tmp/fpa_%s_$$.py)\\n"
            "cat > \\"$_TMP\\" <<\'%s\'\\n"
            "%s\\n"
            "%s\\n"
            "python3 \\"$_TMP\\" \\"$@\\"\\n"
            "_rc=$?; rm -f \\"$_TMP\\"; exit $_rc\\n"
        ) % (version, case_id, case_id, delim, python_code, delim)

    def _make_bat_wrapper(self, python_code, case_id, version):
        """
        Embed base64-encoded Python in a Windows Batch launcher.
        Uses PowerShell (available on Win 7+) to decode and write the .py file.
        Deploy on Windows (run as Administrator):  cmd /c <script>
        """
        import base64 as _b64
        b64 = _b64.b64encode(python_code.encode("utf-8")).decode("ascii")
        # Split into 70-char lines; base64 chars are all alphanumeric / + / = so
        # no BAT special-character escaping is needed
        chunks = [b64[i:i+70] for i in range(0, len(b64), 70)]
        # First chunk uses > (create), subsequent use >> (append)
        echo_lines = "\\r\\n".join(
            ("echo %s> \\"%%_B%%\\"" % c if i == 0
             else "echo %s>> \\"%%_B%%\\"" % c)
            for i, c in enumerate(chunks)
        )
        return (
            "@echo off\\r\\n"
            ":: ForensicPro Remote Agent Launcher  [Batch Script]\\r\\n"
            ":: Generated by ForensicPro v%s  |  Case: %s\\r\\n"
            ":: Deploy on Windows target (run as Administrator):\\r\\n"
            "::   cmd /c %s.bat\\r\\n"
            "setlocal\\r\\n"
            "set \\"_B=%%TEMP%%\\\\fpa_%s.b64\\"\\r\\n"
            "set \\"_P=%%TEMP%%\\\\fpa_%s.py\\"\\r\\n"
            "%s\\r\\n"
            "powershell -NoProfile -Command \\"$b=[IO.File]::"
            "ReadAllText(\'%%_B%%\') -replace \'\\\\s\';"
            "[IO.File]::WriteAllBytes(\'%%_P%%\',[Convert]::"
            "FromBase64String($b))\\"\\r\\n"
            "del \\"%%_B%%\\" 2>nul\\r\\n"
            "python \\"%%_P%%\\"\\r\\n"
            "del \\"%%_P%%\\" 2>nul\\r\\n"
            "endlocal\\r\\n"
        ) % (version, case_id, case_id, case_id, case_id, echo_lines)

    def _make_ps1_wrapper(self, python_code, case_id, version):
        """
        Embed Python source in a PowerShell here-string launcher.
        @\'...\'@ is fully literal (no variable / command expansion).
        Deploy on Windows (run as Administrator):\\n
          powershell -ExecutionPolicy Bypass -File <script>
        """
        return (
            "# ForensicPro Remote Agent Launcher  [PowerShell Script]\\n"
            "# Generated by ForensicPro v%s  |  Case: %s\\n"
            "# Deploy on Windows target (run as Administrator):\\n"
            "#   powershell -ExecutionPolicy Bypass -File <script>\\n"
            "$code = @\'\\n"
            "%s\\n"
            "\'@\\n"
            "$tmp = Join-Path $env:TEMP \'forensic_agent_%s.py\'\\n"
            "[IO.File]::WriteAllText($tmp, $code, [Text.Encoding]::UTF8)\\n"
            "& python $tmp @args\\n"
            "Remove-Item $tmp -Force -ErrorAction SilentlyContinue\\n"
        ) % (version, case_id, python_code, case_id)

    def _compile_exe(self, dest_path, case_id):
        """
        Compile the Python agent to a standalone Windows .exe via PyInstaller.
        Runs in a background thread; shows an info or error dialog when done.
        Requires:  pip install pyinstaller
        """
        code_snapshot = self._code

        def _run():
            import tempfile, subprocess as _sp, shutil as _sh
            tmp_dir = tempfile.mkdtemp(prefix="forensicpro_build_")
            py_src  = os.path.join(tmp_dir, "forensic_agent_%s.py" % case_id)
            try:
                with open(py_src, "w", encoding="utf-8") as f:
                    f.write(code_snapshot)
                res = _sp.run(
                    [sys.executable, "-m", "PyInstaller",
                     "--onefile", "--clean", "--noconfirm",
                     "--name", "forensic_agent_%s" % case_id,
                     "--distpath", tmp_dir,
                     py_src],
                    capture_output=True, text=True, timeout=300)
                exe_built = os.path.join(tmp_dir, "forensic_agent_%s.exe" % case_id)
                if res.returncode == 0 and os.path.isfile(exe_built):
                    _sh.copy2(exe_built, dest_path)
                    try:
                        _sh.copy2(dest_path,
                            "/mnt/user-data/outputs/" + os.path.basename(dest_path))
                    except Exception:
                        pass
                    QMessageBox.information(None, "EXE Built",
                        "Agent compiled successfully:\\n" + dest_path)
                else:
                    QMessageBox.critical(None, "PyInstaller Error",
                        "Build failed (exit %d):\\n%s" % (
                            res.returncode,
                            (res.stdout + "\\n" + res.stderr)[-1500:]))
            except FileNotFoundError:
                QMessageBox.critical(None, "Missing Dependency",
                    "PyInstaller not found.\\n"
                    "Install it first:\\n  pip install pyinstaller")
            except Exception as ex:
                QMessageBox.critical(None, "EXE Compile Error", str(ex))
            finally:
                try:
                    _sh.rmtree(tmp_dir, ignore_errors=True)
                except Exception:
                    pass

        QMessageBox.information(self, "Building EXE…",
            "PyInstaller is compiling the agent.\\n"
            "This may take 30–120 seconds.\\n"
            "A dialog will appear when the build completes.")
        threading.Thread(target=_run, daemon=True).start()'''


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python forensic_qt_patcher.py <forensic_qt.py>")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"Error: file not found — {src}")
        sys.exit(1)

    bak = src + ".bak"
    shutil.copy2(src, bak)
    print(f"Backup created: {bak}\n")

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    print("Applying patches…")
    code = apply(code, FIX1_OLD,  FIX1_NEW,  "Fix 1  — image-browser bookmark KeyError crash")
    code = apply(code, FIX2A_OLD, FIX2A_NEW, "Fix 2a — AGENT_TEMPLATE zpath NameError")
    code = apply(code, FIX2B_OLD, FIX2B_NEW, "Fix 2b — add Agent Format combo box to AgentTab")
    code = apply(code, FIX2C_OLD, FIX2C_NEW, "Fix 2c — replace _save() + add format helpers")

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(code)

    print(f"\nDone — patched file written to: {src}")
    print(f"       Restore original with:    {bak}")


if __name__ == "__main__":
    main()
