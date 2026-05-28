
"""
ForensicPro Enterprise v4.0  –  PyQt6 Edition
Digital Forensic Analysis Platform

Classic EnCase / FTK tri-pane layout:
  Left       : Evidence tree (cases, images, disks, folders)
  Top-Right  : File / entry list
  Bottom-Right: Content viewer (Text | Hex | Image | Metadata | PDF-text)

Plus: Artifact Selection, Analysis Results, Timeline, Remote Agent,
      Email Viewer, Bookmarks tabs.
"""

import sys, os, re, stat, json, csv, hashlib, datetime, time, threading
import struct, platform, socket, tempfile, shutil, zipfile, base64, subprocess
# ── FIX: add missing stdlib imports referenced throughout EmailViewerTab ──
import traceback, email, email.policy, email.message, mailbox
from pathlib import Path

import psutil

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QSplitter, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget, QTextEdit,
    QPlainTextEdit, QLabel, QLineEdit, QPushButton, QToolBar, QStatusBar,
    QMenuBar, QMenu, QFileDialog, QMessageBox, QDialog, QDialogButtonBox,
    QVBoxLayout, QHBoxLayout, QGridLayout, QScrollArea, QFrame, QProgressBar,
    QCheckBox, QComboBox, QGroupBox, QListWidget, QListWidgetItem, QSizePolicy,
    QStackedWidget, QFormLayout, QSpinBox, QToolButton, QAbstractItemView,
    QScrollBar, QInputDialog,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QRect, QPoint, QMimeData,
    QSortFilterProxyModel, QModelIndex, pyqtSlot, QRunnable, QThreadPool,
    QObject,
)
from PyQt6.QtGui import (
    QFont, QFontMetrics, QColor, QPalette, QIcon, QPixmap, QImage,
    QTextCursor, QTextCharFormat, QSyntaxHighlighter, QBrush, QPainter,
    QLinearGradient, QAction as QGuiAction, QAction,
)

# ══════════════════════════════════════════════════════════════
#  PALETTE / THEME
# ══════════════════════════════════════════════════════════════
APP_NAME    = "ForensicPro Enterprise"
APP_VERSION = "4.0"

C = {
    "bg":        "#0d1117",
    "bg2":       "#161b22",
    "bg3":       "#21262d",
    "sidebar":   "#010409",
    "panel":     "#161b22",
    "border":    "#30363d",
    "sel":       "#1f3354",
    "sel_text":  "#58a6ff",
    "fg":        "#e6edf3",
    "fg2":       "#8b949e",
    "fg3":       "#484f58",
    "accent":    "#58a6ff",
    "green":     "#3fb950",
    "red":       "#f85149",
    "orange":    "#d29922",
    "purple":    "#bc8cff",
    "yellow":    "#e3b341",
    "header":    "#21262d",
    "row_alt":   "#1a2030",
    "btn":       "#21262d",
    "btn_hover": "#30363d",
    "btn_press": "#484f58",
}

STYLESHEET = f"""
QMainWindow, QWidget {{
    background: {C['bg']};
    color: {C['fg']};
    font-family: "Segoe UI", "SF Pro Display", "Helvetica Neue", Arial, sans-serif;
    font-size: 9pt;
}}
QMenuBar {{
    background: {C['bg3']};
    color: {C['fg']};
    border-bottom: 1px solid {C['border']};
    padding: 2px 0;
}}
QMenuBar::item:selected {{ background: {C['sel']}; color: {C['accent']}; }}
QMenu {{
    background: {C['bg2']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    padding: 4px 0;
}}
QMenu::item {{ padding: 5px 24px 5px 12px; }}
QMenu::item:selected {{ background: {C['sel']}; color: {C['accent']}; }}
QMenu::separator {{ height: 1px; background: {C['border']}; margin: 3px 0; }}
QToolBar {{
    background: {C['bg3']};
    border-bottom: 1px solid {C['border']};
    spacing: 2px;
    padding: 3px 6px;
}}
QToolButton {{
    background: {C['btn']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 4px 10px;
    font-size: 9pt;
}}
QToolButton:hover  {{ background: {C['btn_hover']}; color: {C['accent']}; }}
QToolButton:pressed{{ background: {C['btn_press']}; }}
QPushButton {{
    background: {C['btn']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 4px 12px;
    font-size: 9pt;
}}
QPushButton:hover  {{ background: {C['btn_hover']}; color: {C['accent']}; }}
QPushButton:pressed{{ background: {C['btn_press']}; }}
QPushButton#accent {{
    background: {C['accent']};
    color: #000;
    font-weight: bold;
    border: none;
}}
QPushButton#accent:hover {{ background: #79c0ff; }}
QTabWidget::pane {{
    border: 1px solid {C['border']};
    background: {C['bg']};
}}
QTabBar::tab {{
    background: {C['bg3']};
    color: {C['fg2']};
    padding: 6px 16px;
    border: 1px solid {C['border']};
    border-bottom: none;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    background: {C['bg']};
    color: {C['accent']};
    border-bottom: 2px solid {C['accent']};
}}
QTableWidget {{
    background: {C['bg']};
    color: {C['fg']};
    gridline-color: {C['border']};
    border: none;
    alternate-background-color: {C['row_alt']};
    selection-background-color: {C['sel']};
    selection-color: {C['accent']};
}}
QHeaderView::section {{
    background: {C['bg3']};
    color: {C['fg2']};
    padding: 4px 8px;
    border: none;
    border-right: 1px solid {C['border']};
    border-bottom: 1px solid {C['border']};
    font-size: 8pt;
    font-weight: bold;
}}
QTreeWidget {{
    background: {C['sidebar']};
    color: {C['fg']};
    border: none;
    alternate-background-color: {C['row_alt']};
}}
QTreeWidget::item:selected {{ background: {C['sel']}; color: {C['accent']}; }}
QListWidget {{
    background: {C['bg2']};
    color: {C['fg']};
    border: none;
    outline: none;
}}
QListWidget::item:selected {{ background: {C['sel']}; color: {C['accent']}; }}
QLineEdit {{
    background: {C['bg3']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 4px 8px;
}}
QLineEdit:focus {{ border-color: {C['accent']}; }}
QPlainTextEdit, QTextEdit {{
    background: {C['bg']};
    color: {C['fg']};
    border: none;
    font-family: 'Consolas','Cascadia Code','Courier New',monospace;
    font-size: 9pt;
}}
QScrollBar:vertical {{
    background: {C['bg2']}; width: 10px; border: none;
}}
QScrollBar::handle:vertical {{
    background: {C['bg3']}; border-radius: 4px; min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {C['border']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {C['bg2']}; height: 10px; border: none;
}}
QScrollBar::handle:horizontal {{
    background: {C['bg3']}; border-radius: 4px; min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{ background: {C['border']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QProgressBar {{
    background: {C['bg3']};
    border: none;
    border-radius: 3px;
    color: {C['accent']};
}}
QProgressBar::chunk {{
    background: {C['accent']};
    border-radius: 3px;
}}
QSplitter::handle {{ background: {C['border']}; }}
QGroupBox {{
    border: 1px solid {C['border']};
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 8px;
    color: {C['fg2']};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
}}
QLabel#section_header {{
    background: {C['bg3']};
    color: {C['fg']};
    font-size: 9pt;
    font-weight: bold;
    padding: 5px 10px;
    border-bottom: 1px solid {C['border']};
}}
QFrame#separator {{
    border: none;
    border-top: 1px solid {C['border']};
    max-height: 1px;
}}
QComboBox {{
    background: {C['bg3']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 4px 8px;
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {C['bg2']};
    color: {C['fg']};
    selection-background-color: {C['sel']};
    border: 1px solid {C['border']};
}}
QCheckBox {{
    color: {C['fg']};
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {C['border']};
    border-radius: 3px;
    background: {C['bg3']};
}}
QCheckBox::indicator:checked {{
    background: {C['accent']};
    border-color: {C['accent']};
}}
QSpinBox {{
    background: {C['bg3']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 3px 6px;
}}
QToolTip {{
    background: {C['bg3']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    padding: 4px 8px;
}}
"""

# ══════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════
def fmt_size(n):
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def fmt_ts(ts):
    if not ts: return ""
    try:
        if isinstance(ts, (int, float)):
            return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        return str(ts)
    except Exception:
        return str(ts)

def md5_path(path):
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception as e:
        return f"[error: {e}]"
    return h.hexdigest()

def sha256_path(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception as e:
        return f"[error: {e}]"
    return h.hexdigest()

def detect_type(path):
    SIGS = [
        (b"\x89PNG",              "PNG Image"),
        (b"\xFF\xD8\xFF",         "JPEG Image"),
        (b"GIF8",                 "GIF Image"),
        (b"BM",                   "BMP Image"),
        (b"%PDF",                 "PDF Document"),
        (b"PK\x03\x04",          "ZIP Archive"),
        (b"Rar!",                 "RAR Archive"),
        (b"\x1f\x8b",            "GZIP"),
        (b"\xFD7zXZ",            "XZ Archive"),
        (b"7z\xBC\xAF",          "7-Zip Archive"),
        (b"OggS",                 "OGG Audio"),
        (b"ID3",                  "MP3 Audio"),
        (b"fLaC",                 "FLAC Audio"),
        (b"RIFF",                 "WAV/AVI"),
        (b"\x00\x00\x00\x18ftyp","MP4 Video"),
        (b"\xD0\xCF\x11\xE0",    "OLE2 / MS Office"),
        (b"SQLite format",        "SQLite Database"),
        (b"ELF",                  "ELF Binary"),
    ]
    try:
        with open(path, "rb") as f: hdr = f.read(16)
        for sig, name in SIGS:
            if hdr[:len(sig)] == sig: return name
    except Exception:
        pass
    return {
        ".e01":"EnCase E01",".dd":"DD Image",".img":"Disk Image",
        ".raw":"RAW Image",".vmdk":"VMware Disk",".vhd":"VHD Image",
        ".iso":"ISO Image",".evtx":"Event Log",".reg":"Registry",
        ".db":"Database",".sqlite":"SQLite",".pcap":"PCAP Capture",
        ".pcapng":"PCAPng Capture",".log":"Log File",".txt":"Text",
        ".xml":"XML",".json":"JSON",".csv":"CSV",".htm":"HTML",
        ".html":"HTML",".py":"Python Script",".ps1":"PowerShell",
        ".bat":"Batch Script",".sh":"Shell Script",".lnk":"LNK Shortcut",
        ".pf":"Prefetch",".exe":"Executable",".dll":"DLL Library",
    }.get(Path(path).suffix.lower(), "Unknown")

def _file_type_label(name):
    return {
        '.jpg':'JPEG Image','.jpeg':'JPEG Image','.png':'PNG Image',
        '.gif':'GIF Image','.bmp':'BMP Image','.tiff':'TIFF Image',
        '.mp3':'MP3 Audio','.wav':'WAV Audio','.flac':'FLAC Audio',
        '.mp4':'MP4 Video','.avi':'AVI Video','.mkv':'MKV Video',
        '.pdf':'PDF Document','.zip':'ZIP Archive','.rar':'RAR Archive',
        '.7z':'7-Zip','.tar':'TAR','.gz':'GZip',
        '.exe':'PE Executable','.dll':'DLL Library','.sys':'Driver',
        '.py':'Python Script','.js':'JavaScript','.sh':'Shell Script',
        '.bat':'Batch Script','.ps1':'PowerShell',
        '.txt':'Text File','.log':'Log File','.xml':'XML File',
        '.json':'JSON File','.csv':'CSV File','.html':'HTML File',
        '.db':'SQLite DB','.sqlite':'SQLite DB','.sqlite3':'SQLite DB',
        '.evtx':'Event Log','.reg':'Registry','.lnk':'LNK Shortcut',
        '.pf':'Prefetch','.hive':'Registry Hive',
        '.e01':'EnCase E01','.dd':'DD Image','.img':'Disk Image',
        '.raw':'RAW Image','.vmdk':'VMware Disk','.vhd':'VHD Image',
        '.pst':'Outlook PST','.ost':'Outlook OST',
        '.msg':'Outlook MSG','.mbox':'MBOX','.eml':'EML',
    }.get(os.path.splitext(name)[1].lower(), 'File')


# ══════════════════════════════════════════════════════════════
#  EWF / E01 BACKEND DETECTION
# ══════════════════════════════════════════════════════════════
def _ewf_available():
    """Return (method, backend) or (None, None)."""
    import ctypes
    for libname in ("libewf.so","libewf-1.dll","libewf.dylib","libewf.so.2"):
        try:
            lib = ctypes.CDLL(libname)
            return ("ctypes_libewf", lib)
        except Exception:
            pass
    try:
        import pyewf
        return ("pyewf", pyewf)
    except ImportError:
        pass
    return (None, None)


# ══════════════════════════════════════════════════════════════
#  FORENSIC IMAGE FS  (pytsk3 + optional EWF)
# ══════════════════════════════════════════════════════════════
class ForensicImageFS:
    _cache = {}

    def __init__(self, image_path):
        self.image_path = image_path
        self.fs    = None
        self.img   = None
        self.error = None
        self._open()

    @classmethod
    def get(cls, path):
        if path not in cls._cache:
            cls._cache[path] = ForensicImageFS(path)
        return cls._cache[path]

    @classmethod
    def invalidate(cls, path):
        if path in cls._cache:
            try: cls._cache[path].cleanup()
            except Exception: pass
            del cls._cache[path]

    def _open(self):
        try:
            import pytsk3
        except ImportError:
            self.error = "pytsk3 not installed.  Run:  pip install pytsk3"
            return
        ext    = os.path.splitext(self.image_path)[1].lower()
        is_ewf = ext in ('.e01','.ewf','.ex01','.e02','.s01','.l01')
        if is_ewf:
            self._open_ewf(pytsk3)
        else:
            self._open_raw(pytsk3, self.image_path)

    def _open_ewf(self, pytsk3):
        import ctypes
        method, backend = _ewf_available()
        norm_path = os.path.normpath(os.path.abspath(self.image_path))
        if method == 'pyewf':
            try:
                ewf = backend
                filenames = ewf.glob(norm_path)
                ewf_handle = ewf.handle()
                ewf_handle.open(filenames)
                self.img = pytsk3.Img_Info(url=norm_path)
                self.fs  = pytsk3.FS_Info(self.img)
                return
            except Exception as e:
                self.error = f"pyewf failed: {e}"
        self.error = "No EWF backend available. Install libewf or pyewf."

    def _open_raw(self, pytsk3, path):
        try:
            self.img = pytsk3.Img_Info(url=path)
            self.fs  = pytsk3.FS_Info(self.img)
        except Exception as e:
            self.error = str(e)

    def list_dir(self, inode=None):
        if not self.fs: return []
        results = []
        try:
            import pytsk3
            if inode is None:
                d = self.fs.open_dir(path="/")
            else:
                d = self.fs.open_dir(inode=inode)
            for entry in d:
                try:
                    name = entry.info.name.name.decode(errors="replace")
                    if name in (".", ".."): continue
                    is_dir = bool(entry.info.meta and
                                  entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
                    sz   = entry.info.meta.size  if entry.info.meta else 0
                    mt   = entry.info.meta.mtime if entry.info.meta else 0
                    ino  = entry.info.meta.addr  if entry.info.meta else None
                    results.append({
                        "name":   name,
                        "is_dir": is_dir,
                        "size":   sz,
                        "mtime":  mt,
                        "inode":  ino,
                        "type":   _file_type_label(name),
                    })
                except Exception:
                    pass
        except Exception:
            pass
        return results

    def read_file(self, inode, max_bytes=1<<20):
        if not self.fs: return b""
        try:
            f = self.fs.open_meta(inode=inode)
            sz = min(f.info.meta.size, max_bytes)
            return f.read_random(0, sz)
        except Exception:
            return b""

    def cleanup(self):
        self.img = None
        self.fs  = None


# ══════════════════════════════════════════════════════════════
#  ARTIFACT DEFINITIONS
# ══════════════════════════════════════════════════════════════
ARTIFACT_CATEGORIES = {
    "System Information": [
        "OS Version & Build","Hostname & Domain","Installed Software",
        "Running Processes","Loaded Drivers/Modules","Scheduled Tasks",
        "System Uptime","BIOS/UEFI Info","Hardware Profile",
    ],
    "Email Artifacts": [
        "PST/OST Files (Outlook)","MSG Files (Outlook)","Thunderbird MBOX",
        "Email Accounts Config","Email Attachments","Email Contacts",
        "Email Calendar Items",
    ],
    "User & Account Activity": [
        "Local User Accounts","Last Login Times","Recent Files (MRU)",
        "Shellbags","UserAssist Keys","Jump Lists",
        "Windows Search History","Typed URLs",
    ],
    "Network Artifacts": [
        "Active Connections","ARP Cache","DNS Cache","Network Interfaces",
        "Firewall Rules","Browser Cookies","Browser History",
        "Cached Credentials","WiFi Profiles",
    ],
    "Persistence Mechanisms": [
        "Registry Run Keys","Startup Folder Items","Services (Auto-Start)",
        "COM Hijacking Keys","Browser Extensions","Task Scheduler Jobs",
        "WMI Subscriptions","AppInit DLLs",
    ],
    "File System Artifacts": [
        "Recently Accessed Files","Prefetch Files","LNK / Shortcut Files",
        "Temp Directory Contents","Recycle Bin Contents",
        "Volume Shadow Copies","Alternate Data Streams","$MFT Entries",
    ],
    "Event Logs": [
        "Security Event Log","System Event Log","Application Event Log",
        "PowerShell Operational Log","RDP Session Log",
        "Account Logon Events","Process Creation Events (4688)",
    ],
    "Memory Artifacts": [
        "Process Memory Strings","Injected DLLs","Hollowed Processes",
        "Heap Allocations","Kernel Objects",
    ],
    "Credentials & Secrets": [
        "SAM Database Hash Dump","LSA Secrets","DPAPI Master Keys",
        "Browser Saved Passwords","Certificate Store",
    ],
}

# ══════════════════════════════════════════════════════════════
#  REMOTE AGENT TEMPLATE
# ══════════════════════════════════════════════════════════════
AGENT_TEMPLATE = '''#!/usr/bin/env python3
"""
ForensicPro Remote Collection Agent  v{version}
Generated : {timestamp}
Case      : {case_name}  ({case_id})
Examiner  : {examiner}
Artifacts : {artifacts_brief}
"""
import os, sys, json, socket, hashlib, datetime, platform, subprocess, zipfile, tempfile
import psutil
ARTIFACTS   = {artifacts_json}
OUTPUT_DIR  = r"{output_dir}"
SERVER      = "{server}"
CASE_ID     = "{case_id}"
VERSION     = "{version}"
def fmt(n):
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{{n:.1f}} {{u}}"
        n /= 1024
    return f"{{n:.1f}} PB"
def sysinfo():
    u = platform.uname(); m = psutil.virtual_memory()
    return {{"hostname":u.node,"os":u.system,"release":u.release,
             "version":u.version,"ram":fmt(m.total),"cpu":psutil.cpu_count()}}
def processes():
    out = []
    for p in psutil.process_iter(['pid','name','username','status','exe']):
        try: out.append(p.info)
        except: pass
    return out
def connections():
    out = []
    for c in psutil.net_connections(kind='inet'):
        try:
            out.append({{"pid":c.pid,"status":c.status,
                "local":f"{{c.laddr.ip}}:{{c.laddr.port}}" if c.laddr else "",
                "remote":f"{{c.raddr.ip}}:{{c.raddr.port}}" if c.raddr else ""}})
        except: pass
    return out
def users():
    try: return [{{"name":u.name,"terminal":u.terminal,"host":u.host,"started":u.started}}
                 for u in psutil.users()]
    except: return []
def disks():
    out = []
    for p in psutil.disk_partitions():
        try:
            u = psutil.disk_usage(p.mountpoint)
            out.append({{"device":p.device,"mount":p.mountpoint,"fs":p.fstype,
                         "total":fmt(u.total),"used":fmt(u.used),"free":fmt(u.free)}})
        except: pass
    return out
COLLECTORS = {{
    "Running Processes": processes,
    "Active Connections": connections,
    "OS Version & Build": sysinfo,
    "Local User Accounts": users,
    "Hardware Profile": disks,
}}
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report = {{"case_id":CASE_ID,"agent_version":VERSION,
               "collected_at":datetime.datetime.now().isoformat(),
               "host":socket.gethostname(),"artifacts":{{}}}}
    for art in ARTIFACTS:
        print(f"[*] {{art}}")
        try:
            fn = COLLECTORS.get(art, lambda: {{"status":"collected","note":"requires OS integration"}})
            report["artifacts"][art] = fn()
            print(f"[+] done")
        except Exception as e:
            report["artifacts"][art] = {{"error":str(e)}}
            print(f"[-] {{e}}")
    ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(OUTPUT_DIR, f"forensic_{{CASE_ID}}_{{ts}}.json")
    with open(out,"w") as f: json.dump(report, f, indent=2, default=str)
    zpath = out.replace(".json",".zip")
    with zipfile.ZipFile(zpath,"w",zipfile.ZIP_DEFLATED) as z:
        z.write(out, os.path.basename(out))
    print(f"[+] Saved: {{out}}")
    if SERVER:
        try:
            host, port = SERVER.split(":")
            s = __import__("socket").socket()
            s.connect((host, int(port)))
            data = open(zpath,"rb").read()
            s.sendall(len(data).to_bytes(8,"big") + data)
            s.close()
            print(f"[+] Sent to {{SERVER}}")
        except Exception as e:
            print(f"[-] Send failed: {{e}}")
if __name__ == "__main__":
    main()
'''


# ══════════════════════════════════════════════════════════════
#  LIVE ARTIFACT COLLECTION
# ══════════════════════════════════════════════════════════════
def collect_artifact(name, target_path=None, target_type="local"):
    import glob, sqlite3, csv as _csv
    results = []
    OS = platform.system()

    effective_home = (Path(target_path) if target_path and target_type == "directory"
                      else Path.home())

    def _run(cmd, timeout=8):
        try:
            out = subprocess.check_output(cmd, text=True, timeout=timeout,
                                          stderr=subprocess.DEVNULL)
            return [l for l in out.splitlines() if l.strip()]
        except Exception:
            return []

    def _read(path, max_bytes=65536):
        try:
            with open(path, errors='replace') as f:
                return f.read(max_bytes)
        except Exception:
            return ""

    def _sqlite_query(db_path, sql, params=()):
        rows = []
        tmp = None
        try:
            import shutil as _sh
            tmp = db_path + ".forensic_tmp"
            _sh.copy2(db_path, tmp)
            con = sqlite3.connect(tmp)
            con.row_factory = sqlite3.Row
            cur = con.execute(sql, params)
            cols = [d[0] for d in cur.description]
            for row in cur.fetchall():
                rows.append(dict(zip(cols, row)))
            con.close()
        except Exception as e:
            rows.append({"Error": str(e)})
        finally:
            try:
                if tmp and os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
        return rows

    try:
        if name == "OS Version & Build":
            u = platform.uname()
            results.append({
                "System": u.system, "Node": u.node, "Release": u.release,
                "Version": u.version, "Machine": u.machine,
                "Processor": u.processor, "Python": sys.version.split()[0],
            })
        elif name == "Hostname & Domain":
            hn = socket.gethostname()
            try:   ip = socket.gethostbyname(hn)
            except: ip = "N/A"
            results.append({"Hostname": hn, "FQDN": socket.getfqdn(), "IP": ip})
        elif name == "System Uptime":
            boot = datetime.datetime.fromtimestamp(psutil.boot_time())
            up   = datetime.datetime.now() - boot
            m    = psutil.virtual_memory()
            results.append({
                "Boot Time": boot.strftime("%Y-%m-%d %H:%M:%S"),
                "Uptime":    str(up).split('.')[0],
                "RAM Total": fmt_size(m.total),
                "RAM Used":  fmt_size(m.used),
                "RAM Free":  fmt_size(m.available),
            })
        elif name == "Hardware Profile":
            for p in psutil.disk_partitions():
                try:
                    u = psutil.disk_usage(p.mountpoint)
                    results.append({
                        "Device": p.device, "Mount": p.mountpoint, "FS": p.fstype,
                        "Total": fmt_size(u.total), "Used": fmt_size(u.used),
                        "Free":  fmt_size(u.free),  "Usage%": f"{u.percent:.1f}%",
                    })
                except Exception:
                    pass
        elif name == "Running Processes":
            for p in psutil.process_iter(['pid','name','username','status','exe']):
                try:
                    info = p.info
                    results.append({
                        "PID":    str(info.get('pid','')),
                        "Name":   info.get('name',''),
                        "User":   info.get('username',''),
                        "Status": info.get('status',''),
                        "EXE":    info.get('exe','') or '',
                    })
                except Exception:
                    pass
        elif name == "Active Connections":
            for c in psutil.net_connections(kind='inet'):
                try:
                    results.append({
                        "PID":    str(c.pid),
                        "Status": c.status,
                        "Local":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "Remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    })
                except Exception:
                    pass
        elif name == "Network Interfaces":
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    results.append({
                        "Interface": iface, "Family": str(addr.family),
                        "Address": addr.address, "Netmask": addr.netmask or "",
                    })
        elif name == "Local User Accounts":
            if OS == "Windows":
                for line in _run(["net", "user"]):
                    results.append({"Entry": line})
            elif OS == "Linux":
                for line in _read("/etc/passwd").splitlines():
                    parts = line.split(":")
                    if len(parts) >= 4:
                        results.append({
                            "User": parts[0], "UID": parts[2], "GID": parts[3],
                            "Home": parts[5] if len(parts) > 5 else "",
                            "Shell": parts[6] if len(parts) > 6 else "",
                        })
            else:
                results.append({"Note": "Platform not supported."})
        elif name == "Installed Software":
            if OS == "Linux":
                lines = _run(["dpkg","-l"], timeout=15)
                for line in lines:
                    if line.startswith("ii"):
                        parts = line.split()
                        if len(parts) >= 3:
                            results.append({"Package": parts[1], "Version": parts[2]})
            elif OS == "Windows":
                lines = _run(["wmic","product","get","Name,Version,Vendor","/format:csv"])
                for line in lines[1:]:
                    parts = line.split(",")
                    if len(parts) >= 3 and parts[1].strip():
                        results.append({"Name": parts[1], "Version": parts[2],
                                        "Vendor": parts[3] if len(parts) > 3 else ""})
            if not results:
                results.append({"Note": "No software list available.", "Platform": OS})
        elif name == "Loaded Drivers/Modules":
            if OS == "Linux":
                for line in _run(["lsmod"])[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        results.append({"Module": parts[0], "Size": parts[1],
                                        "Used By": " ".join(parts[2:])})
            elif OS == "Windows":
                lines = _run(["driverquery", "/fo", "csv", "/v"])
                reader = _csv.reader(lines)
                headers = next(reader, [])
                for row in reader:
                    if row: results.append(dict(zip(headers, row)))
            else:
                results.append({"Note": "Not available on this platform."})
        elif name == "Scheduled Tasks":
            if OS == "Linux":
                for cp in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
                    if os.path.isfile(cp):
                        try:
                            tasks = [l for l in _read(cp).splitlines()
                                     if l.strip() and not l.startswith("#")]
                            results.append({"Source": cp, "Tasks": str(len(tasks)),
                                            "Preview": tasks[0][:80] if tasks else "(empty)"})
                        except Exception:
                            pass
            elif OS == "Windows":
                lines = _run(["schtasks", "/query", "/fo", "csv", "/v"])
                reader = _csv.reader(lines)
                headers = next(reader, [])
                for row in reader:
                    if row and len(row) == len(headers):
                        results.append(dict(zip(headers, row)))
            else:
                results.append({"Note": "Not available on this platform."})
        elif name == "Recently Accessed Files":
            home = effective_home
            found = []
            for d in [home, home/"Documents", home/"Downloads", home/"Desktop"]:
                if d.exists():
                    try:
                        for entry in d.iterdir():
                            if entry.is_file():
                                try:
                                    s = entry.stat()
                                    found.append((s.st_atime, entry, s))
                                except Exception:
                                    pass
                    except Exception:
                        pass
            found.sort(reverse=True)
            for at, f, s in found[:60]:
                results.append({
                    "File": f.name, "Directory": str(f.parent),
                    "Size": fmt_size(s.st_size), "Accessed": fmt_ts(s.st_atime),
                    "Modified": fmt_ts(s.st_mtime), "Type": detect_type(str(f)),
                })
        elif name == "Prefetch Files":
            if OS == "Windows":
                pf_dir = Path("C:/Windows/Prefetch")
                if pf_dir.exists():
                    for f in sorted(pf_dir.iterdir(),
                                    key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
                        try:
                            s = f.stat()
                            results.append({"File": f.name, "Size": fmt_size(s.st_size),
                                            "Created": fmt_ts(s.st_ctime),
                                            "Modified": fmt_ts(s.st_mtime)})
                        except Exception:
                            pass
                else:
                    results.append({"Note": "Prefetch directory not found."})
            else:
                results.append({"Note": "Prefetch files are Windows-specific."})
        elif name == "LNK / Shortcut Files":
            home = effective_home
            for d in [home/"Desktop", home/"Documents",
                      home/"AppData/Roaming/Microsoft/Windows/Recent"]:
                if d.exists():
                    for f in d.rglob("*.lnk" if OS == "Windows" else "*.desktop"):
                        try:
                            s = f.stat()
                            results.append({"File": f.name, "Path": str(f),
                                            "Size": fmt_size(s.st_size),
                                            "Modified": fmt_ts(s.st_mtime)})
                        except Exception:
                            pass
        elif name == "Temp Directory Contents":
            tmp_dir = tempfile.gettempdir()
            try:
                entries = sorted(os.scandir(tmp_dir),
                                 key=lambda e: e.stat().st_mtime, reverse=True)
            except Exception:
                entries = []
            for entry in entries[:80]:
                try:
                    s = entry.stat()
                    results.append({
                        "Name": entry.name,
                        "Is Dir": "Yes" if entry.is_dir() else "No",
                        "Size": fmt_size(s.st_size) if entry.is_file() else "—",
                        "Modified": fmt_ts(s.st_mtime),
                        "Type": "Directory" if entry.is_dir() else detect_type(entry.path),
                    })
                except Exception:
                    pass
        elif name == "Recycle Bin Contents":
            if OS == "Windows":
                rb = Path("C:/$Recycle.Bin")
                if rb.exists():
                    for f in rb.rglob("*"):
                        try:
                            s = f.stat()
                            results.append({"File": f.name, "Path": str(f),
                                            "Size": fmt_size(s.st_size),
                                            "Modified": fmt_ts(s.st_mtime)})
                        except Exception:
                            pass
                else:
                    results.append({"Note": "Recycle Bin not accessible."})
            elif OS == "Linux":
                trash = effective_home/".local/share/Trash/files"
                if trash.exists():
                    for f in trash.iterdir():
                        try:
                            s = f.stat()
                            results.append({"File": f.name, "Path": str(f),
                                            "Size": fmt_size(s.st_size),
                                            "Modified": fmt_ts(s.st_mtime)})
                        except Exception:
                            pass
                else:
                    results.append({"Note": "Trash empty or not found."})
        elif name == "Browser History":
            home = effective_home
            browser_dbs = []
            if OS == "Linux":
                browser_dbs += list(home.glob(".mozilla/firefox/*/places.sqlite"))
                browser_dbs += list(home.glob(".config/google-chrome/*/History"))
            elif OS == "Windows":
                ff_path = home/"AppData/Roaming/Mozilla/Firefox/Profiles"
                if ff_path.exists():
                    browser_dbs += list(ff_path.glob("*/places.sqlite"))
                ch_path = home/"AppData/Local/Google/Chrome/User Data"
                if ch_path.exists():
                    browser_dbs += list(ch_path.glob("*/History"))
            for db in browser_dbs[:3]:
                db = str(db)
                if "places.sqlite" in db:
                    rows = _sqlite_query(db,
                        "SELECT url, title, visit_count, last_visit_date "
                        "FROM moz_places ORDER BY last_visit_date DESC LIMIT 100")
                    for r in rows:
                        r["Browser"] = "Firefox"; results.append(r)
                elif "History" in db:
                    rows = _sqlite_query(db,
                        "SELECT url, title, visit_count, last_visit_time "
                        "FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                    for r in rows:
                        r["Browser"] = "Chrome"; results.append(r)
            if not results:
                results.append({"Note": "No browser history databases found."})
        elif name == "Registry Run Keys":
            if OS == "Windows":
                try:
                    import winreg
                    run_keys = [
                        (winreg.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                        (winreg.HKEY_CURRENT_USER,
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                    ]
                    for hive, subkey in run_keys:
                        try:
                            key = winreg.OpenKey(hive, subkey)
                            i = 0
                            while True:
                                try:
                                    vname, vdata, _ = winreg.EnumValue(key, i)
                                    results.append({"Key": subkey, "Name": vname,
                                                    "Data": str(vdata)})
                                    i += 1
                                except OSError:
                                    break
                        except Exception:
                            pass
                except ImportError:
                    results.append({"Note": "winreg not available."})
            else:
                results.append({"Note": "Registry Run Keys are Windows-specific."})
        elif name in ("Security Event Log","System Event Log","Application Event Log",
                      "PowerShell Operational Log","RDP Session Log",
                      "Account Logon Events","Process Creation Events (4688)"):
            log_map = {
                "Security Event Log": "Security", "System Event Log": "System",
                "Application Event Log": "Application",
                "PowerShell Operational Log": "Microsoft-Windows-PowerShell/Operational",
            }
            if OS == "Windows":
                log_name = log_map.get(name, "System")
                for line in _run(["wevtutil","qe",log_name,"/c:50","/f:text","/rd:true"]):
                    results.append({"Entry": line})
            elif OS == "Linux":
                for logfile in ["/var/log/syslog","/var/log/auth.log","/var/log/messages"]:
                    if os.path.exists(logfile):
                        with open(logfile, errors='replace') as f:
                            lines = f.readlines()
                        for line in lines[-100:]:
                            results.append({"Log": logfile, "Entry": line.strip()})
                        break
                if not results:
                    results.append({"Note": f"{name} not found. Platform: {OS}"})
            else:
                results.append({"Note": f"{name} not available on {OS}."})
        elif name == "PST/OST Files (Outlook)":
            search_roots = [effective_home, effective_home/"Documents",
                            effective_home/"Desktop", effective_home/"Downloads"]
            if OS == "Windows":
                search_roots += [effective_home/"AppData/Local/Microsoft/Outlook"]
            pst_files = []
            for root in search_roots:
                if root.exists():
                    pst_files.extend(list(root.rglob("*.pst"))[:20])
                    pst_files.extend(list(root.rglob("*.ost"))[:10])
            for pf in pst_files[:30]:
                try:
                    s = os.stat(str(pf))
                    results.append({
                        "File": pf.name, "Path": str(pf.parent),
                        "Size": fmt_size(s.st_size), "Modified": fmt_ts(s.st_mtime),
                        "Type": "PST" if pf.suffix.lower() == ".pst" else "OST",
                    })
                except Exception as e:
                    results.append({"File": str(pf), "Error": str(e)})
            if not results:
                results.append({"Note": "No PST/OST files found."})
        elif name == "Thunderbird MBOX":
            tb_profiles = []
            if OS == "Linux":
                tb_profiles = list(effective_home.glob(".thunderbird/*/Mail/**/*.mbox"))
            elif OS == "Windows":
                tb_base = effective_home/"AppData/Roaming/Thunderbird/Profiles"
                if tb_base.exists():
                    tb_profiles = list(tb_base.rglob("*.mbox"))
            for mbox_path in tb_profiles[:20]:
                try:
                    sz = os.path.getsize(str(mbox_path))
                    results.append({"File": mbox_path.name, "Path": str(mbox_path.parent),
                                    "Size": fmt_size(sz)})
                except Exception as e:
                    results.append({"File": str(mbox_path), "Error": str(e)})
            if not results:
                results.append({"Note": "No Thunderbird MBOX files found."})
        elif name == "ARP Cache":
            for line in _run(["arp","-a"] if OS=="Windows" else ["arp","-n"]):
                results.append({"Entry": line})
        elif name == "DNS Cache":
            if OS == "Windows":
                for line in _run(["ipconfig", "/displaydns"]):
                    results.append({"Entry": line})
            else:
                results.append({"Note": "DNS cache not directly accessible without root."})
        elif name == "Firewall Rules":
            if OS == "Linux":
                for line in _run(["iptables","-L","-n","-v"]):
                    results.append({"Rule": line})
            elif OS == "Windows":
                for line in _run(["netsh","advfirewall","firewall","show","rule","name=all"]):
                    results.append({"Rule": line})
            else:
                results.append({"Note": "Not available on this platform."})
        elif name == "Startup Folder Items":
            if OS == "Windows":
                startup = Path.home()/"AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
                if startup.exists():
                    for f in startup.iterdir():
                        try:
                            s = f.stat()
                            results.append({"File": f.name, "Path": str(f),
                                            "Size": fmt_size(s.st_size),
                                            "Modified": fmt_ts(s.st_mtime)})
                        except Exception:
                            pass
                else:
                    results.append({"Note": "Startup folder not found."})
            else:
                autostart = effective_home/".config/autostart"
                if autostart.exists():
                    for f in autostart.iterdir():
                        try:
                            results.append({"File": f.name, "Path": str(f)})
                        except Exception:
                            pass
                else:
                    results.append({"Note": "No autostart directory found."})
        elif name == "Services (Auto-Start)":
            if OS == "Linux":
                for line in _run(["systemctl","list-units","--type=service",
                                   "--state=running","--no-pager","--no-legend"]):
                    parts = line.split()
                    if parts:
                        results.append({"Service": parts[0],
                                        "Status": parts[2] if len(parts)>2 else ""})
            elif OS == "Windows":
                lines = _run(["sc","query","type=","all"])
                svc = {}
                for line in lines:
                    line = line.strip()
                    if ":" in line:
                        k, _, v = line.partition(":")
                        svc[k.strip()] = v.strip()
                    elif not line and svc:
                        results.append(svc); svc = {}
            else:
                results.append({"Note": "Not available on this platform."})
        elif name == "SAM Database Hash Dump":
            if OS == "Windows":
                results.append({"Warning": "Requires SYSTEM privileges.",
                                 "Tool": "Use secretsdump.py for offline extraction."})
            elif OS == "Linux":
                shadow = "/etc/shadow"
                if os.path.exists(shadow):
                    try:
                        with open(shadow) as f:
                            for line in f:
                                parts = line.strip().split(":")
                                if len(parts) >= 2:
                                    results.append({"User": parts[0],
                                                    "Hash": parts[1][:32]+"…" if len(parts[1])>32 else parts[1]})
                    except PermissionError:
                        results.append({"Status": "Permission denied. Run as root."})
                else:
                    results.append({"Note": "/etc/shadow not found."})
        elif name == "Certificate Store":
            if OS == "Windows":
                for line in _run(["certutil","-store","my"]):
                    results.append({"Entry": line})
            elif OS == "Linux":
                for cert_dir in ["/etc/ssl/certs","/usr/share/ca-certificates"]:
                    if os.path.exists(cert_dir):
                        for f in os.listdir(cert_dir)[:50]:
                            results.append({"Certificate": f, "Dir": cert_dir})
        else:
            results.append({"Note": f"Artifact '{name}' not yet implemented.",
                             "Platform": OS})
    except Exception as ex:
        results.append({"Error": str(ex), "Artifact": name,
                        "Traceback": traceback.format_exc()[:500]})
    return results


# ══════════════════════════════════════════════════════════════
#  WORKER THREADS
# ══════════════════════════════════════════════════════════════
class ArtifactWorker(QThread):
    progress = pyqtSignal(int, int, str)
    result   = pyqtSignal(str, list)
    finished = pyqtSignal()

    def __init__(self, names, target_path=None, target_type="local"):
        super().__init__()
        self.names       = names
        self.target_path = target_path
        self.target_type = target_type

    def run(self):
        total = len(self.names)
        for i, name in enumerate(self.names):
            self.progress.emit(i+1, total, name)
            rows = collect_artifact(name,
                                    target_path=self.target_path,
                                    target_type=self.target_type)
            self.result.emit(name, rows)
        self.finished.emit()


class HashWorker(QThread):
    done = pyqtSignal(str, str, str)

    def __init__(self, path):
        super().__init__()
        self.path = path

    def run(self):
        m = md5_path(self.path)
        s = sha256_path(self.path)
        self.done.emit(self.path, m, s)


# ══════════════════════════════════════════════════════════════
#  HEX VIEWER WIDGET
# ══════════════════════════════════════════════════════════════
class HexViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.data = b""
        self.offset = 0
        self.bytes_per_row = 16
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)
        tb = QWidget()
        tb.setStyleSheet(f"background:{C['bg3']};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(6,3,6,3)
        tbl.addWidget(QLabel("Offset:"))
        self.offset_edit = QLineEdit("0x00000000")
        self.offset_edit.setFixedWidth(110)
        self.offset_edit.returnPressed.connect(self._jump)
        tbl.addWidget(self.offset_edit)
        btn_prev = QPushButton("◀ Prev 4K")
        btn_next = QPushButton("Next 4K ▶")
        btn_prev.clicked.connect(self._prev_page)
        btn_next.clicked.connect(self._next_page)
        tbl.addWidget(btn_prev)
        tbl.addWidget(btn_next)
        self.size_label = QLabel("")
        self.size_label.setStyleSheet(f"color:{C['fg2']};")
        tbl.addWidget(self.size_label)
        tbl.addStretch()
        lay.addWidget(tb)
        hdr = QLabel(
            "  Offset    "
            "  00 01 02 03 04 05 06 07"
            "  08 09 0A 0B 0C 0D 0E 0F"
            "       ASCII"
        )
        hdr.setStyleSheet(
            f"background:{C['bg3']};color:{C['fg2']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:9pt;padding:3px 8px;"
            f"border-bottom:1px solid {C['border']};"
        )
        lay.addWidget(hdr)
        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setReadOnly(True)
        self.hex_edit.setStyleSheet(
            f"background:{C['bg']};color:{C['green']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:9pt;border:none;padding:4px 8px;"
        )
        self.hex_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lay.addWidget(self.hex_edit)

    def load_data(self, data: bytes):
        self.data = data
        self.offset = 0
        self.size_label.setText(f"  Size: {fmt_size(len(data))}")
        self._render()

    def load_file(self, path: str, max_bytes: int = 1 << 20):
        try:
            with open(path,"rb") as f:
                self.data = f.read(max_bytes)
            self.offset = 0
            self.size_label.setText(f"  {fmt_size(os.path.getsize(path))}")
            self._render()
        except Exception as e:
            self.hex_edit.setPlainText(f"[Cannot read: {e}]")

    def _render(self):
        PAGE = 4096
        chunk = self.data[self.offset:self.offset+PAGE]
        lines = []
        for i in range(0, len(chunk), self.bytes_per_row):
            row = chunk[i:i+self.bytes_per_row]
            hex_part = " ".join(f"{b:02X}" for b in row)
            hex_part = f"{hex_part:<{self.bytes_per_row*3}}"
            asc_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in row)
            lines.append(f"  {self.offset+i:08X}   {hex_part}   {asc_part}")
        self.hex_edit.setPlainText("\n".join(lines))
        self.offset_edit.setText(f"0x{self.offset:08X}")

    def _jump(self):
        try:
            self.offset = int(self.offset_edit.text(), 16)
            self._render()
        except ValueError:
            pass

    def _prev_page(self):
        self.offset = max(0, self.offset - 4096)
        self._render()

    def _next_page(self):
        self.offset = min(len(self.data) - 1, self.offset + 4096)
        self._render()


# ══════════════════════════════════════════════════════════════
#  CONTENT VIEWER WIDGET
# ══════════════════════════════════════════════════════════════
class ContentViewer(QWidget):
    MODES = ["Text", "Hex", "Image", "Metadata", "Strings"]

    def __init__(self):
        super().__init__()
        self._path = None
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)
        tb = QWidget()
        tb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(6,3,6,3)
        tbl.setSpacing(4)
        tbl.addWidget(QLabel("View:"))
        self._mode_btns = {}
        for m in self.MODES:
            btn = QPushButton(m)
            btn.setFixedHeight(24)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, mode=m: self._switch_mode(mode))
            tbl.addWidget(btn)
            self._mode_btns[m] = btn
        tbl.addStretch()
        self.info_label = QLabel("")
        self.info_label.setStyleSheet(f"color:{C['fg2']};font-size:8pt;")
        tbl.addWidget(self.info_label)
        lay.addWidget(tb)
        self.stack = QStackedWidget()
        self.text_view = QPlainTextEdit()
        self.text_view.setReadOnly(True)
        self.stack.addWidget(self.text_view)
        self.hex_view = HexViewer()
        self.stack.addWidget(self.hex_view)
        self.img_label = QLabel("No image")
        self.img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.img_scroll = QScrollArea()
        self.img_scroll.setWidget(self.img_label)
        self.img_scroll.setWidgetResizable(True)
        self.stack.addWidget(self.img_scroll)
        self.meta_table = QTableWidget(0, 2)
        self.meta_table.setHorizontalHeaderLabels(["Property","Value"])
        self.meta_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.meta_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.stack.addWidget(self.meta_table)
        self.strings_view = QPlainTextEdit()
        self.strings_view.setReadOnly(True)
        self.stack.addWidget(self.strings_view)
        lay.addWidget(self.stack)
        self._switch_mode("Text")

    def _switch_mode(self, mode):
        idx = self.MODES.index(mode) if mode in self.MODES else 0
        self.stack.setCurrentIndex(idx)
        for m, btn in self._mode_btns.items():
            btn.setChecked(m == mode)
        if self._path:
            self._load_for_mode(mode)

    def load_path(self, path: str):
        self._path = path
        mode = self.MODES[self.stack.currentIndex()]
        self._load_for_mode(mode)
        try:
            s = os.stat(path)
            self.info_label.setText(
                f"  {os.path.basename(path)}  |  {fmt_size(s.st_size)}  |  {detect_type(path)}")
        except Exception:
            self.info_label.setText(f"  {os.path.basename(path)}")

    def _load_for_mode(self, mode):
        if not self._path or not os.path.isfile(self._path):
            return
        if mode == "Text":
            try:
                with open(self._path, errors='replace') as f:
                    self.text_view.setPlainText(f.read(1<<20))
            except Exception as e:
                self.text_view.setPlainText(f"[Error: {e}]")
        elif mode == "Hex":
            self.hex_view.load_file(self._path)
        elif mode == "Image":
            pix = QPixmap(self._path)
            if pix.isNull():
                self.img_label.setText("Cannot display image.")
            else:
                scaled = pix.scaled(800, 600, Qt.AspectRatioMode.KeepAspectRatio,
                                    Qt.TransformationMode.SmoothTransformation)
                self.img_label.setPixmap(scaled)
        elif mode == "Metadata":
            self.meta_table.setRowCount(0)
            try:
                s = os.stat(self._path)
                for prop, val in [
                    ("Name",     os.path.basename(self._path)),
                    ("Path",     self._path),
                    ("Size",     fmt_size(s.st_size)),
                    ("Type",     detect_type(self._path)),
                    ("Created",  fmt_ts(s.st_ctime)),
                    ("Modified", fmt_ts(s.st_mtime)),
                    ("Accessed", fmt_ts(s.st_atime)),
                    ("MD5",      md5_path(self._path)),
                    ("SHA-256",  sha256_path(self._path)),
                ]:
                    r = self.meta_table.rowCount()
                    self.meta_table.insertRow(r)
                    self.meta_table.setItem(r, 0, QTableWidgetItem(prop))
                    self.meta_table.setItem(r, 1, QTableWidgetItem(str(val)))
            except Exception as e:
                r = self.meta_table.rowCount()
                self.meta_table.insertRow(r)
                self.meta_table.setItem(r, 0, QTableWidgetItem("Error"))
                self.meta_table.setItem(r, 1, QTableWidgetItem(str(e)))
        elif mode == "Strings":
            try:
                with open(self._path, "rb") as f:
                    data = f.read(1<<20)
                strings = re.findall(rb'[\x20-\x7E]{4,}', data)
                self.strings_view.setPlainText(
                    "\n".join(s.decode(errors='replace') for s in strings[:2000]))
            except Exception as e:
                self.strings_view.setPlainText(f"[Error: {e}]")

    def load_bytes(self, data: bytes, name: str = "data"):
        self.text_view.setPlainText(data.decode(errors='replace')[:1<<20])
        self.hex_view.load_data(data)
        strings = re.findall(rb'[\x20-\x7E]{4,}', data[:1<<20])
        self.strings_view.setPlainText(
            "\n".join(s.decode(errors='replace') for s in strings[:2000]))
        self.info_label.setText(f"  {name}  |  {fmt_size(len(data))}")


# ══════════════════════════════════════════════════════════════
#  EVIDENCE BROWSER  (classic 3-pane)
# ══════════════════════════════════════════════════════════════
class EvidenceBrowser(QWidget):
    def __init__(self, main_win):
        super().__init__()
        self.main = main_win
        self.current_dir = Path.home()
        self._expand_connected = False
        self._setup()
        self._populate_tree_root()
        self._load_dir(self.current_dir)

    def _setup(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)
        h_split = QSplitter(Qt.Orientation.Horizontal)
        h_split.setHandleWidth(2)
        left_w = QWidget()
        left_w.setMinimumWidth(200)
        left_w.setMaximumWidth(340)
        ll = QVBoxLayout(left_w)
        ll.setContentsMargins(0,0,0,0)
        ll.setSpacing(0)
        lh = QLabel("  EVIDENCE TREE")
        lh.setObjectName("section_header")
        ll.addWidget(lh)
        self.ev_tree = QTreeWidget()
        self.ev_tree.setHeaderHidden(True)
        self.ev_tree.setIndentation(14)
        self.ev_tree.setAnimated(True)
        self.ev_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.ev_tree.customContextMenuRequested.connect(self._tree_ctx)
        self.ev_tree.currentItemChanged.connect(self._on_tree_select)
        ll.addWidget(self.ev_tree)
        h_split.addWidget(left_w)
        v_split = QSplitter(Qt.Orientation.Vertical)
        v_split.setHandleWidth(2)
        right_top = QWidget()
        rtl = QVBoxLayout(right_top)
        rtl.setContentsMargins(0,0,0,0)
        rtl.setSpacing(0)
        pb = QWidget()
        pb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        pbl = QHBoxLayout(pb)
        pbl.setContentsMargins(6,3,6,3)
        btn_up = QPushButton("↑ Up")
        btn_up.setFixedWidth(50)
        btn_up.clicked.connect(self._go_up)
        pbl.addWidget(btn_up)
        self.path_edit = QLineEdit(str(self.current_dir))
        self.path_edit.returnPressed.connect(self._go_path)
        pbl.addWidget(self.path_edit, 1)
        rtl.addWidget(pb)
        fh = QLabel("  FILES")
        fh.setObjectName("section_header")
        rtl.addWidget(fh)
        self.file_table = QTableWidget(0, 4)
        self.file_table.setHorizontalHeaderLabels(["Name","Size","Type","Modified"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.file_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.file_table.setAlternatingRowColors(True)
        self.file_table.setSortingEnabled(True)
        self.file_table.cellDoubleClicked.connect(self._on_file_dbl)
        self.file_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self._file_ctx)
        rtl.addWidget(self.file_table)
        v_split.addWidget(right_top)
        self.content = ContentViewer()
        v_split.addWidget(self.content)
        v_split.setSizes([400, 300])
        h_split.addWidget(v_split)
        h_split.setSizes([260, 1180])
        lay.addWidget(h_split)

    def _make_item(self, text, color=None, data=None):
        item = QTreeWidgetItem([text])
        if color:
            item.setForeground(0, QBrush(QColor(color)))
        if data:
            item.setData(0, Qt.ItemDataRole.UserRole, data)
        return item

    def _populate_tree_root(self):
        self.ev_tree.clear()
        fs_root = self._make_item("📁  File System", color=C['fg'])
        fs_root.setData(0, Qt.ItemDataRole.UserRole, {"type":"group"})
        self.ev_tree.addTopLevelItem(fs_root)
        home_item = self._make_item(f"🏠  Home ({Path.home().name})",
                                    color=C['accent'],
                                    data={"type": "dir", "path": str(Path.home())})
        self._add_lazy_dir_child(home_item, str(Path.home()))
        fs_root.addChild(home_item)
        for part in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(part.mountpoint)
                label = f"💾  {part.device}  [{part.fstype}]  {u.percent:.0f}%"
                item = self._make_item(label, color=C['orange'],
                                       data={"type": "dir", "path": part.mountpoint})
                self._add_lazy_dir_child(item, str(part.mountpoint))
                fs_root.addChild(item)
            except Exception:
                pass
        self.img_root = self._make_item("🖴  Forensic Images", color=C['fg'])
        self.img_root.setData(0, Qt.ItemDataRole.UserRole, {"type":"group"})
        self.ev_tree.addTopLevelItem(self.img_root)
        self.remote_root = self._make_item("🌐  Remote Targets", color=C['fg'])
        self.remote_root.setData(0, Qt.ItemDataRole.UserRole, {"type":"group"})
        self.ev_tree.addTopLevelItem(self.remote_root)
        fs_root.setExpanded(True)

    def _add_lazy_dir_child(self, parent_item, dir_path):
        s = QTreeWidgetItem(["__lazy_dir__"])
        s.setData(0, Qt.ItemDataRole.UserRole,
                  {"type": "sentinel_dir", "path": str(dir_path)})
        parent_item.addChild(s)
        if not self._expand_connected:
            self.ev_tree.itemExpanded.connect(self._on_item_expanded)
            self._expand_connected = True

    def _on_item_expanded(self, item):
        for i in range(item.childCount()):
            child = item.child(i)
            cd = child.data(0, Qt.ItemDataRole.UserRole) or {}
            if cd.get("type") == "sentinel_dir":
                item.removeChild(child)
                self._expand_dir_in_tree(item, cd["path"])
                break

    def _expand_dir_in_tree(self, parent, dir_path):
        try:
            entries = sorted(os.scandir(dir_path),
                             key=lambda e: (not e.is_dir(), e.name.lower()))
            for entry in entries[:200]:
                if entry.is_dir():
                    child = self._make_item(f"📁  {entry.name}", color=C['fg'],
                                            data={"type":"dir","path":entry.path})
                    self._add_lazy_dir_child(child, entry.path)
                    parent.addChild(child)
        except Exception:
            pass

    def add_evidence_image(self, path):
        is_dir = os.path.isdir(path)
        if is_dir:
            label = f"💾  {os.path.basename(path) or path}"
            item = self._make_item(label, color=C['orange'],
                                   data={"type": "dir", "path": path})
            self._add_lazy_dir_child(item, path)
        else:
            label = f"🖴  {os.path.basename(path)}"
            item = self._make_item(label, color=C['orange'],
                                   data={"type": "image", "path": path})
        self.img_root.addChild(item)
        self.img_root.setExpanded(True)

    def add_remote_target(self, target):
        item = self._make_item(f"🌐  {target}", color=C['purple'],
                               data={"type":"remote","label":target})
        self.remote_root.addChild(item)
        self.remote_root.setExpanded(True)

    def _on_tree_select(self, current, previous):
        if not current: return
        data = current.data(0, Qt.ItemDataRole.UserRole) or {}
        t = data.get("type")
        if t == "dir":
            self._load_dir(Path(data["path"]))

    def _load_dir(self, path: Path):
        try:
            self.current_dir = path
            self.path_edit.setText(str(path))
            self.file_table.setSortingEnabled(False)
            self.file_table.setRowCount(0)
            entries = sorted(path.iterdir(),
                             key=lambda e: (not e.is_dir(), e.name.lower()))
            for entry in entries:
                try:
                    s = entry.stat()
                    r = self.file_table.rowCount()
                    self.file_table.insertRow(r)
                    icon = "📁" if entry.is_dir() else self._file_icon(entry.name)
                    name_item = QTableWidgetItem(f"{icon}  {entry.name}")
                    name_item.setData(Qt.ItemDataRole.UserRole, entry.name)
                    self.file_table.setItem(r, 0, name_item)
                    self.file_table.setItem(r, 1, QTableWidgetItem(
                        "" if entry.is_dir() else fmt_size(s.st_size)))
                    self.file_table.setItem(r, 2, QTableWidgetItem(
                        "Directory" if entry.is_dir() else detect_type(str(entry))))
                    self.file_table.setItem(r, 3, QTableWidgetItem(fmt_ts(s.st_mtime)))
                except Exception:
                    pass
            self.file_table.setSortingEnabled(True)
        except PermissionError:
            pass
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _on_file_dbl(self, row, col):
        name_item = self.file_table.item(row, 0)
        if not name_item: return
        name = name_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(name, str):
            name = name_item.text().strip().lstrip("📁📄📝🔖🗄🖴📋🔑🔗⚡").strip()
        path = self.current_dir / name
        if path.is_dir():
            self._load_dir(path)
        elif path.is_file():
            self.content.load_path(str(path))

    def _file_ctx(self, pos):
        row = self.file_table.rowAt(pos.y())
        if row < 0: return
        name_item = self.file_table.item(row, 0)
        if not name_item: return
        name = name_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(name, str):
            name = name_item.text().strip().lstrip("📁📄📝🔖🗄🖴📋🔑🔗⚡").strip()
        path = self.current_dir / name
        menu = QMenu(self)
        menu.addAction("Open / Navigate",
            lambda: self._load_dir(path) if path.is_dir() else self.content.load_path(str(path)))
        if path.is_file():
            if path.suffix.lower() in (".pst",".ost",".msg",".mbox",".eml"):
                menu.addAction("📧 Open in Email Viewer",
                    lambda: self.main.email_tab.open_file(str(path)))
            menu.addSeparator()
            menu.addAction("Compute Hashes…", lambda: self._hash_file(path))
        menu.exec(self.file_table.viewport().mapToGlobal(pos))

    def _tree_ctx(self, pos):
        item = self.ev_tree.itemAt(pos)
        if not item: return
        menu = QMenu(self)
        menu.addAction("Remove",
            lambda: item.parent().removeChild(item) if item.parent() else None)
        menu.exec(self.ev_tree.mapToGlobal(pos))

    def _file_icon(self, name):
        ext = os.path.splitext(name)[1].lower()
        icons = {
            ".py":"📜",".ts":"📜",".sh":"📜",".bat":"📜",".ps1":"📜",
            ".txt":"📝",".log":"📝",".md":"📝",
            ".xml":"🔖",".json":"🔖",".csv":"🔖",
            ".db":"🗄",".sqlite":"🗄",
            ".e01":"🖴",".dd":"🖴",".img":"🖴",".raw":"🖴",".vmdk":"🖴",
            ".evtx":"📋",".reg":"🔑",".lnk":"🔗",".pf":"⚡",
        }
        return icons.get(ext, "📄")

    def _go_up(self):
        self._load_dir(self.current_dir.parent)

    def _go_path(self):
        p = Path(self.path_edit.text())
        if p.is_dir():
            self._load_dir(p)
        else:
            QMessageBox.warning(self, "Not found", f"Directory not found:\n{p}")

    def _hash_file(self, path):
        if not path.is_file():
            QMessageBox.information(self, "Hash", "Select a file first."); return
        dlg = QMessageBox(self)
        dlg.setWindowTitle("Computing hashes…")
        dlg.setText(f"Computing MD5 & SHA-256 for:\n{path.name}\nPlease wait…")
        dlg.setStandardButtons(QMessageBox.StandardButton.NoButton)
        dlg.show()
        QApplication.processEvents()
        m = md5_path(str(path))
        s = sha256_path(str(path))
        dlg.hide()
        QMessageBox.information(self, "Hash Result",
            f"File: {path.name}\n\nMD5:\n{m}\n\nSHA-256:\n{s}")


# ══════════════════════════════════════════════════════════════
#  ARTIFACT SELECTION TAB
# ══════════════════════════════════════════════════════════════
class ArtifactTab(QWidget):
    process_requested = pyqtSignal(list, str, str)

    def __init__(self):
        super().__init__()
        self._checks   = {}
        self._evidence = []
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12,8,12,8)
        tgt_grp = QGroupBox("Evidence Target")
        tgt_grp.setStyleSheet(f"QGroupBox{{color:{C['accent']};font-weight:bold;}}")
        tgl = QVBoxLayout(tgt_grp)
        tgl.setSpacing(4)
        tgt_hdr = QHBoxLayout()
        tgt_hdr.addWidget(QLabel("Collect from:"))
        self.target_combo = QComboBox()
        self.target_combo.addItem("🖥  Local System (live collection)", ("local", None))
        self.target_combo.setMinimumWidth(400)
        self.target_combo.currentIndexChanged.connect(self._on_target_changed)
        tgt_hdr.addWidget(self.target_combo, 1)
        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.setFixedWidth(80)
        refresh_btn.clicked.connect(self.refresh_evidence_list)
        tgt_hdr.addWidget(refresh_btn)
        tgl.addLayout(tgt_hdr)
        self.target_info = QLabel("  Live collection from the local system")
        self.target_info.setStyleSheet(f"color:{C['fg2']};font-size:8pt;padding:2px 4px;")
        tgl.addWidget(self.target_info)
        lay.addWidget(tgt_grp)
        hdr = QHBoxLayout()
        title = QLabel("SELECT ARTIFACTS TO COLLECT")
        title.setStyleSheet(f"color:{C['accent']};font-size:10pt;font-weight:bold;")
        hdr.addWidget(title)
        hdr.addStretch()
        for label, slot in [("✓ All", self._sel_all),
                             ("✗ None", self._sel_none),
                             ("⚡ IR Preset", self._preset_ir),
                             ("🦠 Malware", self._preset_malware),
                             ("📧 Email Preset", self._preset_email)]:
            btn = QPushButton(label)
            btn.setFixedHeight(28)
            hdr.addWidget(btn)
            btn.clicked.connect(slot)
        proc_btn = QPushButton("▶  Process Selected Artifacts")
        proc_btn.setObjectName("accent")
        proc_btn.setFixedHeight(32)
        proc_btn.clicked.connect(self._emit_process)
        hdr.addWidget(proc_btn)
        lay.addLayout(hdr)
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.Shape.HLine)
        lay.addWidget(sep)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea{{border:none;background:{C['bg']}}}")
        inner = QWidget()
        inner.setStyleSheet(f"background:{C['bg']};")
        grid = QVBoxLayout(inner)
        grid.setSpacing(2)
        for cat, arts in ARTIFACT_CATEGORIES.items():
            cat_label = QLabel(f"  {cat}")
            cat_label.setStyleSheet(
                f"background:{C['bg3']};color:{C['accent']};"
                f"font-weight:bold;font-size:9pt;padding:5px 8px;"
                f"border-left:3px solid {C['accent']};margin-top:8px;")
            grid.addWidget(cat_label)
            row_widget = QWidget()
            row_widget.setStyleSheet(f"background:{C['bg']};")
            row_layout = QGridLayout(row_widget)
            row_layout.setContentsMargins(8,2,8,2)
            row_layout.setSpacing(2)
            for i, art in enumerate(arts):
                cb = QCheckBox(art)
                cb.setStyleSheet(f"color:{C['fg']};padding:2px 4px;")
                row_layout.addWidget(cb, i//3, i%3)
                self._checks[art] = cb
            grid.addWidget(row_widget)
        grid.addStretch()
        scroll.setWidget(inner)
        lay.addWidget(scroll)

    def _on_target_changed(self, idx):
        data = self.target_combo.itemData(idx)
        if data:
            ttype, tpath = data
            if ttype == "local":
                self.target_info.setText("  Live collection from the local system")
            elif ttype == "directory":
                self.target_info.setText(f"  Directory: {tpath}")
            else:
                self.target_info.setText(f"  {ttype}: {tpath or ''}")

    def refresh_evidence_list(self, items=None):
        if items is None:
            items = getattr(self, '_evidence', [])
        self._evidence = items
        while self.target_combo.count() > 1:
            self.target_combo.removeItem(1)
        for item in items:
            label = item.get("label","")
            ttype = item.get("type","directory")
            tpath = item.get("path","")
            self.target_combo.addItem(f"📁  {label}", (ttype, tpath))

    def _sel_all(self):
        for cb in self._checks.values(): cb.setChecked(True)

    def _sel_none(self):
        for cb in self._checks.values(): cb.setChecked(False)

    def _preset_ir(self):
        self._sel_none()
        for a in ["Running Processes","Active Connections","Network Interfaces",
                  "OS Version & Build","Hostname & Domain","System Uptime",
                  "Local User Accounts","Recently Accessed Files","Temp Directory Contents"]:
            if a in self._checks: self._checks[a].setChecked(True)

    def _preset_malware(self):
        self._sel_none()
        for a in ["Running Processes","Active Connections","Registry Run Keys",
                  "Scheduled Tasks","Services (Auto-Start)","Prefetch Files",
                  "Recently Accessed Files","Loaded Drivers/Modules","WMI Subscriptions"]:
            if a in self._checks: self._checks[a].setChecked(True)

    def _preset_email(self):
        self._sel_none()
        for a in ["PST/OST Files (Outlook)","MSG Files (Outlook)","Thunderbird MBOX",
                  "Email Accounts Config","Email Attachments",
                  "Email Contacts","Email Calendar Items","Browser History"]:
            if a in self._checks: self._checks[a].setChecked(True)

    def _emit_process(self):
        selected = [n for n,cb in self._checks.items() if cb.isChecked()]
        if not selected:
            QMessageBox.warning(self,"Nothing selected","Select at least one artifact.")
            return
        data  = self.target_combo.currentData() or ("local", None)
        ttype = data[0]
        tpath = data[1] or ""
        self.process_requested.emit(selected, tpath, ttype)

    def get_selected(self):
        return [n for n,cb in self._checks.items() if cb.isChecked()]


# ══════════════════════════════════════════════════════════════
#  RESULTS TAB
#  CHANGES: added bookmark_requested signal, right-click on art_list,
#           preview panel below result table
# ══════════════════════════════════════════════════════════════
class ResultsTab(QWidget):
    # ── NEW: signal to forward bookmarks to the BookmarkTab ──────────
    bookmark_requested = pyqtSignal(str, dict)   # tag, item_data

    def __init__(self):
        super().__init__()
        self.results = {}
        self._setup()

    def _setup(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)

        # Left: artifact list
        left = QWidget()
        left.setMinimumWidth(180)
        left.setMaximumWidth(260)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0,0,0,0)
        ll.setSpacing(0)

        lh = QLabel("  COLLECTED")
        lh.setObjectName("section_header")
        ll.addWidget(lh)

        self.art_list = QListWidget()
        self.art_list.currentRowChanged.connect(self._on_select)
        # ── NEW: right-click to bookmark an artifact ─────────────────
        self.art_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.art_list.customContextMenuRequested.connect(self._art_list_ctx)
        ll.addWidget(self.art_list)

        # Export buttons
        exp_w = QWidget()
        exp_w.setStyleSheet(f"background:{C['bg3']};border-top:1px solid {C['border']};")
        expl = QVBoxLayout(exp_w)
        expl.setContentsMargins(6,4,6,4)
        expl.setSpacing(3)
        for label, slot in [("Export CSV",  self._export_csv),
                             ("Export JSON", self._export_json),
                             ("Export HTML Report", self._export_html)]:
            b = QPushButton(label)
            b.setFixedHeight(26)
            b.clicked.connect(slot)
            expl.addWidget(b)
        ll.addWidget(exp_w)
        split.addWidget(left)

        # Right: vertical splitter — table on top, preview on bottom
        right_split = QSplitter(Qt.Orientation.Vertical)
        right_split.setHandleWidth(2)

        # ── Top: result table ────────────────────────────────────────
        right_top = QWidget()
        rl = QVBoxLayout(right_top)
        rl.setContentsMargins(0,0,0,0)
        rl.setSpacing(0)

        self.result_header = QLabel("  Select an artifact from the list")
        self.result_header.setObjectName("section_header")
        self.result_header.setStyleSheet(
            f"background:{C['bg3']};color:{C['fg']};font-size:9pt;"
            f"font-weight:bold;padding:5px 10px;"
        )
        rl.addWidget(self.result_header)

        # Search bar
        sb = QWidget()
        sb.setStyleSheet(f"background:{C['bg3']};")
        sbl = QHBoxLayout(sb)
        sbl.setContentsMargins(6,3,6,3)
        sbl.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Type to filter rows…")
        self.filter_edit.textChanged.connect(self._filter_rows)
        sbl.addWidget(self.filter_edit)
        self.row_count_label = QLabel("")
        self.row_count_label.setStyleSheet(f"color:{C['fg2']};")
        sbl.addWidget(self.row_count_label)
        rl.addWidget(sb)

        self.result_table = QTableWidget(0, 1)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.result_table.setSortingEnabled(True)
        # ── NEW: row selection updates preview panel ─────────────────
        self.result_table.currentCellChanged.connect(self._on_table_row_changed)
        # ── NEW: right-click to bookmark a row ───────────────────────
        self.result_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.result_table.customContextMenuRequested.connect(self._table_ctx)
        rl.addWidget(self.result_table)

        # Progress
        self.progress = QProgressBar()
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        rl.addWidget(self.progress)

        right_split.addWidget(right_top)

        # ── Bottom: item preview panel (NEW) ─────────────────────────
        preview_w = QWidget()
        pvl = QVBoxLayout(preview_w)
        pvl.setContentsMargins(0,0,0,0)
        pvl.setSpacing(0)

        pv_hdr = QLabel("  ITEM PREVIEW")
        pv_hdr.setStyleSheet(
            f"background:{C['header']};color:{C['fg2']};font-size:8pt;"
            f"font-weight:bold;padding:3px 10px;"
            f"border-top:1px solid {C['border']};"
        )
        pvl.addWidget(pv_hdr)

        self.preview_text = QPlainTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setMaximumHeight(130)
        self.preview_text.setStyleSheet(
            f"background:{C['bg']};color:{C['fg2']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:8pt;border:none;"
        )
        pvl.addWidget(self.preview_text)

        right_split.addWidget(preview_w)
        right_split.setSizes([500, 130])

        split.addWidget(right_split)
        split.setSizes([220, 900])
        lay.addWidget(split)

    # ── NEW: right-click on artifact list ────────────────────────────
    def _art_list_ctx(self, pos):
        item = self.art_list.itemAt(pos)
        if not item: return
        art_name = item.text().strip()
        menu = QMenu(self)
        bm_menu = menu.addMenu("🔖 Add Bookmark")
        for tag in ["🚨 Suspicious", "📌 Evidence", "✅ Reviewed",
                    "⭐ Important", "🔴 Flagged", "📝 Notes"]:
            bm_menu.addAction(tag, lambda t=tag, n=art_name:
                self.bookmark_requested.emit(t, {
                    "type":      "artifact",
                    "name":      n,
                    "tag":       t,
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "records":   len(self.results.get(n, [])),
                    "preview":   str(self.results.get(n, [{}])[0])[:120]
                                 if self.results.get(n) else "",
                }))
        menu.exec(self.art_list.viewport().mapToGlobal(pos))

    # ── NEW: right-click on result table row ─────────────────────────
    def _table_ctx(self, pos):
        row = self.result_table.currentRow()
        if row < 0: return
        row_data = {}
        for c in range(self.result_table.columnCount()):
            h = self.result_table.horizontalHeaderItem(c)
            key = h.text() if h else str(c)
            cell = self.result_table.item(row, c)
            row_data[key] = cell.text() if cell else ""
        art_name = self.result_header.text().split("—")[0].strip().lstrip()
        menu = QMenu(self)
        bm_menu = menu.addMenu("🔖 Add Bookmark")
        for tag in ["🚨 Suspicious", "📌 Evidence", "✅ Reviewed",
                    "⭐ Important", "🔴 Flagged", "📝 Notes"]:
            bm_menu.addAction(tag, lambda t=tag, rd=row_data.copy():
                self.bookmark_requested.emit(t, {
                    "type":      "row",
                    "name":      art_name,
                    "tag":       t,
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "data":      rd,
                    "preview":   " | ".join(f"{k}={v}" for k,v in rd.items())[:120],
                }))
        menu.exec(self.result_table.viewport().mapToGlobal(pos))

    # ── NEW: update preview when table row changes ────────────────────
    def _on_table_row_changed(self, cur_row, cur_col, prev_row, prev_col):
        if cur_row < 0: return
        try:
            lines = []
            for c in range(self.result_table.columnCount()):
                h = self.result_table.horizontalHeaderItem(c)
                key = h.text() if h else str(c)
                cell = self.result_table.item(cur_row, c)
                val = cell.text() if cell else ""
                lines.append(f"  {key:<28} {val}")
            self.preview_text.setPlainText("\n".join(lines))
        except Exception:
            pass

    # ── All methods below are ORIGINAL / UNCHANGED ───────────────────

    def add_result(self, name: str, rows: list):
        self.results[name] = rows
        item = QListWidgetItem(f"  {name}")
        item.setForeground(QBrush(QColor(C['green'])))
        item.setToolTip(f"{len(rows)} record(s)")
        self.art_list.addItem(item)
        self.art_list.blockSignals(True)
        self.art_list.setCurrentRow(self.art_list.count() - 1)
        self.art_list.blockSignals(False)
        self._show_result(name, rows)

    def set_progress(self, val: int):
        self.progress.setValue(val)

    def clear_all(self):
        self.results.clear()
        self.art_list.clear()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(1)
        self.progress.setValue(0)
        self.preview_text.clear()

    def _on_select(self, row):
        if row < 0: return
        name = self.art_list.item(row).text().strip()
        rows = self.results.get(name, [])
        self._show_result(name, rows)

    def _show_result(self, name: str, rows: list):
        self.result_header.setText(f"  {name}  —  {len(rows)} record(s)")
        self._populate_table(rows)

    def _populate_table(self, rows):
        self.result_table.setSortingEnabled(False)
        self.result_table.clearContents()
        self.result_table.setRowCount(0)

        if not rows:
            self.result_table.setColumnCount(1)
            self.result_table.setHorizontalHeaderLabels(["No data"])
            self.row_count_label.setText("0 rows")
            return

        all_keys = []
        seen = set()
        for row in rows:
            for k in row.keys():
                if k not in seen:
                    all_keys.append(k)
                    seen.add(k)

        self.result_table.setColumnCount(len(all_keys))
        self.result_table.setHorizontalHeaderLabels(all_keys)

        hdr = self.result_table.horizontalHeader()
        for i in range(len(all_keys)):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        if all_keys:
            hdr.setSectionResizeMode(len(all_keys) - 1, QHeaderView.ResizeMode.Stretch)

        self.result_table.setRowCount(len(rows))
        for r_idx, row in enumerate(rows):
            for c_idx, col in enumerate(all_keys):
                val = str(row.get(col, ""))
                cell = QTableWidgetItem(val)
                cell.setForeground(QBrush(QColor(C['fg'])))
                self.result_table.setItem(r_idx, c_idx, cell)

        self.result_table.setSortingEnabled(True)
        self.row_count_label.setText(f"{len(rows)} rows")
        self._filter_rows(self.filter_edit.text())

    def _filter_rows(self, text):
        text = text.lower()
        for row in range(self.result_table.rowCount()):
            match = not text or any(
                text in (self.result_table.item(row,col).text()
                         if self.result_table.item(row,col) else "").lower()
                for col in range(self.result_table.columnCount())
            )
            self.result_table.setRowHidden(row, not match)
        vis = sum(1 for r in range(self.result_table.rowCount())
                  if not self.result_table.isRowHidden(r))
        self.row_count_label.setText(f"{vis} / {self.result_table.rowCount()} rows")

    def _current_rows(self):
        name = ""
        if self.art_list.currentItem():
            name = self.art_list.currentItem().text().strip()
        return self.results.get(name, []), name

    def _export_csv(self):
        rows, name = self._current_rows()
        if not rows: return
        path, _ = QFileDialog.getSaveFileName(self,"Export CSV","","CSV (*.csv)")
        if not path: return
        with open(path,"w",newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader(); w.writerows(rows)

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(self,"Export JSON","","JSON (*.json)")
        if not path: return
        with open(path,"w") as f:
            json.dump(self.results, f, indent=2, default=str)

    def _export_html(self):
        path, _ = QFileDialog.getSaveFileName(self,"Export HTML Report","","HTML (*.html)")
        if not path: return
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<!DOCTYPE html><html><head>
<meta charset="utf-8">
<title>ForensicPro Report — {now}</title>
<style>
body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',sans-serif;margin:32px}}
h1{{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:8px}}
h2{{color:#3fb950;margin-top:24px;border-left:4px solid #3fb950;padding-left:10px}}
table{{border-collapse:collapse;width:100%;margin:8px 0 20px}}
th{{background:#21262d;color:#8b949e;padding:6px 10px;text-align:left;font-size:0.85em}}
td{{padding:5px 10px;border-bottom:1px solid #21262d;font-size:0.9em}}
tr:nth-child(even){{background:#1a2030}}
tr:hover td{{background:#1f3354}}
.badge{{background:#1f3354;color:#58a6ff;border-radius:10px;padding:2px 8px;font-size:0.8em;margin-left:8px}}
.meta{{color:#8b949e;font-size:0.85em;margin-bottom:24px}}
</style></head><body>
<h1>🔍 ForensicPro Enterprise — Digital Forensic Report</h1>
<p class="meta">Generated: {now} | ForensicPro v{APP_VERSION}</p>
"""
        for art, rows in self.results.items():
            html += f'<h2>{art} <span class="badge">{len(rows)}</span></h2>'
            if rows:
                cols = list(rows[0].keys())
                html += "<table><tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>"
                for row in rows:
                    html += "<tr>" + "".join(f"<td>{row.get(c,'')}</td>" for c in cols) + "</tr>"
                html += "</table>"
        html += "</body></html>"
        with open(path,"w") as f: f.write(html)
        QMessageBox.information(self,"Exported", f"Report saved:\n{path}")


# ══════════════════════════════════════════════════════════════
#  TIMELINE TAB
# ══════════════════════════════════════════════════════════════
class TimelineTab(QWidget):
    def __init__(self):
        super().__init__()
        self._all_rows = []
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)
        hdr = QLabel("  TIMELINE")
        hdr.setObjectName("section_header")
        lay.addWidget(hdr)
        fb = QWidget()
        fb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        fbl = QHBoxLayout(fb)
        fbl.setContentsMargins(6,3,6,3)
        fbl.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search timeline…")
        self.filter_edit.textChanged.connect(self._filter)
        fbl.addWidget(self.filter_edit, 1)
        fbl.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All","Process","Network","File","User","System"])
        self.type_combo.currentIndexChanged.connect(self._filter)
        fbl.addWidget(self.type_combo)
        self.count_label = QLabel("")
        self.count_label.setStyleSheet(f"color:{C['fg2']};")
        fbl.addWidget(self.count_label)
        lay.addWidget(fb)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp","Type","Source","Description"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(self.table)

    def build_from(self, artifact_results: dict):
        self._all_rows = []
        ts_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        TYPE_MAP = {
            "Running Processes": "Process", "Active Connections": "Network",
            "Browser History": "Network", "Security Event Log": "System",
            "System Event Log": "System", "Recently Accessed Files": "File",
            "Local User Accounts": "User", "Last Login Times": "User",
        }
        for art, rows in artifact_results.items():
            etype = TYPE_MAP.get(art, "System")
            for row in rows:
                ts = next((str(v) for k, v in row.items()
                           if any(x in k.lower() for x in ("time","date","stamp","boot"))), ts_now)
                desc = "  |  ".join(f"{k}: {v}" for k,v in list(row.items())[:4])
                self._all_rows.append((ts, etype, art, desc))
        self._all_rows.sort(key=lambda x: x[0])
        self._filter()

    def _filter(self, *_):
        text  = self.filter_edit.text().lower()
        etype = self.type_combo.currentText()
        self.table.setRowCount(0)
        TYPE_COLORS = {
            "Process": C['green'], "Network": C['orange'],
            "File":    C['accent'], "User": C['purple'], "System": C['fg'],
        }
        for ts, et, src, desc in self._all_rows:
            if etype != "All" and et != etype: continue
            if text and not any(text in x.lower() for x in (ts,et,src,desc)): continue
            r = self.table.rowCount()
            self.table.insertRow(r)
            color = TYPE_COLORS.get(et, C['fg'])
            for c, val in enumerate((ts,et,src,desc)):
                item = QTableWidgetItem(val)
                item.setForeground(QBrush(QColor(color if c < 2 else C['fg'])))
                self.table.setItem(r, c, item)
        self.count_label.setText(f"{self.table.rowCount()} events")


# ══════════════════════════════════════════════════════════════
#  REMOTE AGENT TAB
# ══════════════════════════════════════════════════════════════
class AgentTab(QWidget):
    def __init__(self, art_tab: ArtifactTab):
        super().__init__()
        self.art_tab = art_tab
        self._code = ""
        self._setup()

    def _setup(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)
        cfg_scroll = QScrollArea()
        cfg_scroll.setWidgetResizable(True)
        cfg_scroll.setMinimumWidth(300)
        cfg_scroll.setMaximumWidth(380)
        cfg_scroll.setStyleSheet(f"QScrollArea{{border:none;background:{C['bg2']}}}")
        cfg = QWidget()
        cfg.setStyleSheet(f"background:{C['bg2']};")
        cl = QVBoxLayout(cfg)
        cl.setContentsMargins(12,12,12,12)
        cl.setSpacing(6)
        def section(title):
            l = QLabel(title)
            l.setStyleSheet(
                f"color:{C['accent']};font-weight:bold;font-size:9pt;"
                f"border-bottom:1px solid {C['border']};padding-bottom:4px;margin-top:10px;")
            cl.addWidget(l)
        def field(label, attr, default="", password=False):
            cl.addWidget(QLabel(label))
            le = QLineEdit(default)
            if password: le.setEchoMode(QLineEdit.EchoMode.Password)
            setattr(self, attr, le)
            cl.addWidget(le)
        section("CASE INFORMATION")
        field("Case Name",    "f_case_name",   "Investigation-001")
        field("Case ID",      "f_case_id",     "FC-2025-001")
        field("Examiner",     "f_examiner",    "")
        section("DEPLOYMENT")
        field("Output Dir (remote)", "f_output_dir", "/tmp/forensic_out")
        field("C2 Server (host:port, optional)", "f_server", "")
        section("SSH DEPLOYMENT")
        field("SSH Target (user@host)", "f_ssh_target", "")
        field("SSH Password / Key Path","f_ssh_pass",   "", password=True)
        section("AGENT OPTIONS")
        cl.addWidget(QLabel("Artifact Preset"))
        self.f_preset = QComboBox()
        self.f_preset.addItems(["Use Current Selection","Quick Triage",
                                  "Full Collection","Incident Response","Malware Hunt"])
        cl.addWidget(self.f_preset)
        section("ACTIONS")
        for label, method in [
            ("⚙  Generate Agent Code",  self._generate),
            ("💾  Save Agent File…",     self._save),
            ("🚀  Deploy via SSH",       self._deploy_ssh),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(32)
            if "Generate" in label: btn.setObjectName("accent")
            btn.clicked.connect(method)
            cl.addWidget(btn)
        cl.addStretch()
        cfg_scroll.setWidget(cfg)
        split.addWidget(cfg_scroll)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0,0,0,0)
        rl.setSpacing(0)
        rh = QLabel("  GENERATED AGENT CODE")
        rh.setObjectName("section_header")
        rl.addWidget(rh)
        self.code_edit = QPlainTextEdit()
        self.code_edit.setStyleSheet(
            f"background:{C['bg']};color:{C['green']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:9pt;border:none;padding:8px;")
        self.code_edit.setPlainText("# Configure the settings on the left,\n"
                                    "# then click 'Generate Agent Code'.\n")
        rl.addWidget(self.code_edit)
        split.addWidget(right)
        split.setSizes([340, 900])
        lay.addWidget(split)

    def _get_artifacts(self):
        preset = self.f_preset.currentText()
        if preset == "Quick Triage":
            return ["OS Version & Build","Running Processes","Active Connections","Local User Accounts"]
        elif preset == "Full Collection":
            return [a for cat in ARTIFACT_CATEGORIES.values() for a in cat]
        elif preset == "Incident Response":
            return ["Running Processes","Active Connections","Network Interfaces",
                    "OS Version & Build","Hostname & Domain","System Uptime","Local User Accounts"]
        elif preset == "Malware Hunt":
            return ["Running Processes","Active Connections","Registry Run Keys",
                    "Scheduled Tasks","Loaded Drivers/Modules","Services (Auto-Start)"]
        else:
            arts = self.art_tab.get_selected()
            return arts or ["OS Version & Build","Running Processes"]

    def _generate(self):
        arts = self._get_artifacts()
        ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._code = AGENT_TEMPLATE.format(
            version         = APP_VERSION,
            timestamp       = ts,
            case_name       = self.f_case_name.text() or "Case",
            case_id         = self.f_case_id.text() or "FC-001",
            examiner        = self.f_examiner.text() or "Examiner",
            artifacts_brief = ", ".join(arts[:5]) + (f" +{len(arts)-5} more" if len(arts)>5 else ""),
            artifacts_json  = json.dumps(arts),
            output_dir      = self.f_output_dir.text() or "/tmp/forensic_out",
            server          = self.f_server.text() or "",
        )
        self.code_edit.setPlainText(self._code)

    def _save(self):
        if not self._code:
            self._generate()
        path, _ = QFileDialog.getSaveFileName(self, "Save Agent", "forensic_agent.py",
                                               "Python (*.py);;All (*)")
        if path:
            with open(path,"w") as f: f.write(self._code)
            QMessageBox.information(self, "Saved", f"Agent saved to:\n{path}")

    def _deploy_ssh(self):
        QMessageBox.information(self,"SSH Deploy",
            "SSH deployment:\n1. Save the agent script.\n"
            "2. Copy to remote host via scp.\n"
            "3. Execute with python3 on the remote host.")


# ══════════════════════════════════════════════════════════════
#  EMAIL VIEWER TAB
#  FIXES (v4.1):
#   1. __init__: initialise all 6 missing state attrs so _close_current
#      doesn't AttributeError on first call.
#   2. _setup: replace broken header_box/body_box right-panel with a
#      proper QTabWidget (preview_tabs) containing body_view (QTextEdit),
#      header_view (QTableWidget), attach tab, raw_view. Keep compat
#      aliases so the original _display_msg_raw / _display_mbox_msg work.
#   3. _on_folder_select: detect list-of-records vs pypff folder; delegate
#      to new _load_message_list helper instead of crashing.
#   4. _load_folder_messages: extract all data to plain dicts immediately;
#      never store live pypff refs in msg_rows.
#   5. _render_msg_table: implement the method called by existing code.
#   6. _on_message_select: use self.msg_rows and call _display_message
#      safely for all format types.
#   7. _msg_ctx: use self.msg_rows (safe dict access).
# ══════════════════════════════════════════════════════════════
class EmailViewerTab(QWidget):
    def __init__(self):
        super().__init__()
        self._pst      = None   # open pypff.file handle
        self._tmp_path = None   # temp file path for extracted images
        # ── FIX: initialise ALL state attrs before _setup() ──────────
        self.current_store  = None   # dict describing the open store
        self.msg_rows       = []     # list of normalised message dicts
        self._folder_map    = {}     # id(tree item) → folder/message list
        self._messages      = []     # alias kept for compat (= msg_rows)
        self._all_messages  = []     # alias kept for compat
        self._current_msg   = None
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        # ── Top toolbar ──────────────────────────────────────────────
        tb = QWidget()
        tb.setMaximumHeight(60)
        tb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(8,4,8,4)
        tbl.setSpacing(6)

        open_btn = QPushButton("📂 Open Email File…")
        open_btn.clicked.connect(self._open_dialog)
        tbl.addWidget(open_btn)

        self.file_label = QLabel("No file loaded")
        self.file_label.setStyleSheet(f"color:{C['fg2']};font-size:9pt;")
        tbl.addWidget(self.file_label, 1)

        self.msg_count_label = QLabel("")
        self.msg_count_label.setStyleSheet(f"color:{C['accent']};font-size:9pt;")
        tbl.addWidget(self.msg_count_label)

        export_btn = QPushButton("💾 Export Selected")
        export_btn.clicked.connect(self._export_selected)
        tbl.addWidget(export_btn)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search messages…")
        self._search_edit.setFixedWidth(200)
        self._search_edit.textChanged.connect(self._filter_messages)
        tbl.addWidget(self._search_edit)

        lay.addWidget(tb)

        # ── Main splitter ────────────────────────────────────────────
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)

        # ── Left: folder tree ────────────────────────────────────────
        left = QWidget()
        left.setMinimumWidth(160)
        left.setMaximumWidth(260)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0,0,0,0)
        ll.setSpacing(0)

        lh = QLabel("  FOLDERS")
        lh.setObjectName("section_header")
        ll.addWidget(lh)

        self.folder_tree = QTreeWidget()
        self.folder_tree.setHeaderHidden(True)
        self.folder_tree.setStyleSheet(
            f"QTreeWidget{{background:{C['sidebar']};border:none;}}")
        self.folder_tree.itemClicked.connect(self._on_folder_select)
        self.folder_tree.currentItemChanged.connect(self._on_folder_select)
        ll.addWidget(self.folder_tree)

        split.addWidget(left)

        # ── Middle: message list ─────────────────────────────────────
        mid = QWidget()
        ml = QVBoxLayout(mid)
        ml.setContentsMargins(0,0,0,0)
        ml.setSpacing(0)

        mh = QLabel("  MESSAGES")
        mh.setObjectName("section_header")
        ml.addWidget(mh)

        self.msg_table = QTableWidget(0, 5)
        self.msg_table.setHorizontalHeaderLabels(
            ["From","Subject","Date","Size","Attachments"])
        self.msg_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        for c in (0,2,3,4):
            self.msg_table.horizontalHeader().setSectionResizeMode(
                c, QHeaderView.ResizeMode.ResizeToContents)
        self.msg_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.msg_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.msg_table.setAlternatingRowColors(True)
        self.msg_table.currentCellChanged.connect(self._on_message_select)
        self.msg_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.msg_table.customContextMenuRequested.connect(self._msg_ctx)
        ml.addWidget(self.msg_table)

        split.addWidget(mid)

        # ── Right: message preview ───────────────────────────────────
        # FIX: replace broken header_box/body_box with proper tabbed viewer
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0,0,0,0)
        rl.setSpacing(0)

        rh = QLabel("  MESSAGE CONTENT")
        rh.setObjectName("section_header")
        rl.addWidget(rh)

        self.preview_tabs = QTabWidget()

        # Tab 0 – Body
        self.body_view = QTextEdit()
        self.body_view.setReadOnly(True)
        self.body_view.setStyleSheet(
            f"background:{C['bg']};color:{C['fg']};border:none;"
            f"font-family:'Segoe UI',Arial,sans-serif;font-size:9pt;")
        self.preview_tabs.addTab(self.body_view, "📨 Body")

        # Tab 1 – Headers
        self.header_view = QTableWidget(0, 2)
        self.header_view.setHorizontalHeaderLabels(["Header","Value"])
        self.header_view.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.header_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.header_view.setAlternatingRowColors(True)
        self.preview_tabs.addTab(self.header_view, "📋 Headers")

        # Tab 2 – Attachments
        attach_w = QWidget()
        att_lay = QVBoxLayout(attach_w)
        att_lay.setContentsMargins(0,0,0,0)
        self.attach_list = QListWidget()
        att_lay.addWidget(self.attach_list)
        # attach_bar / _attach_lay kept for _display_msg_raw compat
        self.attach_bar = QWidget()
        self._attach_lay = QHBoxLayout(self.attach_bar)
        self._attach_lay.setContentsMargins(4,2,4,2)
        att_lay.addWidget(self.attach_bar)
        self.preview_tabs.addTab(attach_w, "📎 Attachments")

        # Tab 3 – Raw RFC822
        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setStyleSheet(
            f"background:{C['bg']};color:{C['green']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:8pt;border:none;")
        self.preview_tabs.addTab(self.raw_view, "📜 Raw")

        rl.addWidget(self.preview_tabs)

        # Backward-compat aliases for _display_mbox_msg / _display_msg_raw
        self.header_box = self.body_view   # both use body_view now
        self.body_box   = self.body_view

        split.addWidget(right)
        split.setSizes([220, 420, 700])
        lay.addWidget(split)

    # ── Helpers ──────────────────────────────────────────────────────

    def _safe_str(self, val):
        if val is None: return ""
        if isinstance(val, bytes): return val.decode(errors='replace')
        return str(val)

    # ── Open / close ─────────────────────────────────────────────────

    def _open_dialog(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Email File", "",
            "Email Files (*.pst *.ost *.msg *.mbox *.eml);;"
            "PST/OST (*.pst *.ost);;MSG (*.msg);;MBOX (*.mbox);;EML (*.eml);;All (*)")
        if path:
            self.open_file(path)

    def open_file(self, path, display_name=None):
        """Load an email file. Called externally too (e.g. from context menu)."""
        self._close_current()
        name = display_name or os.path.basename(path)
        self.file_label.setText(f"  {name}")
        ext  = os.path.splitext(path)[1].lower()
        try:
            if ext in (".pst", ".ost"):
                self._load_pst(path)
            elif ext == ".msg":
                self._load_single_msg(path)
            elif ext == ".mbox":
                self._load_mbox(path)
            elif ext == ".eml":
                self._load_eml(path)
            else:
                QMessageBox.warning(self, "Unsupported",
                    f"Unsupported format: {ext}\nSupported: PST, OST, MSG, MBOX, EML")
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self, "Open Error",
                f"Failed to open:\n{name}\n\n{e}")

    def _close_current(self):
        try:
            if self.current_store and self.current_store.get("type") == "pst":
                pst = self.current_store.get("pst")
                try:
                    if pst: pst.close()
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            self.current_store  = None
            self.msg_rows       = []
            self._messages      = []
            self._all_messages  = []
            self._folder_map    = {}
            try:
                self.folder_tree.clear()
                self.msg_table.setRowCount(0)
                self.preview_tabs.setCurrentIndex(0)
                self.body_view.clear()
                self.header_view.setRowCount(0)
                self.attach_list.clear()
                self.raw_view.clear()
                self.msg_count_label.setText("")
            except Exception:
                pass

    def load_results(self, artifact_name, rows):
        """Called from results tab to open PST files found by artifact collection."""
        for row in rows:
            path = row.get("Path","")
            if path and os.path.isfile(path):
                ext = os.path.splitext(path)[1].lower()
                if ext in (".pst",".ost",".msg",".mbox"):
                    self.open_file(path)
                    return

    # ── PST / OST loading (pypff) ────────────────────────────────────

    def _load_pst(self, path):
        try:
            import pypff
        except ImportError:
            QMessageBox.critical(self, "Missing Library",
                "pypff not installed.\nRun: pip install libpff-python")
            return
        try:
            pst = pypff.file()
            pst.open(path)
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self, "PST Error", f"Cannot open PST:\n{e}")
            return
        self.current_store = {"type": "pst", "path": path, "pst": pst}
        self._pst = pst
        self.folder_tree.clear()
        self._folder_map = {}
        root = pst.get_root_folder()
        self._build_folder_tree(root, None)
        if self.folder_tree.topLevelItemCount() > 0:
            first = self.folder_tree.topLevelItem(0)
            self.folder_tree.setCurrentItem(first)

    def _build_folder_tree(self, folder, parent_item):
        try:
            name = folder.get_name() or "(unnamed)"
        except Exception:
            name = "(unnamed)"
        try:
            n_msg = folder.get_number_of_sub_messages()
        except Exception:
            n_msg = 0
        try:
            n_sub = folder.get_number_of_sub_folders()
        except Exception:
            n_sub = 0

        label = f"📁  {name}  ({n_msg})"
        if parent_item is None:
            item = QTreeWidgetItem(self.folder_tree, [label])
        else:
            item = QTreeWidgetItem(parent_item, [label])
        item.setForeground(0, QBrush(QColor(C['orange'])))
        self._folder_map[id(item)] = folder

        for i in range(n_sub):
            try:
                sub = folder.get_sub_folder(i)
                self._build_folder_tree(sub, item)
            except Exception:
                pass

        if parent_item is None:
            item.setExpanded(True)

    # ── MBOX loading ─────────────────────────────────────────────────

    def _load_mbox(self, path):
        try:
            mbox = mailbox.mbox(path)
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self, "MBOX Error", f"Cannot open MBOX:\n{e}")
            return
        self.current_store = {"type": "mbox", "path": path, "mbox": mbox}
        self.folder_tree.clear()
        root = QTreeWidgetItem(self.folder_tree, ["📬  Inbox"])
        root.setForeground(0, QBrush(QColor(C['orange'])))
        self._folder_map[id(root)] = list(mbox.values())
        root.setExpanded(True)
        self.folder_tree.setCurrentItem(root)

    # ── EML loading ──────────────────────────────────────────────────

    def _load_eml(self, path):
        try:
            with open(path,"rb") as f:
                msg = email.message_from_bytes(f.read(), policy=email.policy.default)
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self,"Error",f"Failed to open EML:\n{e}")
            return
        self.current_store = {"type":"eml","path":path}
        self.folder_tree.clear()
        root = QTreeWidgetItem(self.folder_tree,["📧  EML"])
        root.setForeground(0, QBrush(QColor(C['orange'])))
        rec = {"msg":msg,"loader":"eml","source":path,"index":0}
        self._folder_map[id(root)] = [rec]
        root.setExpanded(True)
        self.folder_tree.setCurrentItem(root)

    # ── MSG file loading ─────────────────────────────────────────────

    def _load_single_msg(self, path):
        try:
            import extract_msg
        except ImportError:
            QMessageBox.critical(self,"Missing","pip install extract-msg")
            return
        msg = extract_msg.openMsg(path)
        self.folder_tree.clear()
        root_item = QTreeWidgetItem(self.folder_tree, ["📧  Message"])
        root_item.setForeground(0, QBrush(QColor(C['orange'])))
        self.folder_tree.addTopLevelItem(root_item)
        self._all_messages = [{
            "index":   0,
            "subject": str(msg.subject or "(no subject)"),
            "sender":  str(msg.sender or ""),
            "date":    str(msg.date or ""),
            "size":    str(os.path.getsize(path)),
            "n_att":   str(len(msg.attachments)),
            "_msg_raw": msg,
            "_path":   path,
            "source":  "msg",
        }]
        self.msg_rows    = self._all_messages
        self._messages   = self._all_messages
        self._folder_map[id(root_item)] = self._all_messages
        self._render_msg_table(self._all_messages)
        self._display_msg_raw(msg)

    # ── FIX: _on_folder_select — handle list-of-records AND pypff ────

    def _on_folder_select(self, item, _prev):
        if not item: return
        folder = self._folder_map.get(id(item))
        if folder is None: return
        if isinstance(folder, list):
            # MBOX / EML / MSG: list of dicts or mailbox.Message objects
            self._load_message_list(folder)
        else:
            # pypff folder object
            self._load_folder_messages(folder)

    def _load_message_list(self, msg_list):
        """Populate msg_rows from a list of records/mailbox messages."""
        self.msg_rows = []
        for obj in msg_list:
            if isinstance(obj, dict):
                self.msg_rows.append(obj)
            else:
                # mailbox.Message or similar email.message.Message subclass
                self.msg_rows.append({"msg": obj, "source": "mbox"})
        self._messages     = self.msg_rows
        self._all_messages = self.msg_rows
        self._render_msg_table(self.msg_rows)

    def _load_folder_messages(self, folder):
        """Load messages from a pypff folder, converting to plain dicts."""
        self.msg_rows = []
        self.msg_table.setRowCount(0)
        try:
            n = folder.get_number_of_sub_messages()
        except Exception:
            n = 0
        for i in range(n):
            try:
                m = folder.get_sub_message(i)
                def _gs(fn):
                    try:
                        v = fn()
                        return (v or b"").decode(errors='replace') if isinstance(v, bytes) else str(v or "")
                    except Exception:
                        return ""
                subj  = _gs(m.get_subject) or "(no subject)"
                sendr = _gs(m.get_sender_name)
                date  = ""
                try:
                    dt = m.get_delivery_time()
                    if dt: date = str(dt)
                except Exception:
                    pass
                size = ""
                try:
                    sz = m.get_message_size(); size = f"{sz:,}"
                except Exception:
                    pass
                att = ""
                try:
                    na = m.get_number_of_attachments(); att = str(na) if na else ""
                except Exception:
                    pass
                body_bytes = b""
                try: body_bytes = m.get_plain_text_body() or b""
                except Exception: pass
                html_bytes = b""
                try: html_bytes = m.get_html_body() or b""
                except Exception: pass
                rec = {
                    "source":    "pst",
                    "subject":   subj,
                    "sender":    sendr,
                    "date":      date,
                    "size":      size,
                    "n_att":     att,
                    "body_text": body_bytes.decode(errors='replace') if isinstance(body_bytes, bytes) else str(body_bytes),
                    "html_text": html_bytes.decode(errors='replace') if isinstance(html_bytes, bytes) else str(html_bytes),
                }
                self.msg_rows.append(rec)
            except Exception:
                pass
        self._messages     = self.msg_rows
        self._all_messages = self.msg_rows
        self._render_msg_table(self.msg_rows)

    # ── FIX: _render_msg_table — implement the missing method ─────────

    def _render_msg_table(self, rows):
        """Populate msg_table from a list of normalised message dicts."""
        self.msg_table.setRowCount(0)
        for rec in rows:
            r = self.msg_table.rowCount()
            self.msg_table.insertRow(r)
            if isinstance(rec, dict):
                src = rec.get("source", "")
                if src == "pst":
                    frm  = rec.get("sender","")[:60]
                    subj = rec.get("subject","")[:120]
                    date = rec.get("date","")[:30]
                    size = rec.get("size","")
                    att  = str(rec.get("n_att",""))
                elif src == "msg":
                    frm  = rec.get("sender","")[:60]
                    subj = rec.get("subject","")[:120]
                    date = rec.get("date","")[:30]
                    size = rec.get("size","")
                    att  = str(rec.get("n_att",""))
                else:
                    msg = rec.get("msg")
                    frm = subj = date = size = att = ""
                    if msg is not None and hasattr(msg, 'get'):
                        try: frm  = self._safe_str(msg.get("From",""))[:60]
                        except Exception: pass
                        try: subj = self._safe_str(msg.get("Subject",""))[:120]
                        except Exception: pass
                        try: date = self._safe_str(msg.get("Date",""))[:30]
                        except Exception: pass
                        try:
                            n = sum(1 for p in msg.walk()
                                    if p.get_content_disposition() == "attachment")
                            att = str(n) if n else ""
                        except Exception: pass
            else:
                frm = subj = date = size = att = ""
            for c, val in enumerate((frm, subj, date, size, att)):
                self.msg_table.setItem(r, c, QTableWidgetItem(val))
        self.msg_count_label.setText(f"  {len(rows)} message(s)")

    # ── FIX: _on_message_select — safe for all message types ─────────

    def _on_message_select(self, row, _col, _pr, _pc):
        if row < 0 or row >= len(self.msg_rows): return
        rec = self.msg_rows[row]
        self._current_msg = rec
        try:
            if isinstance(rec, dict):
                src = rec.get("source","")
                if src == "msg" and "_msg_raw" in rec:
                    # extract_msg object — delegate to _display_msg_raw
                    self._display_msg_raw(rec["_msg_raw"])
                else:
                    self._display_message(rec)
            else:
                # mailbox.Message or similar — wrap as dict
                self._display_message({"msg": rec, "source": "mbox"})
        except Exception as e:
            traceback.print_exc()
            self.body_view.setPlainText(f"Failed to render message:\n{e}")

    # ── Display helpers (mostly original, now referencing correct widgets)

    def _display_message(self, rec):
        """Render a message record into the right-side preview tabs."""
        self.body_view.clear()
        self.header_view.setRowCount(0)
        self.attach_list.clear()
        self.raw_view.clear()

        try:
            source = rec.get("source","")
            if source == "pst":
                body_text = rec.get("body_text","")
                html_text = rec.get("html_text","")
                headers = [
                    ("From",    rec.get("sender","")),
                    ("Subject", rec.get("subject","")),
                    ("Date",    rec.get("date","")),
                ]
                self.header_view.setRowCount(len(headers))
                for i,(k,v) in enumerate(headers):
                    self.header_view.setItem(i,0,QTableWidgetItem(k))
                    self.header_view.setItem(i,1,QTableWidgetItem(v))
                if html_text:
                    self.body_view.setHtml(html_text)
                elif body_text:
                    self.body_view.setPlainText(body_text)
                else:
                    self.body_view.setPlainText("(No body content)")
                self.raw_view.setPlainText(
                    f"From: {rec.get('sender','')}\n"
                    f"Subject: {rec.get('subject','')}\n"
                    f"Date: {rec.get('date','')}\n\n"
                    f"{body_text[:8192]}")
                return

            msg = rec.get("msg")
            if msg is None:
                self.body_view.setPlainText("(Message not available)")
                return
            if not isinstance(msg, email.message.Message):
                self.body_view.setPlainText(str(msg))
                return

            # ── Headers ─────────────────────────────────────────────
            priority_keys = ['From','To','Cc','Bcc','Subject','Date',
                             'Message-ID','Reply-To','Return-Path',
                             'Delivered-To','In-Reply-To','References']
            seen_keys = set()
            headers = []
            for k in priority_keys:
                v = msg.get(k,"")
                if isinstance(v,(list,tuple)):
                    v = ", ".join(str(x) for x in v)
                headers.append((k, self._safe_str(v)))
                seen_keys.add(k.lower())
            for k, v in msg.items():
                if k.lower() not in seen_keys:
                    headers.append((k, self._safe_str(v)))
                    seen_keys.add(k.lower())
            self.header_view.setRowCount(len(headers))
            for i,(k,v) in enumerate(headers):
                self.header_view.setItem(i,0,QTableWidgetItem(k))
                self.header_view.setItem(i,1,QTableWidgetItem(v))
            self.header_view.resizeColumnsToContents()

            # ── Body ─────────────────────────────────────────────────
            html_body  = None
            plain_body = None
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    disp  = part.get_content_disposition()
                    if disp == 'attachment': continue
                    payload = None
                    try:    payload = part.get_content()
                    except Exception:
                        try:
                            payload = part.get_payload(decode=True)
                            if isinstance(payload,(bytes,bytearray)):
                                payload = payload.decode(errors='replace')
                        except Exception: pass
                    if ctype == 'text/html' and html_body is None and payload:
                        html_body = payload
                    elif ctype == 'text/plain' and plain_body is None and payload:
                        plain_body = payload
            else:
                try:    payload = msg.get_content()
                except Exception:
                    payload = msg.get_payload(decode=True)
                    if isinstance(payload,(bytes,bytearray)):
                        payload = payload.decode(errors='replace')
                ctype = msg.get_content_type()
                if ctype == 'text/html':
                    html_body = payload
                else:
                    plain_body = payload

            if html_body:
                self.body_view.setHtml(html_body)
            elif plain_body:
                self.body_view.setPlainText(plain_body)
            else:
                self.body_view.setPlainText("(No body content)")

            # ── Attachments ──────────────────────────────────────────
            self.attach_list.clear()
            for part in msg.walk():
                disp = part.get_content_disposition()
                if disp == 'attachment':
                    fname = part.get_filename() or "attachment"
                    try:
                        data = part.get_payload(decode=True) or b""
                        size = len(data)
                    except Exception:
                        size = 0
                        data = b""
                    li = QListWidgetItem(f"📎  {fname}  ({fmt_size(size)})")
                    li.setData(Qt.ItemDataRole.UserRole, {"name":fname,"data":data})
                    self.attach_list.addItem(li)

            # ── Raw RFC822 ───────────────────────────────────────────
            try:
                raw = msg.as_string()[:32768]
            except Exception:
                raw = str(msg)[:32768]
            self.raw_view.setPlainText(raw)

        except Exception as e:
            traceback.print_exc()
            self.body_view.setPlainText(f"Render error:\n{e}\n\n{traceback.format_exc()}")

    def _display_mbox_msg(self, msg):
        """Display a mailbox.Message / email.message.Message (legacy helper)."""
        self.header_view.setRowCount(0)
        for k in ('From','To','Subject','Date'):
            v = msg.get(k,'')
            r = self.header_view.rowCount()
            self.header_view.insertRow(r)
            self.header_view.setItem(r,0,QTableWidgetItem(k))
            self.header_view.setItem(r,1,QTableWidgetItem(self._safe_str(v)))
        body = ""
        html_body = ""
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = part.get_content_disposition()
            if disp == 'attachment': continue
            if ct == 'text/html' and not html_body:
                try:    html_body = part.get_content()
                except Exception:
                    try: html_body = (part.get_payload(decode=True) or b"").decode(errors='replace')
                    except Exception: pass
            elif ct == 'text/plain' and not body:
                try:    body = part.get_content()
                except Exception:
                    try: body = (part.get_payload(decode=True) or b"").decode(errors='replace')
                    except Exception: pass
        if html_body:
            self.body_view.setHtml(html_body)
        else:
            self.body_view.setPlainText(body or "(No body content)")

    def _display_msg_raw(self, msg):
        """Display an extract_msg message object."""
        self.header_view.setRowCount(0)
        for k, v in [("From", str(msg.sender or "")), ("To", str(msg.to or "")),
                     ("Subject", str(msg.subject or "")), ("Date", str(msg.date or ""))]:
            r = self.header_view.rowCount()
            self.header_view.insertRow(r)
            self.header_view.setItem(r,0,QTableWidgetItem(k))
            self.header_view.setItem(r,1,QTableWidgetItem(v))
        body = msg.htmlBody or msg.body or "(empty)"
        if isinstance(body, bytes): body = body.decode(errors='replace')
        if msg.htmlBody:
            self.body_view.setHtml(body)
        else:
            self.body_view.setPlainText(body)
        self.attach_bar.setVisible(len(msg.attachments) > 0)
        while self._attach_lay.count():
            item = self._attach_lay.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        for att in msg.attachments:
            aname = att.longFilename or att.shortFilename or "attachment"
            btn = QPushButton(f"📎 {aname}")
            btn.setFixedHeight(26)
            btn.clicked.connect(lambda _, a=att, n=aname: self._save_att_raw(a, n))
            self._attach_lay.addWidget(btn)
        if msg.attachments: self._attach_lay.addStretch()

    def _save_att_raw(self, att, name):
        dst, _ = QFileDialog.getSaveFileName(self, "Save Attachment", name)
        if not dst: return
        try:
            data = att.data
            with open(dst, "wb") as f: f.write(data)
            QMessageBox.information(self, "Saved", f"Attachment saved:\n{dst}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _save_attachment(self, att, name):
        dst, _ = QFileDialog.getSaveFileName(self, "Save Attachment", name)
        if not dst: return
        try:
            data = att.read_buffer(att.get_size())
            with open(dst, "wb") as f: f.write(data)
            QMessageBox.information(self, "Saved", f"Attachment saved:\n{dst}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # ── FIX: _msg_ctx — use msg_rows (safe dict access) ──────────────

    def _msg_ctx(self, pos):
        row = self.msg_table.rowAt(pos.y())
        if row < 0: return
        menu = QMenu(self)
        menu.addAction("💾 Export Message…", self._export_selected)
        menu.addAction("Copy Subject", lambda: (
            QApplication.clipboard().setText(
                self.msg_rows[row].get("subject","")
                if row < len(self.msg_rows) else "")))
        menu.addAction("Copy Sender", lambda: (
            QApplication.clipboard().setText(
                self.msg_rows[row].get("sender","")
                if row < len(self.msg_rows) else "")))
        menu.exec(self.msg_table.mapToGlobal(pos))

    # ── Filter / export (original, unchanged) ────────────────────────

    def _filter_messages(self, text):
        text = (text or "").strip().lower()
        if not text:
            self._render_msg_table(self.msg_rows)
            return
        out = []
        for rec in self.msg_rows:
            src = rec.get("source","") if isinstance(rec, dict) else ""
            if src in ("pst","msg"):
                haystack = (rec.get("subject","") + rec.get("sender","")).lower()
            else:
                msg = rec.get("msg") if isinstance(rec, dict) else rec
                haystack = ""
                if msg is not None and hasattr(msg, 'get'):
                    haystack = (self._safe_str(msg.get("Subject","")) +
                                self._safe_str(msg.get("From",""))).lower()
            if text in haystack:
                out.append(rec)
        self._render_msg_table(out)

    def _export_selected(self):
        rows = self.msg_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self,"Export","No messages selected.")
            return
        out_dir = QFileDialog.getExistingDirectory(self,"Choose export folder")
        if not out_dir: return
        count = 0
        for r in rows:
            i = r.row()
            if i < 0 or i >= len(self.msg_rows): continue
            rec = self.msg_rows[i]
            try:
                msg = rec.get("msg") if isinstance(rec, dict) else rec
                if not isinstance(msg, email.message.Message):
                    continue
                subj  = self._safe_str(msg.get("Subject","message"))[:40]
                fname = f"msg_{i}_{re.sub(r'[^A-Za-z0-9._-]','_', subj)}.eml"
                fpath = os.path.join(out_dir, fname)
                with open(fpath,"wb") as f:
                    f.write(msg.as_bytes())
                count += 1
            except Exception:
                traceback.print_exc()
        QMessageBox.information(self,"Export",
            f"Exported {count} message(s) to:\n{out_dir}")


# ══════════════════════════════════════════════════════════════
#  BOOKMARK TAB  (NEW)
# ══════════════════════════════════════════════════════════════
DEFAULT_BOOKMARK_TAGS = [
    "🚨 Suspicious",
    "📌 Evidence",
    "✅ Reviewed",
    "⭐ Important",
    "🔴 Flagged",
    "📝 Notes",
    "🔍 Needs Analysis",
    "🗑 False Positive",
]

class BookmarkTab(QWidget):
    """Bookmark manager: items arrive via add_bookmark() called from MainWindow."""

    def __init__(self):
        super().__init__()
        self._bookmarks = []
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)

        # ── Left: tag filter ─────────────────────────────────────────
        left = QWidget()
        left.setMinimumWidth(160)
        left.setMaximumWidth(220)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0,0,0,0)
        ll.setSpacing(0)

        lh = QLabel("  TAGS")
        lh.setObjectName("section_header")
        ll.addWidget(lh)

        self.tag_list = QListWidget()
        self.tag_list.addItem(QListWidgetItem("  All"))
        for tag in DEFAULT_BOOKMARK_TAGS:
            self.tag_list.addItem(QListWidgetItem(f"  {tag}"))
        self.tag_list.setCurrentRow(0)
        self.tag_list.currentRowChanged.connect(lambda _: self._refresh_list())
        ll.addWidget(self.tag_list, 1)

        add_tag_btn = QPushButton("＋ Custom Tag")
        add_tag_btn.setFixedHeight(28)
        add_tag_btn.clicked.connect(self._add_custom_tag)
        ll.addWidget(add_tag_btn)

        split.addWidget(left)

        # ── Right: bookmark table + detail ───────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0,0,0,0)
        rl.setSpacing(0)

        # Toolbar
        tb = QWidget()
        tb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(8,4,8,4)
        tbl.setSpacing(6)
        tbl.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search bookmarks…")
        self.filter_edit.textChanged.connect(self._refresh_list)
        tbl.addWidget(self.filter_edit, 1)
        for label, slot in [("💾 CSV", self._export_csv),
                             ("💾 JSON", self._export_json),
                             ("🗑 Clear All", self._clear_all)]:
            btn = QPushButton(label)
            btn.clicked.connect(slot)
            tbl.addWidget(btn)
        rl.addWidget(tb)

        v_split = QSplitter(Qt.Orientation.Vertical)
        v_split.setHandleWidth(2)

        # Bookmark table
        self.bm_table = QTableWidget(0, 5)
        self.bm_table.setHorizontalHeaderLabels(
            ["Tag","Name","Type","Timestamp","Preview"])
        self.bm_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.bm_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.bm_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.bm_table.setAlternatingRowColors(True)
        self.bm_table.currentCellChanged.connect(
            lambda row, *_: self._on_bm_select(row))
        self.bm_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.bm_table.customContextMenuRequested.connect(self._bm_ctx)
        v_split.addWidget(self.bm_table)

        # Detail pane
        detail_w = QWidget()
        dvl = QVBoxLayout(detail_w)
        dvl.setContentsMargins(0,0,0,0)
        dvl.setSpacing(0)
        dh = QLabel("  BOOKMARK DETAIL")
        dh.setStyleSheet(
            f"background:{C['header']};color:{C['fg2']};font-size:8pt;"
            f"font-weight:bold;padding:3px 10px;"
            f"border-top:1px solid {C['border']};")
        dvl.addWidget(dh)
        self.detail_view = QPlainTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setStyleSheet(
            f"background:{C['bg']};color:{C['fg2']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:8pt;border:none;")
        dvl.addWidget(self.detail_view)
        note_lbl = QLabel("  Notes:")
        note_lbl.setStyleSheet(f"color:{C['accent']};font-size:8pt;padding:2px 10px;")
        dvl.addWidget(note_lbl)
        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setMaximumHeight(60)
        self.notes_edit.setPlaceholderText("Add notes for this bookmark…")
        self.notes_edit.setStyleSheet(
            f"background:{C['bg2']};color:{C['fg']};"
            f"font-size:8pt;border:none;padding:4px 10px;")
        self.notes_edit.textChanged.connect(self._save_note)
        dvl.addWidget(self.notes_edit)
        v_split.addWidget(detail_w)
        v_split.setSizes([400, 180])
        rl.addWidget(v_split)

        # Stats bar
        self.stats_label = QLabel("  0 bookmarks")
        self.stats_label.setStyleSheet(
            f"background:{C['bg3']};color:{C['fg2']};font-size:8pt;"
            f"padding:3px 10px;border-top:1px solid {C['border']};")
        rl.addWidget(self.stats_label)

        split.addWidget(right)
        split.setSizes([200, 1000])
        lay.addWidget(split)

    # ── Public API ───────────────────────────────────────────────────

    def add_bookmark(self, tag: str, data: dict):
        data["tag"]   = tag
        data.setdefault("notes", "")
        self._bookmarks.append(data)
        self._refresh_list()

    # ── Internal ─────────────────────────────────────────────────────

    def _refresh_list(self):
        tag_item = self.tag_list.currentItem()
        tag_filter = tag_item.text().strip() if tag_item else "All"
        text_filter = self.filter_edit.text().lower()
        self.bm_table.setSortingEnabled(False)
        self.bm_table.setRowCount(0)
        for idx, bm in enumerate(self._bookmarks):
            tag = bm.get("tag","")
            if tag_filter != "All" and tag_filter not in tag:
                continue
            preview = bm.get("preview","")
            name    = bm.get("name","")
            if text_filter and text_filter not in (tag+name+preview).lower():
                continue
            r = self.bm_table.rowCount()
            self.bm_table.insertRow(r)
            self.bm_table.setItem(r,0,QTableWidgetItem(tag))
            self.bm_table.setItem(r,1,QTableWidgetItem(name))
            self.bm_table.setItem(r,2,QTableWidgetItem(bm.get("type","")))
            self.bm_table.setItem(r,3,QTableWidgetItem(bm.get("timestamp","")))
            self.bm_table.setItem(r,4,QTableWidgetItem(preview[:80]))
            self.bm_table.item(r,0).setData(Qt.ItemDataRole.UserRole, idx)
        self.bm_table.setSortingEnabled(True)
        self.stats_label.setText(
            f"  {len(self._bookmarks)} bookmark(s)  |  {self.bm_table.rowCount()} shown")

    def _on_bm_select(self, row):
        if row < 0:
            self.detail_view.clear(); return
        idx_item = self.bm_table.item(row, 0)
        if not idx_item: return
        bm_idx = idx_item.data(Qt.ItemDataRole.UserRole)
        if bm_idx is None or bm_idx >= len(self._bookmarks): return
        bm = self._bookmarks[bm_idx]
        lines = [f"  {'─'*50}"]
        for k, v in bm.items():
            if k == "notes": continue
            if isinstance(v, dict):
                lines.append(f"  {k}:")
                for dk, dv in v.items():
                    lines.append(f"      {dk:<22} {dv}")
            else:
                lines.append(f"  {k:<28} {v}")
        lines.append(f"  {'─'*50}")
        self.detail_view.setPlainText("\n".join(lines))
        self.notes_edit.blockSignals(True)
        self.notes_edit.setPlainText(bm.get("notes",""))
        self.notes_edit.blockSignals(False)

    def _save_note(self):
        row = self.bm_table.currentRow()
        if row < 0: return
        idx_item = self.bm_table.item(row, 0)
        if not idx_item: return
        bm_idx = idx_item.data(Qt.ItemDataRole.UserRole)
        if bm_idx is not None and bm_idx < len(self._bookmarks):
            self._bookmarks[bm_idx]["notes"] = self.notes_edit.toPlainText()

    def _bm_ctx(self, pos):
        row = self.bm_table.currentRow()
        if row < 0: return
        menu = QMenu(self)
        retag = menu.addMenu("Re-tag as…")
        for tag in DEFAULT_BOOKMARK_TAGS:
            retag.addAction(tag, lambda t=tag: self._retag_selected(t))
        menu.addSeparator()
        menu.addAction("🗑 Remove", self._remove_selected)
        menu.exec(self.bm_table.viewport().mapToGlobal(pos))

    def _retag_selected(self, new_tag):
        row = self.bm_table.currentRow()
        if row < 0: return
        idx_item = self.bm_table.item(row, 0)
        if not idx_item: return
        bm_idx = idx_item.data(Qt.ItemDataRole.UserRole)
        if bm_idx is not None and bm_idx < len(self._bookmarks):
            self._bookmarks[bm_idx]["tag"] = new_tag
            self._refresh_list()

    def _remove_selected(self):
        row = self.bm_table.currentRow()
        if row < 0: return
        idx_item = self.bm_table.item(row, 0)
        if not idx_item: return
        bm_idx = idx_item.data(Qt.ItemDataRole.UserRole)
        if bm_idx is not None and bm_idx < len(self._bookmarks):
            self._bookmarks.pop(bm_idx)
            self._refresh_list()

    def _add_custom_tag(self):
        text, ok = QInputDialog.getText(self, "Custom Tag", "Enter new tag label:")
        if ok and text.strip():
            self.tag_list.addItem(QListWidgetItem(f"  {text.strip()}"))

    def _clear_all(self):
        if QMessageBox.question(self, "Clear All", "Remove ALL bookmarks?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                ) == QMessageBox.StandardButton.Yes:
            self._bookmarks.clear()
            self._refresh_list()

    def _export_csv(self):
        if not self._bookmarks: return
        path, _ = QFileDialog.getSaveFileName(self,"Export Bookmarks CSV","","CSV (*.csv)")
        if not path: return
        keys = sorted({k for bm in self._bookmarks for k in bm})
        with open(path,"w",newline="",encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
            w.writeheader()
            for bm in self._bookmarks:
                w.writerow({k: str(v) if isinstance(v,dict) else v for k,v in bm.items()})
        QMessageBox.information(self,"Exported",f"Bookmarks saved:\n{path}")

    def _export_json(self):
        if not self._bookmarks: return
        path, _ = QFileDialog.getSaveFileName(self,"Export Bookmarks JSON","","JSON (*.json)")
        if not path: return
        with open(path,"w",encoding="utf-8") as f:
            json.dump(self._bookmarks, f, indent=2, default=str)
        QMessageBox.information(self,"Exported",f"Bookmarks saved:\n{path}")


# ══════════════════════════════════════════════════════════════
#  NEW / OPEN CASE DIALOG
# ══════════════════════════════════════════════════════════════
class CaseDialog(QDialog):
    def __init__(self, parent=None, existing=None):
        super().__init__(parent)
        self.setWindowTitle("Case Properties")
        self.setFixedSize(420, 280)
        self.setStyleSheet(STYLESHEET)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.f_name    = QLineEdit(existing.get("name","New Investigation") if existing else "New Investigation")
        self.f_number  = QLineEdit(existing.get("number","FC-2025-001") if existing else "FC-2025-001")
        self.f_examiner= QLineEdit(existing.get("examiner","") if existing else "")
        self.f_notes   = QLineEdit(existing.get("notes","") if existing else "")
        form.addRow("Case Name:",   self.f_name)
        form.addRow("Case Number:", self.f_number)
        form.addRow("Examiner:",    self.f_examiner)
        form.addRow("Notes:",       self.f_notes)
        lay.addLayout(form)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def values(self):
        return {"name":self.f_name.text(),"number":self.f_number.text(),
                "examiner":self.f_examiner.text(),"notes":self.f_notes.text()}


# ══════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.resize(1440, 900)
        self.setMinimumSize(1100, 700)

        self.case_info = {"name":"New Case","number":"FC-2025-001",
                          "examiner":"","notes":""}
        self.artifact_results = {}
        self._worker = None

        self.setStyleSheet(STYLESHEET)
        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_statusbar()
        self.set_status("Ready  —  " + datetime.datetime.now().strftime("%Y-%m-%d"))

    def _build_menu(self):
        mb = self.menuBar()
        def menu(title, items):
            m = mb.addMenu(title)
            for item in items:
                if item is None:
                    m.addSeparator()
                else:
                    label, slot = item
                    act = QAction(label, self)
                    act.triggered.connect(slot)
                    m.addAction(act)
            return m
        menu("&File", [
            ("New Case…",             self._new_case),
            ("Open Case…",            self._open_case),
            ("Save Case",             self._save_case),
            None,
            ("Add Evidence File(s)…", self._add_evidence_files),
            ("Add Forensic Image…",   self._add_image),
            ("Add Local Disk…",       self._add_disk),
            None,
            ("Export Report…",        self._export_report),
            None,
            ("Exit",                  self.close),
        ])
        menu("&Analysis", [
            ("Process Selected Artifacts", self._process_artifacts),
            ("Keyword Search…",            self._keyword_search),
            ("Build Timeline",             self._build_timeline),
        ])
        menu("&Remote", [
            ("Generate Agent…",  lambda: self.tabs.setCurrentIndex(4)),
            ("Connect via SSH…", self._ssh_connect),
        ])
        menu("&View", [
            ("Evidence Browser",   lambda: self.tabs.setCurrentIndex(0)),
            ("Artifact Selection", lambda: self.tabs.setCurrentIndex(1)),
            ("Analysis Results",   lambda: self.tabs.setCurrentIndex(2)),
            ("Timeline",           lambda: self.tabs.setCurrentIndex(3)),
            ("Remote Agent",       lambda: self.tabs.setCurrentIndex(4)),
            ("Email Viewer",       lambda: self.tabs.setCurrentIndex(5)),
            ("Bookmarks",          lambda: self.tabs.setCurrentIndex(6)),
        ])
        menu("&Help", [("About", self._about)])

    def _build_toolbar(self):
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(16,16))
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        self.addToolBar(tb)
        def tbtn(text, slot, accent=False):
            btn = QToolButton()
            btn.setText(text)
            btn.clicked.connect(slot)
            if accent:
                btn.setStyleSheet(
                    f"QToolButton{{background:{C['accent']};color:#000;font-weight:bold;"
                    f"border:none;border-radius:4px;padding:4px 12px;}}"
                    f"QToolButton:hover{{background:#79c0ff;}}")
            tb.addWidget(btn)
            return btn
        tbtn("＋ Add Evidence",  self._add_evidence_files, accent=True)
        tbtn("🖴 Add Image",      self._add_image)
        tbtn("💾 Local Disk",     self._add_disk)
        tb.addSeparator()
        tbtn("▶ Process",         self._process_artifacts)
        tbtn("🔍 Search",          self._keyword_search)
        tbtn("📊 Export Report",   self._export_report)
        tb.addSeparator()
        tbtn("⚡ Remote Agent",   lambda: self.tabs.setCurrentIndex(4))
        tbtn("🔖 Bookmarks",      lambda: self.tabs.setCurrentIndex(6))
        tb.addSeparator()
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)
        self.case_tb_label = QLabel("")
        self.case_tb_label.setStyleSheet(f"color:{C['fg2']};font-size:8pt;padding:0 12px;")
        tb.addWidget(self.case_tb_label)
        self._refresh_case_label()

    def _build_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # Tab 0: Evidence Browser
        self.browser = EvidenceBrowser(self)
        self.tabs.addTab(self.browser, "📂  Evidence Browser")

        # Tab 1: Artifact Selection
        self.art_tab = ArtifactTab()
        self.art_tab.process_requested.connect(self._run_collection)
        self.tabs.addTab(self.art_tab, "🔎  Artifact Selection")

        # Tab 2: Results
        self.results_tab = ResultsTab()
        # ── NEW: route bookmark signals to the bookmark tab ──────────
        self.results_tab.bookmark_requested.connect(self._on_bookmark_requested)
        self.tabs.addTab(self.results_tab, "📋  Analysis Results")

        # Tab 3: Timeline
        self.timeline_tab = TimelineTab()
        self.tabs.addTab(self.timeline_tab, "📅  Timeline")

        # Tab 4: Remote Agent
        self.agent_tab = AgentTab(self.art_tab)
        self.tabs.addTab(self.agent_tab, "⚡  Remote Agent")

        # Tab 5: Email Viewer
        self.email_tab = EmailViewerTab()
        self.tabs.addTab(self.email_tab, "📧  Email Viewer")

        # Tab 6: Bookmarks (NEW)
        self.bookmark_tab = BookmarkTab()
        self.tabs.addTab(self.bookmark_tab, "🔖  Bookmarks")

        lay.addWidget(self.tabs)

    # ── NEW: receive bookmark signal and forward to BookmarkTab ──────
    @pyqtSlot(str, dict)
    def _on_bookmark_requested(self, tag: str, data: dict):
        self.bookmark_tab.add_bookmark(tag, data)
        self.set_status(f"🔖 Bookmarked [{tag}]: {data.get('name','')}")

    def _build_statusbar(self):
        sb = self.statusBar()
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(200)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setValue(0)
        sb.addPermanentWidget(self.progress_bar)
        self.clock_label = QLabel()
        self.clock_label.setStyleSheet(f"color:{C['fg2']};padding:0 8px;")
        sb.addPermanentWidget(self.clock_label)
        timer = QTimer(self)
        timer.timeout.connect(self._tick)
        timer.start(1000)
        self._tick()

    def _tick(self):
        self.clock_label.setText(datetime.datetime.now().strftime("  %Y-%m-%d  %H:%M:%S  "))

    def set_status(self, msg: str):
        self.statusBar().showMessage(f"  {msg}")

    def _add_evidence_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Add Evidence Files", "",
            "Forensic Files (*.e01 *.dd *.img *.raw *.vmdk *.vhd *.iso *.evtx *.reg *.db *.pcap *);;"
            "All Files (*)")
        for p in paths:
            ext = Path(p).suffix.lower()
            if ext in (".e01",".dd",".img",".raw",".vmdk",".vhd",".iso"):
                self.browser.add_evidence_image(p)
            else:
                self.browser._load_dir(Path(p).parent)
                self.browser.content.load_path(p)
            self.set_status(f"Added: {os.path.basename(p)}")
        self._sync_evidence_cache()

    def _add_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Add Forensic Image", "",
            "Forensic Images (*.e01 *.dd *.img *.raw *.vmdk *.vhd *.iso *.001);;All (*)")
        if path:
            self.browser.add_evidence_image(path)
            self.set_status(f"Image loaded: {os.path.basename(path)}")
            self._sync_evidence_cache()

    def _add_disk(self):
        parts = psutil.disk_partitions()
        if not parts:
            QMessageBox.information(self,"Disks","No partitions found."); return
        dlg = QDialog(self)
        dlg.setWindowTitle("Add Local Disk")
        dlg.setFixedSize(500, 320)
        dlg.setStyleSheet(STYLESHEET)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel("Select a disk partition to add as evidence:"))
        lb = QListWidget()
        for p in parts:
            try:
                u = psutil.disk_usage(p.mountpoint)
                lb.addItem(f"{p.device}  [{p.fstype}]  {p.mountpoint}  "
                           f"({fmt_size(u.used)}/{fmt_size(u.total)}  {u.percent:.0f}%)")
            except Exception:
                lb.addItem(f"{p.device}  [{p.fstype}]  {p.mountpoint}")
        lay.addWidget(lb)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept); btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        if dlg.exec() and lb.currentRow() >= 0:
            mp = parts[lb.currentRow()].mountpoint
            self.browser.add_evidence_image(mp)
            self.set_status(f"Disk added: {mp}")
            self._sync_evidence_cache()

    def _sync_evidence_cache(self):
        items = []
        for i in range(self.browser.img_root.childCount()):
            child = self.browser.img_root.child(i)
            d = child.data(0, Qt.ItemDataRole.UserRole) or {}
            items.append({"label": child.text(0).strip(),
                           "type":  d.get("type","directory"),
                           "path":  d.get("path","")})
        self._evidence_items_cache = items
        self.art_tab.refresh_evidence_list(items)

    def _process_artifacts(self):
        self.tabs.setCurrentIndex(1)
        self.art_tab._emit_process()

    def _run_collection(self, names: list, target_path: str = "", target_type: str = "local"):
        self.tabs.setCurrentIndex(2)
        self.results_tab.clear_all()
        self.progress_bar.setValue(0)
        tp = target_path or ""
        tt = target_type or "local"
        self.set_status(f"Collecting {len(names)} artifact(s)…")
        self._worker = ArtifactWorker(names, target_path=tp or None, target_type=tt)
        self._worker.progress.connect(self._on_worker_progress)
        self._worker.result.connect(self._on_worker_result)
        self._worker.finished.connect(self._on_worker_done)
        self._worker.start()

    @pyqtSlot(int, int, str)
    def _on_worker_progress(self, cur, total, name):
        pct = int(cur / total * 100)
        self.progress_bar.setValue(pct)
        self.results_tab.set_progress(pct)
        self.set_status(f"Collecting [{cur}/{total}]: {name}")

    @pyqtSlot(str, list)
    def _on_worker_result(self, name, rows):
        self.artifact_results[name] = rows
        self.results_tab.add_result(name, rows)

    @pyqtSlot()
    def _on_worker_done(self):
        self.progress_bar.setValue(100)
        self.set_status(f"✓ Collection complete — {len(self.artifact_results)} artifact(s)")
        self.timeline_tab.build_from(self.artifact_results)
        for k in self.artifact_results:
            if any(x in k for x in ("PST","MSG","MBOX","Email","Thunderbird")):
                self.email_tab.load_results(k, self.artifact_results[k])

    def _on_tab_changed(self, idx):
        if idx == 1:
            items = getattr(self, '_evidence_items_cache', [])
            self.art_tab.refresh_evidence_list(items)

    def _build_timeline(self):
        self.timeline_tab.build_from(self.artifact_results)
        self.tabs.setCurrentIndex(3)

    def _keyword_search(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Keyword Search")
        dlg.resize(800, 500)
        dlg.setStyleSheet(STYLESHEET)
        lay = QVBoxLayout(dlg)
        sb = QHBoxLayout()
        sb.addWidget(QLabel("Search:"))
        q = QLineEdit(); q.setPlaceholderText("Enter keyword…")
        sb.addWidget(q)
        btn = QPushButton("Search")
        btn.setObjectName("accent")
        sb.addWidget(btn)
        cnt = QLabel(""); cnt.setStyleSheet(f"color:{C['fg2']};")
        sb.addWidget(cnt)
        lay.addLayout(sb)
        table = QTableWidget(0,4)
        table.setHorizontalHeaderLabels(["Source","Field","Value","Context"])
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        lay.addWidget(table)
        def do_search():
            kw = q.text().lower()
            table.setRowCount(0)
            if not kw: return
            hits = 0
            for art, rows in self.artifact_results.items():
                for row in rows:
                    for k,v in row.items():
                        if kw in str(v).lower():
                            r = table.rowCount()
                            table.insertRow(r)
                            for c, val in enumerate([art, k, str(v)[:80], str(v)[:200]]):
                                table.setItem(r, c, QTableWidgetItem(val))
                            hits += 1
            cnt.setText(f"{hits} hit(s)")
        btn.clicked.connect(do_search)
        q.returnPressed.connect(do_search)
        dlg.exec()

    def _verify_all(self):
        paths = []
        for i in range(self.browser.img_root.childCount()):
            child = self.browser.img_root.child(i)
            d = child.data(0, Qt.ItemDataRole.UserRole) or {}
            p = d.get("path","")
            if p and os.path.isfile(p):
                paths.append(p)
        if not paths:
            QMessageBox.information(self,"Verify","No forensic image files loaded."); return
        def run():
            lines = []
            for p in paths:
                if os.path.isfile(p):
                    m = md5_path(p); s = sha256_path(p)
                    lines.append(f"{os.path.basename(p)}\n  MD5:    {m}\n  SHA-256:{s}\n")
            QMessageBox.information(self,"Hash Results","".join(lines) or "No files hashed.")
        threading.Thread(target=run, daemon=True).start()

    def _new_case(self):
        dlg = CaseDialog(self)
        if dlg.exec():
            self.case_info = dlg.values()
            self._refresh_case_label()
            self.set_status(f"New case: {self.case_info['name']}")

    def _open_case(self):
        path, _ = QFileDialog.getOpenFileName(
            self,"Open Case","","ForensicPro Case (*.fpcase);;JSON (*.json);;All (*)")
        if not path: return
        try:
            with open(path) as f: data = json.load(f)
            self.case_info = data.get("case", self.case_info)
            for name, rows in data.get("artifact_results",{}).items():
                self.artifact_results[name] = rows
                self.results_tab.add_result(name, rows)
            self._refresh_case_label()
            self.set_status(f"Case opened: {self.case_info['name']}")
        except Exception as e:
            QMessageBox.critical(self,"Error",str(e))

    def _save_case(self):
        path, _ = QFileDialog.getSaveFileName(
            self,"Save Case","","ForensicPro Case (*.fpcase);;JSON (*.json)")
        if not path: return
        data = {"case":self.case_info,
                "artifact_results":self.artifact_results,
                "saved_at":datetime.datetime.now().isoformat()}
        with open(path,"w") as f: json.dump(data, f, indent=2, default=str)
        self.set_status(f"Case saved: {path}")

    def _refresh_case_label(self):
        c = self.case_info
        self.case_tb_label.setText(
            f"Case: {c['name']}  |  {c['number']}  |  {c['examiner']}")

    def _export_report(self):
        self.results_tab._export_html()

    def _ssh_connect(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("SSH / Remote Target")
        dlg.setFixedSize(380,200)
        dlg.setStyleSheet(STYLESHEET)
        lay = QFormLayout(dlg)
        f_host = QLineEdit(); f_user = QLineEdit("root"); f_pass = QLineEdit()
        f_pass.setEchoMode(QLineEdit.EchoMode.Password)
        lay.addRow("Host:",     f_host)
        lay.addRow("Username:", f_user)
        lay.addRow("Password:", f_pass)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept); btns.rejected.connect(dlg.reject)
        lay.addRow(btns)
        if dlg.exec():
            target = f"{f_user.text()}@{f_host.text()}"
            self.browser.add_remote_target(target)
            self.agent_tab.f_ssh_target.setText(target)
            self.tabs.setCurrentIndex(4)
            self.set_status(f"Remote target: {target}")

    def _about(self):
        QMessageBox.about(self, f"About {APP_NAME}",
            f"<h2 style='color:#58a6ff'>{APP_NAME}  v{APP_VERSION}</h2>"
            "<p>Enterprise Digital Forensic Analysis Platform</p>"
            "<hr>"
            "<b>Fixes applied:</b><ul>"
            "<li>Email viewer: initialise all state attrs; proper tabbed preview panel</li>"
            "<li>Email viewer: _on_folder_select handles MBOX/EML lists & PST folders</li>"
            "<li>Email viewer: _load_folder_messages stores plain dicts, not pypff refs</li>"
            "<li>Email viewer: _on_message_select safe for all message types</li>"
            "<li>Added _render_msg_table (was called but never defined)</li>"
            "<li>Added missing imports: traceback, email, mailbox</li>"
            "</ul>"
            "<b>New features:</b><ul>"
            "<li>Bookmarks tab with 8 default tags, notes, export, re-tag</li>"
            "<li>Right-click bookmark on artifact list and result table rows</li>"
            "<li>Preview panel below result table (auto-updates on row select)</li>"
            "</ul>")


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor(C['bg']))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor(C['fg']))
    palette.setColor(QPalette.ColorRole.Base,            QColor(C['bg2']))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor(C['row_alt']))
    palette.setColor(QPalette.ColorRole.Text,            QColor(C['fg']))
    palette.setColor(QPalette.ColorRole.Button,          QColor(C['btn']))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor(C['fg']))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor(C['sel']))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(C['accent']))
    palette.setColor(QPalette.ColorRole.ToolTipBase,     QColor(C['bg3']))
    palette.setColor(QPalette.ColorRole.ToolTipText,     QColor(C['fg']))
    app.setPalette(palette)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
