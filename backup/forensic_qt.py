"""
ForensicPro Enterprise v4.0  –  PyQt6 Edition
Digital Forensic Analysis Platform
Classic EnCase / FTK tri-pane layout:
  Left   : Evidence tree (cases, images, disks, folders)
  Top-Right  : File / entry list
  Bottom-Right: Content viewer (Text | Hex | Image | Metadata | PDF-text)
Plus: Artifact Selection, Analysis Results, Timeline, Remote Agent tabs.
"""

import sys, os, re, stat, json, csv, hashlib, datetime, time, threading
import struct, platform, socket, tempfile, shutil, zipfile, base64, subprocess
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
    QScrollBar,
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QRect, QPoint, QMimeData,
    QSortFilterProxyModel, QModelIndex, pyqtSlot, QRunnable, QThreadPool,
    QObject,
)
from PyQt6.QtGui import (
    QFont, QFontMetrics, QColor, QPalette, QIcon, QPixmap, QImage,
    QTextCursor, QTextCharFormat, QSyntaxHighlighter, QBrush, QPainter,
    QLinearGradient, QAction as QGuiAction,
)

# ══════════════════════════════════════════════════════════════
#  PALETTE / THEME
# ══════════════════════════════════════════════════════════════
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
    padding: 5px 14px;
    font-size: 9pt;
}}
QPushButton:hover  {{ background: {C['btn_hover']}; color: {C['accent']}; border-color: {C['accent']}; }}
QPushButton:pressed{{ background: {C['btn_press']}; }}
QPushButton#accent {{
    background: {C['accent']};
    color: #000;
    border: none;
    font-weight: bold;
}}
QPushButton#accent:hover {{ background: #79c0ff; }}
QPushButton#danger {{
    background: {C['red']};
    color: #fff;
    border: none;
    font-weight: bold;
}}

QSplitter::handle {{ background: {C['border']}; }}
QSplitter::handle:horizontal {{ width: 2px; }}
QSplitter::handle:vertical   {{ height: 2px; }}

QTreeWidget, QTreeView {{
    background: {C['sidebar']};
    color: {C['fg']};
    border: none;
    outline: none;
    alternate-background-color: {C['bg2']};
    selection-background-color: {C['sel']};
    selection-color: {C['accent']};
    font-size: 9pt;
}}
QTreeWidget::item {{ padding: 3px 2px; }}
QTreeWidget::item:hover {{ background: {C['bg3']}; }}
QTreeWidget::item:selected {{ background: {C['sel']}; color: {C['accent']}; }}
QTreeWidget::branch:has-children:!has-siblings:closed,
QTreeWidget::branch:closed:has-children:has-siblings {{
    image: none;
    border-image: none;
}}

QTableWidget, QTableView {{
    background: {C['panel']};
    color: {C['fg']};
    gridline-color: {C['border']};
    border: none;
    outline: none;
    alternate-background-color: {C['row_alt']};
    selection-background-color: {C['sel']};
    selection-color: {C['accent']};
}}
QHeaderView::section {{
    background: {C['bg3']};
    color: {C['fg2']};
    border: none;
    border-right: 1px solid {C['border']};
    border-bottom: 1px solid {C['border']};
    padding: 4px 8px;
    font-weight: bold;
    font-size: 8pt;
}}
QHeaderView::section:hover {{ background: {C['btn_hover']}; color: {C['fg']}; }}

QTabWidget::pane {{
    border: 1px solid {C['border']};
    background: {C['bg']};
    top: -1px;
}}
QTabBar::tab {{
    background: {C['bg3']};
    color: {C['fg2']};
    border: 1px solid {C['border']};
    border-bottom: none;
    padding: 6px 16px;
    margin-right: 1px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    font-size: 9pt;
}}
QTabBar::tab:selected {{ background: {C['bg']}; color: {C['accent']}; border-bottom: 2px solid {C['accent']}; }}
QTabBar::tab:hover:!selected {{ background: {C['btn_hover']}; color: {C['fg']}; }}

QTextEdit, QPlainTextEdit {{
    background: {C['bg']};
    color: {C['fg']};
    border: none;
    selection-background-color: {C['sel']};
    font-family: "Consolas", "Cascadia Code", "Courier New", monospace;
    font-size: 9pt;
}}
QLineEdit {{
    background: {C['bg2']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 4px 8px;
    selection-background-color: {C['sel']};
}}
QLineEdit:focus {{ border-color: {C['accent']}; }}
QComboBox {{
    background: {C['bg2']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    padding: 4px 8px;
}}
QComboBox::drop-down {{ border: none; width: 20px; }}
QComboBox QAbstractItemView {{
    background: {C['bg2']};
    color: {C['fg']};
    border: 1px solid {C['border']};
    selection-background-color: {C['sel']};
}}
QCheckBox {{
    color: {C['fg']};
    spacing: 6px;
}}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {C['border']};
    border-radius: 3px;
    background: {C['bg2']};
}}
QCheckBox::indicator:checked {{
    background: {C['accent']};
    border-color: {C['accent']};
}}
QScrollBar:vertical {{
    background: {C['bg']};
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {C['bg3']};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {C['fg3']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{
    background: {C['bg']};
    height: 8px;
    border: none;
}}
QScrollBar::handle:horizontal {{
    background: {C['bg3']};
    border-radius: 4px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{ background: {C['fg3']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QProgressBar {{
    background: {C['bg2']};
    border: 1px solid {C['border']};
    border-radius: 3px;
    text-align: center;
    color: {C['fg']};
    height: 14px;
    font-size: 8pt;
}}
QProgressBar::chunk {{
    background: {C['accent']};
    border-radius: 3px;
}}
QStatusBar {{
    background: {C['bg3']};
    color: {C['fg2']};
    border-top: 1px solid {C['border']};
    font-size: 8pt;
}}
QGroupBox {{
    color: {C['fg2']};
    border: 1px solid {C['border']};
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 6px;
    font-size: 8pt;
    font-weight: bold;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: {C['fg2']};
}}
QListWidget {{
    background: {C['sidebar']};
    color: {C['fg']};
    border: none;
    outline: none;
    alternate-background-color: {C['bg2']};
}}
QListWidget::item {{ padding: 4px 8px; }}
QListWidget::item:selected {{ background: {C['sel']}; color: {C['accent']}; }}
QListWidget::item:hover {{ background: {C['bg3']}; }}
QLabel#section_header {{
    background: {C['bg3']};
    color: {C['fg2']};
    padding: 4px 10px;
    font-size: 8pt;
    font-weight: bold;
    border-bottom: 1px solid {C['border']};
}}
QFrame#separator {{
    background: {C['border']};
    max-height: 1px;
}}
"""

APP_VERSION = "4.0"
APP_NAME    = "ForensicPro Enterprise"

# ══════════════════════════════════════════════════════════════
#  UTILITIES
# ══════════════════════════════════════════════════════════════

def fmt_size(n):
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def fmt_ts(ts):
    try: return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except: return "—"

def md5_path(p, chunk=1<<16):
    h = hashlib.md5()
    try:
        with open(p,"rb") as f:
            while d := f.read(chunk): h.update(d)
        return h.hexdigest()
    except: return "N/A"

def sha256_path(p, chunk=1<<16):
    h = hashlib.sha256()
    try:
        with open(p,"rb") as f:
            while d := f.read(chunk): h.update(d)
        return h.hexdigest()
    except: return "N/A"

def detect_type(path):
    SIGS = [
        (b"\x4D\x5A",           "PE Executable"),
        (b"\x7FELF",            "ELF Binary"),
        (b"\xFF\xD8\xFF",       "JPEG Image"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image"),
        (b"GIF8",               "GIF Image"),
        (b"BM",                 "BMP Image"),
        (b"II\x2A\x00",        "TIFF Image"),
        (b"MM\x00\x2A",        "TIFF Image"),
        (b"%PDF",               "PDF Document"),
        (b"PK\x03\x04",        "ZIP Archive"),
        (b"Rar!",               "RAR Archive"),
        (b"\x1F\x8B",          "GZIP"),
        (b"\xFD7zXZ",          "XZ Archive"),
        (b"7z\xBC\xAF",        "7-Zip Archive"),
        (b"OggS",               "OGG Audio"),
        (b"ID3",                "MP3 Audio"),
        (b"fLaC",               "FLAC Audio"),
        (b"RIFF",               "WAV/AVI"),
        (b"\x00\x00\x00\x18ftyp","MP4 Video"),
        (b"\xD0\xCF\x11\xE0",  "OLE2 / MS Office"),
        (b"SQLite format",      "SQLite Database"),
        (b"ELF",                "ELF Binary"),
    ]
    try:
        with open(path,"rb") as f: hdr = f.read(16)
        for sig, name in SIGS:
            if hdr[:len(sig)] == sig: return name
    except: pass
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

# ══════════════════════════════════════════════════════════════
#  ARTIFACT DEFINITIONS
# ══════════════════════════════════════════════════════════════

ARTIFACT_CATEGORIES = {
    "System Information": [
        "OS Version & Build","Hostname & Domain","Installed Software",
        "Running Processes","Loaded Drivers/Modules","Scheduled Tasks",
        "System Uptime","BIOS/UEFI Info","Hardware Profile",
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
#  LIVE ARTIFACT COLLECTION (worker thread)
# ══════════════════════════════════════════════════════════════

def collect_artifact(name):
    results = []
    try:
        if name == "Running Processes":
            for p in psutil.process_iter(['pid','name','username','status','create_time','exe','memory_info','cpu_percent']):
                try:
                    i = p.info
                    mem = fmt_size(i['memory_info'].rss) if i['memory_info'] else "N/A"
                    results.append({"PID":str(i['pid']),"Name":i['name'] or "","User":i['username'] or "",
                        "Status":i['status'],"Memory":mem,
                        "Started":fmt_ts(i['create_time']) if i['create_time'] else "","Path":i['exe'] or ""})
                except: pass

        elif name == "Active Connections":
            for c in psutil.net_connections(kind='inet'):
                try:
                    la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    try: pn = psutil.Process(c.pid).name() if c.pid else ""
                    except: pn = ""
                    results.append({"PID":str(c.pid) if c.pid else "","Process":pn,
                        "Proto":c.type.name if hasattr(c.type,"name") else str(c.type),
                        "Local":la,"Remote":ra,"Status":c.status})
                except: pass

        elif name == "Network Interfaces":
            for iface, addrs in psutil.net_if_addrs().items():
                st = psutil.net_if_stats().get(iface)
                for a in addrs:
                    results.append({"Interface":iface,"Family":str(a.family),
                        "Address":a.address,"Netmask":a.netmask or "",
                        "Speed":f"{st.speed}Mbps" if st else "",
                        "Up":"Yes" if (st and st.isup) else "No"})

        elif name == "OS Version & Build":
            u = platform.uname()
            results.append({"System":u.system,"Node":u.node,"Release":u.release,
                "Version":u.version,"Machine":u.machine,"Processor":u.processor,
                "Python":sys.version.split()[0]})

        elif name == "Hostname & Domain":
            results.append({"Hostname":socket.gethostname(),"FQDN":socket.getfqdn(),
                "IP":socket.gethostbyname(socket.gethostname())})

        elif name == "System Uptime":
            boot = datetime.datetime.fromtimestamp(psutil.boot_time())
            up   = datetime.datetime.now() - boot
            m    = psutil.virtual_memory()
            d    = psutil.disk_usage('/')
            results.append({"Boot":boot.strftime("%Y-%m-%d %H:%M:%S"),
                "Uptime":str(up).split('.')[0],
                "RAM Total":fmt_size(m.total),"RAM Used":fmt_size(m.used),"RAM %":f"{m.percent}%",
                "Disk Total":fmt_size(d.total),"Disk Used":fmt_size(d.used),"Disk %":f"{d.percent}%"})

        elif name == "Hardware Profile":
            cpu = psutil.cpu_freq()
            results.append({"CPU Physical":str(psutil.cpu_count(logical=False)),
                "CPU Logical":str(psutil.cpu_count(logical=True)),
                "CPU MHz":f"{cpu.current:.0f}" if cpu else "N/A",
                "CPU Usage":f"{psutil.cpu_percent(interval=0.3)}%",
                "RAM":fmt_size(psutil.virtual_memory().total),
                "Swap":fmt_size(psutil.swap_memory().total)})
            for i, d in enumerate(psutil.disk_partitions()):
                try:
                    u = psutil.disk_usage(d.mountpoint)
                    results.append({"#":f"Disk {i+1}","Device":d.device,"Mount":d.mountpoint,
                        "FS":d.fstype,"Total":fmt_size(u.total),"Used":fmt_size(u.used),"Free":fmt_size(u.free)})
                except: pass

        elif name == "Local User Accounts":
            for u in psutil.users():
                results.append({"User":u.name,"Terminal":u.terminal or "","Host":u.host or "",
                    "Started":fmt_ts(u.started)})

        elif name == "Recently Accessed Files":
            home = Path.home()
            found = []
            for d in [home, home/"Documents", home/"Downloads", home/"Desktop"]:
                if d.exists():
                    for f in d.iterdir():
                        if f.is_file():
                            try:
                                s = f.stat()
                                found.append((s.st_atime, f, s))
                            except: pass
            found.sort(reverse=True)
            for at, f, s in found[:50]:
                results.append({"File":f.name,"Dir":str(f.parent),"Size":fmt_size(s.st_size),
                    "Accessed":fmt_ts(s.st_atime),"Modified":fmt_ts(s.st_mtime),"Type":detect_type(str(f))})

        elif name == "Temp Directory Contents":
            tmp = tempfile.gettempdir()
            for f in sorted(os.listdir(tmp))[:60]:
                fp = os.path.join(tmp, f)
                try:
                    s = os.stat(fp)
                    results.append({"Name":f,"IsDir":"Yes" if os.path.isdir(fp) else "No",
                        "Size":fmt_size(s.st_size) if os.path.isfile(fp) else "—",
                        "Created":fmt_ts(s.st_ctime),"Modified":fmt_ts(s.st_mtime)})
                except: pass

        elif name == "Installed Software":
            if platform.system() == "Linux":
                try:
                    out = subprocess.check_output(["dpkg","-l"], text=True, timeout=10)
                    for line in out.splitlines()[5:80]:
                        pts = line.split()
                        if len(pts) >= 3 and pts[0] == "ii":
                            results.append({"Package":pts[1],"Version":pts[2],"Status":"Installed"})
                except Exception as e:
                    results.append({"Error":str(e)})

        elif name == "Scheduled Tasks":
            if platform.system() == "Linux":
                for cp in ["/etc/crontab","/etc/cron.d","/var/spool/cron"]:
                    if os.path.isdir(cp):
                        for f in os.listdir(cp)[:20]:
                            fp = os.path.join(cp, f)
                            try:
                                s = os.stat(fp)
                                results.append({"Path":fp,"Modified":fmt_ts(s.st_mtime),"Type":"cron"})
                            except: pass
                    elif os.path.isfile(cp):
                        try:
                            s = os.stat(cp)
                            results.append({"Path":cp,"Modified":fmt_ts(s.st_mtime),"Type":"crontab"})
                        except: pass
        else:
            results.append({"Artifact":name,"Status":"Collected",
                "Timestamp":datetime.datetime.now().strftime("%H:%M:%S"),
                "Note":"Deploy agent for full OS-level collection."})
    except Exception as e:
        results.append({"Error":str(e),"Artifact":name})
    return results

# ══════════════════════════════════════════════════════════════
#  WORKER THREADS
# ══════════════════════════════════════════════════════════════

class ArtifactWorker(QThread):
    progress   = pyqtSignal(int, int, str)   # current, total, name
    result     = pyqtSignal(str, list)        # name, rows
    finished   = pyqtSignal()

    def __init__(self, names):
        super().__init__()
        self.names = names

    def run(self):
        total = len(self.names)
        for i, name in enumerate(self.names):
            self.progress.emit(i+1, total, name)
            rows = collect_artifact(name)
            self.result.emit(name, rows)
        self.finished.emit()


class HashWorker(QThread):
    done = pyqtSignal(str, str, str)   # path, md5, sha256
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

        # Toolbar
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

        # Split: hex | ascii
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)

        # Header row
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0,0,0,0)
        cl.setSpacing(0)

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
        cl.addWidget(hdr)

        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setReadOnly(True)
        self.hex_edit.setStyleSheet(
            f"background:{C['bg']};color:{C['green']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:9pt;border:none;padding:4px 8px;"
        )
        self.hex_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        cl.addWidget(self.hex_edit)
        lay.addWidget(content)

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
            self.size_label.setText(
                f"  {fmt_size(os.path.getsize(path))}"
                + ("  (first 1 MB shown)" if os.path.getsize(path) > max_bytes else "")
            )
            self._render()
        except Exception as e:
            self.hex_edit.setPlainText(f"[Cannot read: {e}]")

    def _render(self):
        PAGE = 4096
        chunk = self.data[self.offset: self.offset + PAGE]
        lines = []
        for i in range(0, len(chunk), 16):
            row = chunk[i:i+16]
            addr = self.offset + i
            h1 = " ".join(f"{b:02X}" for b in row[:8])
            h2 = " ".join(f"{b:02X}" for b in row[8:])
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            lines.append(f"  {addr:08X}   {h1:<23}  {h2:<23}   {asc}")
        self.hex_edit.setPlainText("\n".join(lines))
        self.offset_edit.setText(f"0x{self.offset:08X}")

    def _jump(self):
        try:
            val = int(self.offset_edit.text(), 0)
            self.offset = max(0, min(val, len(self.data)-1))
            self._render()
        except: pass

    def _prev_page(self):
        self.offset = max(0, self.offset - 4096)
        self._render()

    def _next_page(self):
        self.offset = min(len(self.data) - 1, self.offset + 4096)
        self._render()

# ══════════════════════════════════════════════════════════════
#  CONTENT VIEWER (tabbed: Text | Hex | Image | Metadata)
# ══════════════════════════════════════════════════════════════

class ContentViewer(QWidget):
    def __init__(self):
        super().__init__()
        self._current_path = None
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        # Mode toolbar
        tb = QWidget()
        tb.setFixedHeight(34)
        tb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(6,3,6,3)
        tbl.setSpacing(2)

        self.mode_btns = {}
        for mode in ["Text","Hex","Image","Metadata","Strings"]:
            btn = QPushButton(mode)
            btn.setCheckable(True)
            btn.setFixedHeight(24)
            btn.setStyleSheet(f"""
                QPushButton {{ background:{C['btn']}; color:{C['fg2']}; border:1px solid {C['border']};
                    border-radius:3px; padding:2px 10px; font-size:8pt; }}
                QPushButton:checked {{ background:{C['sel']}; color:{C['accent']};
                    border-color:{C['accent']}; }}
                QPushButton:hover {{ color:{C['fg']}; }}
            """)
            btn.clicked.connect(lambda _, m=mode: self._switch_mode(m))
            tbl.addWidget(btn)
            self.mode_btns[mode] = btn
        tbl.addStretch()

        self.path_label = QLabel("")
        self.path_label.setStyleSheet(f"color:{C['fg2']};font-size:8pt;")
        tbl.addWidget(self.path_label)
        lay.addWidget(tb)

        # Stacked content
        self.stack = QStackedWidget()

        # Text
        self.text_view = QPlainTextEdit()
        self.text_view.setReadOnly(True)
        self.text_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.stack.addWidget(self.text_view)             # 0

        # Hex
        self.hex_view = HexViewer()
        self.stack.addWidget(self.hex_view)              # 1

        # Image
        img_scroll = QScrollArea()
        img_scroll.setWidgetResizable(True)
        img_scroll.setStyleSheet(f"background:{C['bg']};border:none;")
        self.image_label = QLabel(alignment=Qt.AlignmentFlag.AlignCenter)
        self.image_label.setStyleSheet(f"background:{C['bg']};")
        img_scroll.setWidget(self.image_label)
        self.stack.addWidget(img_scroll)                 # 2

        # Metadata
        self.meta_table = QTableWidget(0, 2)
        self.meta_table.setHorizontalHeaderLabels(["Property","Value"])
        self.meta_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.meta_table.verticalHeader().setVisible(False)
        self.meta_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.meta_table.setAlternatingRowColors(True)
        self.stack.addWidget(self.meta_table)            # 3

        # Strings
        self.strings_view = QPlainTextEdit()
        self.strings_view.setReadOnly(True)
        self.strings_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.strings_view.setStyleSheet(
            f"background:{C['bg']};color:{C['orange']};"
            f"font-family:'Consolas','Courier New',monospace;font-size:9pt;"
        )
        self.stack.addWidget(self.strings_view)          # 4

        lay.addWidget(self.stack)
        self._switch_mode("Text")

    def _switch_mode(self, mode):
        idx = {"Text":0,"Hex":1,"Image":2,"Metadata":3,"Strings":4}[mode]
        self.stack.setCurrentIndex(idx)
        for m, btn in self.mode_btns.items():
            btn.setChecked(m == mode)
        if self._current_path:
            self._load_for_mode(self._current_path, mode)

    def load_path(self, path: str):
        self._current_path = path
        self.path_label.setText(os.path.basename(path))
        mode = ["Text","Hex","Image","Metadata","Strings"][self.stack.currentIndex()]
        self._load_for_mode(path, mode)

    def load_bytes(self, data: bytes, name: str = ""):
        self._current_path = None
        self.path_label.setText(name)
        self.hex_view.load_data(data)
        try:
            txt = data.decode("utf-8","replace")
            self.text_view.setPlainText(txt[:200_000])
        except:
            self.text_view.setPlainText("[Binary data]")

    def clear(self):
        self._current_path = None
        self.path_label.setText("")
        self.text_view.clear()
        self.hex_view.load_data(b"")
        self.image_label.clear()
        self.meta_table.setRowCount(0)
        self.strings_view.clear()

    def _load_for_mode(self, path: str, mode: str):
        if mode == "Text":   self._load_text(path)
        elif mode == "Hex":  self.hex_view.load_file(path)
        elif mode == "Image":self._load_image(path)
        elif mode == "Metadata": self._load_meta(path)
        elif mode == "Strings":  self._load_strings(path)

    def _load_text(self, path):
        try:
            size = os.path.getsize(path)
            if size > 10 * 1024 * 1024:
                self.text_view.setPlainText(f"[File too large to display as text: {fmt_size(size)}]")
                return
            with open(path,"rb") as f:
                raw = f.read(500_000)
            # Detect encoding
            for enc in ("utf-8","latin-1","utf-16","ascii"):
                try:
                    text = raw.decode(enc)
                    self.text_view.setPlainText(text)
                    return
                except: pass
            # Binary preview as hex-text
            lines = []
            for i in range(0, min(len(raw), 4096), 16):
                row = raw[i:i+16]
                h = " ".join(f"{b:02X}" for b in row)
                a = "".join(chr(b) if 32<=b<127 else "." for b in row)
                lines.append(f"{i:08X}  {h:<47}  {a}")
            self.text_view.setPlainText("\n".join(lines))
        except Exception as e:
            self.text_view.setPlainText(f"[Error: {e}]")

    def _load_image(self, path):
        pix = QPixmap(path)
        if pix.isNull():
            # Try raw bytes
            try:
                with open(path,"rb") as f:
                    data = f.read()
                img = QImage.fromData(data)
                if not img.isNull():
                    pix = QPixmap.fromImage(img)
            except: pass
        if pix.isNull():
            self.image_label.setText(
                f'<span style="color:{C["fg2"]}">[ No image preview available ]</span>')
        else:
            scaled = pix.scaled(
                self.image_label.parent().width() - 20,
                self.image_label.parent().height() - 20,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self.image_label.setPixmap(scaled)

    def _load_meta(self, path):
        self.meta_table.setRowCount(0)
        rows = []
        try:
            s = os.stat(path)
            rows = [
                ("Name",        os.path.basename(path)),
                ("Full Path",   path),
                ("Size",        f"{fmt_size(s.st_size)}  ({s.st_size:,} bytes)"),
                ("Type",        detect_type(path)),
                ("Extension",   Path(path).suffix or "(none)"),
                ("Created",     fmt_ts(s.st_ctime)),
                ("Modified",    fmt_ts(s.st_mtime)),
                ("Accessed",    fmt_ts(s.st_atime)),
                ("Permissions", oct(stat.S_IMODE(s.st_mode))),
                ("Inode",       str(s.st_ino)),
                ("Hard Links",  str(s.st_nlink)),
                ("UID",         str(s.st_uid)),
                ("GID",         str(s.st_gid)),
            ]
            if s.st_size < 64 * 1024 * 1024:
                rows.append(("MD5",    md5_path(path)))
                rows.append(("SHA-256",sha256_path(path)))
        except Exception as e:
            rows = [("Error", str(e))]
        for prop, val in rows:
            r = self.meta_table.rowCount()
            self.meta_table.insertRow(r)
            p_item = QTableWidgetItem(prop)
            p_item.setForeground(QBrush(QColor(C['fg2'])))
            v_item = QTableWidgetItem(val)
            self.meta_table.setItem(r, 0, p_item)
            self.meta_table.setItem(r, 1, v_item)

    def _load_strings(self, path):
        try:
            with open(path,"rb") as f:
                data = f.read(4 * 1024 * 1024)
            strings = []
            cur = []
            for b in data:
                if 32 <= b < 127:
                    cur.append(chr(b))
                else:
                    if len(cur) >= 4:
                        strings.append("".join(cur))
                    cur = []
            if len(cur) >= 4:
                strings.append("".join(cur))
            self.strings_view.setPlainText(
                f"[{len(strings)} strings found]\n\n" + "\n".join(strings[:5000]))
        except Exception as e:
            self.strings_view.setPlainText(f"[Error: {e}]")

# ══════════════════════════════════════════════════════════════
#  EVIDENCE BROWSER  (classic 3-pane)
# ══════════════════════════════════════════════════════════════

class EvidenceBrowser(QWidget):
    def __init__(self, main_win):
        super().__init__()
        self.main = main_win
        self.current_dir = Path.home()
        self._setup()
        self._populate_tree_root()
        self._load_dir(self.current_dir)

    def _setup(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        # ── Outer horizontal splitter ──────────────────
        h_split = QSplitter(Qt.Orientation.Horizontal)
        h_split.setHandleWidth(2)

        # ── LEFT: folder/evidence tree ─────────────────
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

        # ── RIGHT: vertical splitter (list top | viewer bottom) ──
        v_split = QSplitter(Qt.Orientation.Vertical)
        v_split.setHandleWidth(2)

        # Top-right: file list
        right_top = QWidget()
        rtl = QVBoxLayout(right_top)
        rtl.setContentsMargins(0,0,0,0)
        rtl.setSpacing(0)

        # Path bar
        pb = QWidget()
        pb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        pbl = QHBoxLayout(pb)
        pbl.setContentsMargins(6,3,6,3)
        pbl.setSpacing(4)
        up_btn = QPushButton("↑")
        up_btn.setFixedSize(26,26)
        up_btn.setToolTip("Parent directory")
        up_btn.clicked.connect(self._go_up)
        pbl.addWidget(up_btn)
        self.path_edit = QLineEdit(str(Path.home()))
        self.path_edit.returnPressed.connect(self._go_path)
        pbl.addWidget(self.path_edit)
        go_btn = QPushButton("Go")
        go_btn.setFixedWidth(36)
        go_btn.clicked.connect(self._go_path)
        pbl.addWidget(go_btn)
        rtl.addWidget(pb)

        # File list table
        self.file_table = QTableWidget(0, 6)
        self.file_table.setHorizontalHeaderLabels(
            ["Name","Size","Type","Modified","Created","Permissions"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1,6):
            self.file_table.horizontalHeader().setSectionResizeMode(
                i, QHeaderView.ResizeMode.ResizeToContents)
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.file_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.file_table.setAlternatingRowColors(True)
        self.file_table.setSortingEnabled(True)
        self.file_table.doubleClicked.connect(self._on_file_double)
        self.file_table.selectionModel().selectionChanged.connect(self._on_file_select)
        self.file_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_table.customContextMenuRequested.connect(self._file_ctx)
        rtl.addWidget(self.file_table)
        v_split.addWidget(right_top)

        # Bottom-right: content viewer
        bottom_w = QWidget()
        bl = QVBoxLayout(bottom_w)
        bl.setContentsMargins(0,0,0,0)
        bl.setSpacing(0)

        bh = QLabel("  CONTENT VIEWER")
        bh.setObjectName("section_header")
        bl.addWidget(bh)

        self.content = ContentViewer()
        bl.addWidget(self.content)
        v_split.addWidget(bottom_w)

        v_split.setSizes([420, 300])
        h_split.addWidget(v_split)
        h_split.setSizes([240, 900])

        lay.addWidget(h_split)

    # ── Evidence tree population ──────────────
    def _make_item(self, text, icon_text="", color=None, data=None):
        item = QTreeWidgetItem([text])
        if color:
            item.setForeground(0, QBrush(QColor(color)))
        if data:
            item.setData(0, Qt.ItemDataRole.UserRole, data)
        return item

    def _populate_tree_root(self):
        self.ev_tree.clear()

        # Local file system roots
        fs_root = self._make_item("📁  File System", color=C['fg'])
        fs_root.setData(0, Qt.ItemDataRole.UserRole, {"type":"group"})
        self.ev_tree.addTopLevelItem(fs_root)

        home_item = self._make_item(f"🏠  Home ({Path.home().name})",
                                    color=C['accent'],
                                    data={"type":"dir","path":str(Path.home())})
        fs_root.addChild(home_item)

        for part in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(part.mountpoint)
                pct = u.percent
                label = f"💾  {part.device}  [{part.fstype}]  {pct:.0f}%"
                item = self._make_item(label, color=C['orange'],
                                       data={"type":"dir","path":part.mountpoint})
                fs_root.addChild(item)
            except: pass

        # Evidence images
        self.img_root = self._make_item("🖴  Forensic Images", color=C['fg'])
        self.img_root.setData(0, Qt.ItemDataRole.UserRole, {"type":"group"})
        self.ev_tree.addTopLevelItem(self.img_root)

        # Remote targets
        self.remote_root = self._make_item("🌐  Remote Targets", color=C['fg'])
        self.remote_root.setData(0, Qt.ItemDataRole.UserRole, {"type":"group"})
        self.ev_tree.addTopLevelItem(self.remote_root)

        fs_root.setExpanded(True)

    def add_evidence_image(self, path):
        label = f"🖴  {os.path.basename(path)}"
        item = self._make_item(label, color=C['orange'],
                               data={"type":"image","path":path})
        size_item = self._make_item(f"   Size: {fmt_size(os.path.getsize(path))}",
                                    color=C['fg2'])
        type_item = self._make_item(f"   Type: {detect_type(path)}",
                                    color=C['fg2'])
        item.addChild(size_item)
        item.addChild(type_item)
        self.img_root.addChild(item)
        self.img_root.setExpanded(True)

    def add_remote_target(self, label):
        item = self._make_item(f"🌐  {label}", color=C['purple'],
                               data={"type":"remote","label":label})
        self.remote_root.addChild(item)
        self.remote_root.setExpanded(True)

    def _on_tree_select(self, item, _prev):
        if not item: return
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data: return
        if data.get("type") == "dir":
            self._load_dir(Path(data["path"]))

    def _on_file_select(self, selected, _):
        idxs = self.file_table.selectedItems()
        if not idxs: return
        row = self.file_table.currentRow()
        name_item = self.file_table.item(row, 0)
        if not name_item: return
        name = name_item.data(Qt.ItemDataRole.UserRole) or name_item.text()
        path = self.current_dir / name
        if path.is_file():
            self.content.load_path(str(path))

    def _on_file_double(self, index):
        row = index.row()
        name_item = self.file_table.item(row, 0)
        if not name_item: return
        name = name_item.data(Qt.ItemDataRole.UserRole) or name_item.text()
        if name == "..":
            self._go_up(); return
        path = self.current_dir / name
        if path.is_dir():
            self._load_dir(path)

    def _load_dir(self, path: Path):
        self.current_dir = path
        self.path_edit.setText(str(path))
        self.file_table.setSortingEnabled(False)
        self.file_table.setRowCount(0)

        # Parent row
        self._add_file_row("..", True, None)

        try:
            entries = sorted(path.iterdir(),
                             key=lambda x: (not x.is_dir(), x.name.lower()))
        except PermissionError:
            entries = []

        for entry in entries:
            try:
                self._add_file_row(entry.name, entry.is_dir(), entry)
            except: pass

        self.file_table.setSortingEnabled(True)
        self.main.set_status(f"  {path}  —  {len(entries)} item(s)")

        # Sync tree selection
        self._sync_tree_to_path(path)

    def _add_file_row(self, name: str, is_dir: bool, entry):
        row = self.file_table.rowCount()
        self.file_table.insertRow(row)

        icon = "📁" if is_dir else self._file_icon(name)
        display = f"{icon}  {name}"
        name_item = QTableWidgetItem(display)
        name_item.setData(Qt.ItemDataRole.UserRole, name)
        if is_dir:
            name_item.setForeground(QBrush(QColor(C['orange'])))

        self.file_table.setItem(row, 0, name_item)

        if entry and entry.exists():
            try:
                s = entry.stat()
                size_val = s.st_size if entry.is_file() else -1
                size_item = QTableWidgetItem(fmt_size(s.st_size) if entry.is_file() else "")
                size_item.setData(Qt.ItemDataRole.UserRole, size_val)
                size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                size_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 1, size_item)

                ftype = "Directory" if entry.is_dir() else detect_type(str(entry))
                t_item = QTableWidgetItem(ftype)
                t_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 2, t_item)

                mod_item = QTableWidgetItem(fmt_ts(s.st_mtime))
                mod_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 3, mod_item)

                cre_item = QTableWidgetItem(fmt_ts(s.st_ctime))
                cre_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 4, cre_item)

                perm_item = QTableWidgetItem(oct(stat.S_IMODE(s.st_mode)))
                perm_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 5, perm_item)
            except: pass

    def _file_icon(self, name):
        ext = Path(name).suffix.lower()
        icons = {
            ".jpg":"🖼",".jpeg":"🖼",".png":"🖼",".gif":"🖼",".bmp":"🖼",".tiff":"🖼",
            ".mp3":"🎵",".wav":"🎵",".flac":"🎵",".ogg":"🎵",".aac":"🎵",
            ".mp4":"🎬",".avi":"🎬",".mkv":"🎬",".mov":"🎬",
            ".pdf":"📕",
            ".zip":"📦",".rar":"📦",".7z":"📦",".tar":"📦",".gz":"📦",
            ".exe":"⚙",".dll":"⚙",".so":"⚙",
            ".py":"🐍",".js":"📜",".ts":"📜",".sh":"📜",".bat":"📜",".ps1":"📜",
            ".txt":"📝",".log":"📝",".md":"📝",
            ".xml":"🔖",".json":"🔖",".csv":"🔖",".yaml":"🔖",
            ".db":"🗄",".sqlite":"🗄",".sql":"🗄",
            ".e01":"🖴",".dd":"🖴",".img":"🖴",".raw":"🖴",".vmdk":"🖴",
            ".evtx":"📋",".reg":"🔑",".lnk":"🔗",".pf":"⚡",
        }
        return icons.get(ext, "📄")

    def _sync_tree_to_path(self, path):
        pass  # Could highlight matching tree node

    def _go_up(self):
        self._load_dir(self.current_dir.parent)

    def _go_path(self):
        p = Path(self.path_edit.text())
        if p.is_dir():
            self._load_dir(p)
        else:
            QMessageBox.warning(self, "Not found", f"Directory not found:\n{p}")

    def _tree_ctx(self, pos):
        item = self.ev_tree.itemAt(pos)
        if not item: return
        menu = QMenu(self)
        data = item.data(0, Qt.ItemDataRole.UserRole) or {}
        if data.get("type") == "dir":
            menu.addAction("Open", lambda: self._load_dir(Path(data["path"])))
        menu.addAction("Remove", lambda: item.parent().removeChild(item) if item.parent() else None)
        menu.exec(self.ev_tree.mapToGlobal(pos))

    def _file_ctx(self, pos):
        row = self.file_table.rowAt(pos.y())
        if row < 0: return
        name_item = self.file_table.item(row, 0)
        if not name_item: return
        name = name_item.data(Qt.ItemDataRole.UserRole) or name_item.text()
        path = self.current_dir / name
        menu = QMenu(self)
        menu.addAction("Open / Navigate",
            lambda: self._load_dir(path) if path.is_dir() else self.content.load_path(str(path)))
        menu.addAction("View in Hex", lambda: (
            self.content._switch_mode("Hex"),
            self.content.load_path(str(path)) if path.is_file() else None))
        menu.addAction("View Metadata", lambda: (
            self.content._switch_mode("Metadata"),
            self.content.load_path(str(path)) if path.is_file() else None))
        menu.addSeparator()
        menu.addAction("Compute Hashes…", lambda: self._hash_file(path))
        menu.addAction("Add to Evidence", lambda: self.main._add_evidence_from_path(str(path)))
        menu.exec(self.file_table.mapToGlobal(pos))

    def _hash_file(self, path):
        if not path.is_file():
            QMessageBox.information(self,"Hash","Select a file first."); return
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
    process_requested = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self._checks = {}
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12,8,12,8)

        # Header + buttons
        hdr = QHBoxLayout()
        title = QLabel("SELECT ARTIFACTS TO COLLECT")
        title.setStyleSheet(f"color:{C['accent']};font-size:11pt;font-weight:bold;")
        hdr.addWidget(title)
        hdr.addStretch()

        for label, slot in [("✓ All", self._sel_all),
                             ("✗ None", self._sel_none),
                             ("⚡ IR Preset", self._preset_ir),
                             ("🦠 Malware Preset", self._preset_malware)]:
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

        # Scrollable grid of checkboxes
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea{{border:none;background:{C['bg']}}}")
        inner = QWidget()
        inner.setStyleSheet(f"background:{C['bg']};")
        grid = QVBoxLayout(inner)
        grid.setSpacing(2)

        for cat, arts in ARTIFACT_CATEGORIES.items():
            # Category header
            cat_label = QLabel(f"  {cat}")
            cat_label.setStyleSheet(
                f"background:{C['bg3']};color:{C['accent']};"
                f"font-weight:bold;font-size:9pt;padding:5px 8px;"
                f"border-left:3px solid {C['accent']};"
                f"margin-top:8px;"
            )
            grid.addWidget(cat_label)

            # Checkboxes in 3-column grid
            row_widget = QWidget()
            row_widget.setStyleSheet(f"background:{C['bg']};")
            row_lay = QGridLayout(row_widget)
            row_lay.setContentsMargins(20,2,4,2)
            row_lay.setHorizontalSpacing(8)
            row_lay.setVerticalSpacing(1)

            for idx, art in enumerate(arts):
                cb = QCheckBox(art)
                cb.setChecked(True)
                row_lay.addWidget(cb, idx // 3, idx % 3)
                self._checks[art] = cb

            grid.addWidget(row_widget)

        grid.addStretch()
        scroll.setWidget(inner)
        lay.addWidget(scroll)

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
                  "Recently Accessed Files","Loaded Drivers/Modules",
                  "WMI Subscriptions","AppInit DLLs"]:
            if a in self._checks: self._checks[a].setChecked(True)

    def _emit_process(self):
        selected = [n for n,cb in self._checks.items() if cb.isChecked()]
        if not selected:
            QMessageBox.warning(self,"Nothing selected","Select at least one artifact.")
            return
        self.process_requested.emit(selected)

    def get_selected(self):
        return [n for n,cb in self._checks.items() if cb.isChecked()]


# ══════════════════════════════════════════════════════════════
#  RESULTS TAB
# ══════════════════════════════════════════════════════════════

class ResultsTab(QWidget):
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

        # Right: result table
        right = QWidget()
        rl = QVBoxLayout(right)
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
        rl.addWidget(self.result_table)

        # Progress
        self.progress = QProgressBar()
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        rl.addWidget(self.progress)

        split.addWidget(right)
        split.setSizes([220, 900])
        lay.addWidget(split)

    def add_result(self, name: str, rows: list):
        self.results[name] = rows
        item = QListWidgetItem(f"  {name}")
        item.setForeground(QBrush(QColor(C['green'])))
        self.art_list.addItem(item)
        self.art_list.setCurrentRow(self.art_list.count() - 1)

    def set_progress(self, val: int):
        self.progress.setValue(val)

    def clear_all(self):
        self.results.clear()
        self.art_list.clear()
        self.result_table.setRowCount(0)
        self.result_table.setColumnCount(1)
        self.progress.setValue(0)

    def _on_select(self, row):
        if row < 0: return
        name = self.art_list.item(row).text().strip()
        rows = self.results.get(name, [])
        self.result_header.setText(f"  {name}  —  {len(rows)} record(s)")
        self._populate_table(rows)

    def _populate_table(self, rows):
        self.result_table.setSortingEnabled(False)
        self.result_table.setRowCount(0)
        if not rows:
            self.result_table.setColumnCount(1)
            self.result_table.setHorizontalHeaderLabels(["No data"])
            self.row_count_label.setText("")
            return

        cols = list(rows[0].keys())
        self.result_table.setColumnCount(len(cols))
        self.result_table.setHorizontalHeaderLabels(cols)

        for i, cols_w in enumerate(self.result_table.horizontalHeader().count() * [None]):
            self.result_table.horizontalHeader().setSectionResizeMode(
                i, QHeaderView.ResizeMode.ResizeToContents)
        if cols:
            self.result_table.horizontalHeader().setSectionResizeMode(
                len(cols)-1, QHeaderView.ResizeMode.Stretch)

        for r_idx, row in enumerate(rows):
            self.result_table.insertRow(r_idx)
            for c_idx, col in enumerate(cols):
                val = str(row.get(col, ""))
                item = QTableWidgetItem(val)
                item.setForeground(QBrush(QColor(C['fg'])))
                self.result_table.setItem(r_idx, c_idx, item)

        self.result_table.setSortingEnabled(True)
        self.row_count_label.setText(f"{len(rows)} rows")
        self._filter_rows(self.filter_edit.text())

    def _filter_rows(self, text):
        text = text.lower()
        for row in range(self.result_table.rowCount()):
            match = not text or any(
                text in (self.result_table.item(row,col).text() if self.result_table.item(row,col) else "").lower()
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
th{{background:#21262d;color:#8b949e;padding:6px 10px;text-align:left;font-size:0.85em;letter-spacing:.05em}}
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
        lay.setContentsMargins(8,8,8,8)

        hdr = QHBoxLayout()
        title = QLabel("TIMELINE ANALYSIS")
        title.setStyleSheet(f"color:{C['accent']};font-size:11pt;font-weight:bold;")
        hdr.addWidget(title)
        hdr.addStretch()
        build_btn = QPushButton("⟳ Build Timeline from Results")
        build_btn.setObjectName("accent")
        build_btn.clicked.connect(self._build)
        hdr.addWidget(build_btn)
        lay.addLayout(hdr)

        # Filter bar
        fb = QHBoxLayout()
        fb.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search events…")
        self.filter_edit.textChanged.connect(self._filter)
        fb.addWidget(self.filter_edit)
        fb.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["All","Process","Network","File","User","System"])
        self.type_combo.currentTextChanged.connect(self._filter)
        fb.addWidget(self.type_combo)
        self.count_label = QLabel("")
        self.count_label.setStyleSheet(f"color:{C['fg2']};")
        fb.addWidget(self.count_label)
        lay.addLayout(fb)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Timestamp","Event Type","Source","Description"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        lay.addWidget(self.table)

    def build_from(self, results: dict):
        self._all_rows = []
        TYPE_MAP = {
            "Process":"Process","Connection":"Network","Interface":"Network",
            "File":"File","Prefetch":"File","Temp":"File","Recycle":"File",
            "User":"User","Login":"User","Account":"User",
            "OS":"System","System":"System","Hardware":"System","Hostname":"System",
        }
        ts_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for art, rows in results.items():
            etype = next((v for k,v in TYPE_MAP.items() if k in art), "System")
            for row in rows:
                ts = next((str(v) for k,v in row.items()
                           if any(x in k.lower() for x in ("time","date","stamp","started","boot"))), ts_now)
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
            "File":    C['accent'],"User":    C['purple'],"System": C['fg'],
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

    def _build(self):
        QMessageBox.information(self,"Timeline",
            "Run artifact collection first, then the timeline builds automatically.\n"
            "Or click here after collection to refresh.")


# ══════════════════════════════════════════════════════════════
#  REMOTE AGENT TAB
# ══════════════════════════════════════════════════════════════

AGENT_TEMPLATE = '''#!/usr/bin/env python3
"""
ForensicPro Remote Collection Agent  v{version}
Generated : {timestamp}
Case      : {case_name}  ({case_id})
Examiner  : {examiner}
Artifacts : {artifacts_brief}
---
Deploy on remote host with administrator/root privileges.
Usage: python3 forensic_agent.py
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
    print(f"[+] Archive: {{zpath}}")

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

        # ── Left config panel ──────────────────
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
                f"border-bottom:1px solid {C['border']};padding-bottom:4px;"
                f"margin-top:10px;"
            )
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
        cl.addWidget(QLabel("Agent Type"))
        self.f_agent_type = QComboBox()
        self.f_agent_type.addItems(["Python Script (.py)",
                                     "Standalone EXE (PyInstaller)",
                                     "Shell Script (.sh)"])
        cl.addWidget(self.f_agent_type)

        cl.addWidget(QLabel("Artifact Preset"))
        self.f_preset = QComboBox()
        self.f_preset.addItems(["Use Current Selection",
                                  "Quick Triage",
                                  "Full Collection",
                                  "Incident Response",
                                  "Malware Hunt"])
        cl.addWidget(self.f_preset)

        section("ACTIONS")
        for label, method in [
            ("⚙  Generate Agent Code",  self._generate),
            ("💾  Save Agent File…",     self._save),
            ("🚀  Deploy via SSH",       self._deploy_ssh),
            ("📥  Import Agent Results…",self._import_results),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(32)
            if "Generate" in label: btn.setObjectName("accent")
            btn.clicked.connect(method)
            cl.addWidget(btn)

        cl.addStretch()
        cfg_scroll.setWidget(cfg)
        split.addWidget(cfg_scroll)

        # ── Right code panel ──────────────────
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
            f"font-size:9pt;border:none;padding:8px;"
        )
        self.code_edit.setPlainText(
            "# Configure the settings on the left,\n"
            "# then click 'Generate Agent Code'.\n"
        )
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
                    "OS Version & Build","Hostname & Domain","System Uptime",
                    "Local User Accounts","Recently Accessed Files","Temp Directory Contents"]
        elif preset == "Malware Hunt":
            return ["Running Processes","Active Connections","Registry Run Keys",
                    "Scheduled Tasks","Loaded Drivers/Modules","Services (Auto-Start)",
                    "WMI Subscriptions","AppInit DLLs","Recently Accessed Files","Prefetch Files"]
        else:
            arts = self.art_tab.get_selected()
            return arts or ["OS Version & Build","Running Processes"]

    def _generate(self):
        arts = self._get_artifacts()
        ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._code = AGENT_TEMPLATE.format(
            version       = APP_VERSION,
            timestamp     = ts,
            case_name     = self.f_case_name.text() or "Case",
            case_id       = self.f_case_id.text() or "FC-001",
            examiner      = self.f_examiner.text() or "Examiner",
            artifacts_brief = ", ".join(arts[:5]) + (f" +{len(arts)-5} more" if len(arts)>5 else ""),
            artifacts_json  = json.dumps(arts),
            output_dir    = self.f_output_dir.text() or "/tmp/forensic_out",
            server        = self.f_server.text() or "",
        )
        self.code_edit.setPlainText(self._code)

    def _save(self):
        if not self._code:
            QMessageBox.warning(self,"Generate First","Generate the agent code first."); return
        path, _ = QFileDialog.getSaveFileName(self,"Save Agent","forensic_agent.py",
                                               "Python (*.py);;Shell (*.sh);;All (*)")
        if path:
            with open(path,"w") as f: f.write(self._code)
            try: shutil.copy(path, f"/mnt/user-data/outputs/{os.path.basename(path)}")
            except: pass
            QMessageBox.information(self,"Saved",f"Agent saved:\n{path}")

    def _deploy_ssh(self):
        target = self.f_ssh_target.text()
        if not target:
            QMessageBox.warning(self,"SSH","Enter SSH target (user@host)."); return
        if not self._code:
            QMessageBox.warning(self,"Generate","Generate the agent first."); return
        try: import paramiko
        except ImportError:
            QMessageBox.critical(self,"Missing","Install paramiko:\npip install paramiko"); return

        def run():
            try:
                user, host = target.split("@") if "@" in target else ("root", target)
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                passwd = self.f_ssh_pass.text() or None
                client.connect(host, username=user, password=passwd, timeout=15)
                sftp = client.open_sftp()
                rpath = f"/tmp/forensic_agent_{self.f_case_id.text()}.py"
                with sftp.open(rpath,"w") as rf: rf.write(self._code)
                sftp.chmod(rpath, 0o755)
                _, out, err = client.exec_command(f"python3 {rpath} &")
                stdout_data = out.read().decode()
                client.close()
                QMessageBox.information(None,"Deployed",
                    f"Agent deployed to {target}\nPath: {rpath}\n\n{stdout_data[:400]}")
            except Exception as e:
                QMessageBox.critical(None,"SSH Error", str(e))

        threading.Thread(target=run, daemon=True).start()

    def _import_results(self):
        path, _ = QFileDialog.getOpenFileName(self,"Import Agent Results","",
                                               "JSON/ZIP (*.json *.zip);;All (*)")
        if not path: return
        try:
            if path.endswith(".zip"):
                with zipfile.ZipFile(path) as z:
                    names = [n for n in z.namelist() if n.endswith(".json")]
                    if not names: raise ValueError("No JSON in archive")
                    data = json.loads(z.read(names[0]))
            else:
                with open(path) as f: data = json.load(f)
            return data
        except Exception as e:
            QMessageBox.critical(self,"Import Error", str(e))
            return None


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
        self.f_name   = QLineEdit(existing.get("name","New Investigation") if existing else "New Investigation")
        self.f_number = QLineEdit(existing.get("number","FC-2025-001") if existing else "FC-2025-001")
        self.f_examiner = QLineEdit(existing.get("examiner","") if existing else "")
        self.f_notes  = QLineEdit(existing.get("notes","") if existing else "")
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

    # ── Menu ─────────────────────────────────
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
            ("New Case…",              self._new_case),
            ("Open Case…",             self._open_case),
            ("Save Case",              self._save_case),
            None,
            ("Add Evidence File(s)…",  self._add_evidence_files),
            ("Add Forensic Image…",    self._add_image),
            ("Add Local Disk…",        self._add_disk),
            None,
            ("Export Report…",         self._export_report),
            None,
            ("Exit",                   self.close),
        ])
        menu("&Evidence", [
            ("Verify Integrity (Hash All)", self._verify_all),
            ("Remove Selected Evidence",    lambda: None),
            None,
            ("Refresh View",               self._refresh_view),
        ])
        menu("&Analysis", [
            ("Process Selected Artifacts",  self._process_artifacts),
            ("Keyword Search…",             self._keyword_search),
            ("Build Timeline",              self._build_timeline),
        ])
        menu("&Remote", [
            ("Generate Agent…",     lambda: self.tabs.setCurrentIndex(4)),
            ("Connect via SSH…",    self._ssh_connect),
        ])
        menu("&View", [
            ("Evidence Browser",  lambda: self.tabs.setCurrentIndex(0)),
            ("Artifact Selection",lambda: self.tabs.setCurrentIndex(1)),
            ("Analysis Results",  lambda: self.tabs.setCurrentIndex(2)),
            ("Timeline",          lambda: self.tabs.setCurrentIndex(3)),
            ("Remote Agent",      lambda: self.tabs.setCurrentIndex(4)),
        ])
        menu("&Help", [
            ("About", self._about),
        ])

    # ── Toolbar ──────────────────────────────
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
                    f"QToolButton:hover{{background:#79c0ff;}}"
                )
            tb.addWidget(btn)
            return btn

        tbtn("＋ Add Evidence",   self._add_evidence_files, accent=True)
        tbtn("🖴 Add Image",       self._add_image)
        tbtn("💾 Local Disk",      self._add_disk)
        tb.addSeparator()
        tbtn("▶ Process",          self._process_artifacts)
        tbtn("🔍 Search",           self._keyword_search)
        tbtn("📊 Export Report",    self._export_report)
        tb.addSeparator()
        tbtn("⚡ Remote Agent",    lambda: self.tabs.setCurrentIndex(4))
        tbtn("🔐 Verify Hashes",   self._verify_all)
        tb.addSeparator()

        # Case label on right
        spacer = QWidget(); spacer.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)
        self.case_tb_label = QLabel("")
        self.case_tb_label.setStyleSheet(f"color:{C['fg2']};font-size:8pt;padding:0 12px;")
        tb.addWidget(self.case_tb_label)
        self._refresh_case_label()

    # ── Central widget ────────────────────────
    def _build_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Tab 0: Evidence Browser
        self.browser = EvidenceBrowser(self)
        self.tabs.addTab(self.browser, "📂  Evidence Browser")

        # Tab 1: Artifact Selection
        self.art_tab = ArtifactTab()
        self.art_tab.process_requested.connect(self._run_collection)
        self.tabs.addTab(self.art_tab, "🔎  Artifact Selection")

        # Tab 2: Results
        self.results_tab = ResultsTab()
        self.tabs.addTab(self.results_tab, "📋  Analysis Results")

        # Tab 3: Timeline
        self.timeline_tab = TimelineTab()
        self.tabs.addTab(self.timeline_tab, "📅  Timeline")

        # Tab 4: Remote Agent
        self.agent_tab = AgentTab(self.art_tab)
        self.tabs.addTab(self.agent_tab, "⚡  Remote Agent")

        lay.addWidget(self.tabs)

    # ── Status bar ────────────────────────────
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

    # ── Evidence management ───────────────────
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

    def _add_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Add Forensic Image", "",
            "Forensic Images (*.e01 *.dd *.img *.raw *.vmdk *.vhd *.iso *.001);;"
            "All (*)")
        if path:
            self.browser.add_evidence_image(path)
            self.set_status(f"Image loaded: {os.path.basename(path)}")

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
                lb.addItem(f"{p.device}  [{p.fstype}]  {fmt_size(u.total)} total  —  {fmt_size(u.free)} free")
            except:
                lb.addItem(f"{p.device}  [{p.fstype}]")
        lay.addWidget(lb)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        if dlg.exec() and lb.currentRow() >= 0:
            part = parts[lb.currentRow()]
            self.browser.add_evidence_image(part.device)
            self.browser._load_dir(Path(part.mountpoint))
            self.set_status(f"Disk added: {part.device}")

    def _add_evidence_from_path(self, path):
        ext = Path(path).suffix.lower()
        if ext in (".e01",".dd",".img",".raw",".vmdk",".vhd",".iso"):
            self.browser.add_evidence_image(path)
        self.set_status(f"Added to evidence: {os.path.basename(path)}")

    def _refresh_view(self):
        self.browser._load_dir(self.browser.current_dir)

    # ── Artifact collection ───────────────────
    def _process_artifacts(self):
        self.tabs.setCurrentIndex(1)
        self.art_tab._emit_process()

    def _run_collection(self, names: list):
        self.tabs.setCurrentIndex(2)
        self.results_tab.clear_all()
        self.progress_bar.setValue(0)
        self.set_status(f"Collecting {len(names)} artifact(s)…")

        self._worker = ArtifactWorker(names)
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

    # ── Timeline ─────────────────────────────
    def _build_timeline(self):
        self.timeline_tab.build_from(self.artifact_results)
        self.tabs.setCurrentIndex(3)

    # ── Keyword search ────────────────────────
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
            # File system
            for entry in self.browser.current_dir.iterdir():
                if kw in entry.name.lower():
                    r = table.rowCount()
                    table.insertRow(r)
                    table.setItem(r,0,QTableWidgetItem("File System"))
                    table.setItem(r,1,QTableWidgetItem("Name"))
                    table.setItem(r,2,QTableWidgetItem(entry.name))
                    table.setItem(r,3,QTableWidgetItem(str(self.browser.current_dir)))
                    hits += 1
            cnt.setText(f"{hits} hit(s)")

        btn.clicked.connect(do_search)
        q.returnPressed.connect(do_search)
        dlg.exec()

    # ── Verify hashes ─────────────────────────
    def _verify_all(self):
        paths = []
        for i in range(self.browser.img_root.childCount()):
            child = self.browser.img_root.child(i)
            data  = child.data(0, Qt.ItemDataRole.UserRole)
            if data and data.get("path"):
                paths.append(data["path"])
        if not paths:
            QMessageBox.information(self,"Verify","No forensic images to hash."); return

        self.set_status(f"Hashing {len(paths)} image(s)…")
        def run():
            lines = []
            for p in paths:
                if os.path.isfile(p):
                    m = md5_path(p); s = sha256_path(p)
                    lines.append(f"{os.path.basename(p)}\n  MD5:    {m}\n  SHA-256:{s}\n")
            QMessageBox.information(self,"Hash Results","\n".join(lines) or "No files hashed.")
            self.set_status("Hash verification complete.")
        threading.Thread(target=run, daemon=True).start()

    # ── Case management ───────────────────────
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
            saved = data.get("artifact_results",{})
            for name, rows in saved.items():
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

    # ── Export ───────────────────────────────
    def _export_report(self):
        self.results_tab._export_html()

    # ── SSH connect ───────────────────────────
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
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept); btns.rejected.connect(dlg.reject)
        lay.addRow(btns)
        if dlg.exec():
            target = f"{f_user.text()}@{f_host.text()}"
            self.browser.add_remote_target(target)
            self.agent_tab.f_ssh_target.setText(target)
            self.agent_tab.f_ssh_pass.setText(f_pass.text())
            self.tabs.setCurrentIndex(4)
            self.set_status(f"Remote target: {target}")

    # ── About ────────────────────────────────
    def _about(self):
        QMessageBox.about(self, f"About {APP_NAME}",
            f"<h2 style='color:#58a6ff'>{APP_NAME}  v{APP_VERSION}</h2>"
            "<p>Enterprise Digital Forensic Analysis Platform</p>"
            "<p>Inspired by EnCase Enterprise / FTK</p>"
            "<hr>"
            "<b>Features:</b><ul>"
            "<li>Classic 3-pane EnCase/FTK evidence browser</li>"
            "<li>Multi-format image support (E01, DD, RAW, VMDK…)</li>"
            "<li>Content viewer: Text | Hex | Image | Metadata | Strings</li>"
            "<li>60+ artifact categories with live collection</li>"
            "<li>Remote agent generation & SSH deployment</li>"
            "<li>Timeline analysis & keyword search</li>"
            "<li>HTML / JSON / CSV export</li>"
            "</ul>"
            f"<p style='color:#8b949e'>Python {sys.version.split()[0]} | PyQt6 | psutil | paramiko</p>"
        )


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)

    # Dark palette baseline
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,        QColor(C['bg']))
    palette.setColor(QPalette.ColorRole.WindowText,    QColor(C['fg']))
    palette.setColor(QPalette.ColorRole.Base,          QColor(C['bg2']))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(C['row_alt']))
    palette.setColor(QPalette.ColorRole.Text,          QColor(C['fg']))
    palette.setColor(QPalette.ColorRole.Button,        QColor(C['btn']))
    palette.setColor(QPalette.ColorRole.ButtonText,    QColor(C['fg']))
    palette.setColor(QPalette.ColorRole.Highlight,     QColor(C['sel']))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(C['accent']))
    palette.setColor(QPalette.ColorRole.ToolTipBase,   QColor(C['bg3']))
    palette.setColor(QPalette.ColorRole.ToolTipText,   QColor(C['fg']))
    app.setPalette(palette)

    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
