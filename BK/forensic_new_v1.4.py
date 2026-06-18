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
    QStackedWidget, QFormLayout, QSpinBox,  QToolButton, QAbstractItemView,
    QScrollBar,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QRect, QPoint, QMimeData,
    QSortFilterProxyModel, QModelIndex, pyqtSlot, QRunnable, QThreadPool,
    QObject,
)
from PyQt6.QtGui import (
    QFont, QFontMetrics, QColor, QPalette, QIcon, QPixmap, QImage,
    QTextCursor, QTextCharFormat, QSyntaxHighlighter, QBrush, QPainter,
    QLinearGradient, QAction as QGuiAction,QAction,
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

def fmt_win_filetime(ft):
    """Format a Windows FILETIME (100ns since 1601) as a timestamp string."""
    try:
        if not ft:
            return ""
        return (datetime.datetime(1601, 1, 1) +
                datetime.timedelta(microseconds=ft / 10)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

def _lnk_localpath(data):
    """Best-effort extraction of the LocalBasePath from raw .lnk bytes."""
    if not data or data[:4] != b"\x4c\x00\x00\x00" or len(data) < 76:
        return ""
    try:
        flags  = struct.unpack_from("<I", data, 20)[0]
        offset = 76
        if flags & 0x01:                       # HasLinkTargetIDList
            idl_sz  = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + idl_sz
        if flags & 0x02 and len(data) > offset + 28:   # HasLinkInfo
            lp_off = struct.unpack_from("<I", data, offset + 16)[0]
            raw_p  = data[offset + lp_off:].split(b"\x00")[0]
            return raw_p.decode("latin-1", errors="replace")
    except Exception:
        pass
    return ""

# ══════════════════════════════════════════════════════════════
#  OFFLINE SAM / SYSTEM HIVE HASH EXTRACTOR  (zero third-party deps)
#  --------------------------------------------------------------
#  Pure-Python RC4 + DES + AES-128-CBC and a minimal regf hive
#  reader so NT/LM hashes can be recovered locally from hives that
#  were copied back into the case folder (reg save HKLM\SAM etc.).
#  Uses python-registry if it is installed (consistent with the
#  rest of the app); otherwise falls back to the built-in reader.
#  Algorithm mirrors the well-documented SYSKEY/SAM scheme.
# ══════════════════════════════════════════════════════════════
import struct as _struct
import hashlib as _hashlib

# ── RC4 ───────────────────────────────────────────────────────
def _sam_rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for ch in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

# ── DES (used for the final RID-keyed hash de-obfuscation) ─────
_DES_IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,
           64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
           61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_DES_FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,
           37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
           34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_DES_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
          16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
_DES_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
          2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_DES_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
            60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_DES_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
            41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_DES_SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_DES_SBOX = [
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]

def _des_bits(data):
    out = []
    for byte in data:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out
def _des_frombits(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        out.append(b)
    return bytes(out)
def _des_perm(block, table):
    return [block[x - 1] for x in table]
def _des_subkeys(key8):
    k = _des_perm(_des_bits(key8), _DES_PC1)
    C, D = k[:28], k[28:]; keys = []
    for s in _DES_SHIFT:
        C = C[s:] + C[:s]; D = D[s:] + D[:s]
        keys.append(_des_perm(C + D, _DES_PC2))
    return keys
def _des_block(block_bits, subkeys):
    b = _des_perm(block_bits, _DES_IP); L, R = b[:32], b[32:]
    for sk in subkeys:
        er = _des_perm(R, _DES_E)
        x = [er[i] ^ sk[i] for i in range(48)]; out = []
        for i in range(8):
            c = x[i*6:(i+1)*6]
            row = (c[0] << 1) | c[5]
            col = (c[1] << 3) | (c[2] << 2) | (c[3] << 1) | c[4]
            val = _DES_SBOX[i][row*16 + col]
            out += [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]
        f = _des_perm(out, _DES_P)
        L, R = R, [L[i] ^ f[i] for i in range(32)]
    return _des_perm(R + L, _DES_FP)
def _des_decrypt(key8, data8):
    return _des_frombits(_des_block(_des_bits(data8), list(reversed(_des_subkeys(key8)))))

# ── AES-128-CBC decrypt ───────────────────────────────────────
def _aes_init():
    p = q = 1; sbox = [0]*256; sbox[0] = 0x63
    while True:
        p = p ^ ((p << 1) & 0xff) ^ (0x1b if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff
        if q & 0x80: q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x & 0xff) ^ 0x63
        if p == 1: break
    inv = [0]*256
    for i, v in enumerate(sbox): inv[v] = i
    return sbox, inv
_AES_SBOX, _AES_INV = _aes_init()
_AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
def _aes_xtime(a): return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1)
def _aes_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        a = _aes_xtime(a); b >>= 1
    return r & 0xff
def _aes_key_expansion(key):
    # Supports AES-128/192/256 (key length 16/24/32). Nk = words in key.
    Nk = len(key) // 4
    Nr = Nk + 6
    w = [list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk, 4*(Nr+1)):
        t = list(w[i-1])
        if i % Nk == 0:
            t = t[1:] + t[:1]; t = [_AES_SBOX[b] for b in t]; t[0] ^= _AES_RCON[i//Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            t = [_AES_SBOX[b] for b in t]
        w.append([w[i-Nk][j] ^ t[j] for j in range(4)])
    return w
def _aes_dec_block(w, block):
    Nr = len(w) // 4 - 1
    s = [[block[r + 4*c] for c in range(4)] for r in range(4)]
    for c in range(4):
        for r in range(4): s[r][c] ^= w[Nr*4 + c][r]
    for rnd in range(Nr-1, 0, -1):
        for r in range(1, 4): s[r] = s[r][-r:] + s[r][:-r]          # inv shift rows
        for r in range(4):
            for c in range(4): s[r][c] = _AES_INV[s[r][c]]          # inv sub bytes
        for c in range(4):
            for r in range(4): s[r][c] ^= w[rnd*4 + c][r]           # add round key
        for c in range(4):                                          # inv mix columns
            a = [s[r][c] for r in range(4)]
            s[0][c] = _aes_mul(a[0],14)^_aes_mul(a[1],11)^_aes_mul(a[2],13)^_aes_mul(a[3],9)
            s[1][c] = _aes_mul(a[0],9)^_aes_mul(a[1],14)^_aes_mul(a[2],11)^_aes_mul(a[3],13)
            s[2][c] = _aes_mul(a[0],13)^_aes_mul(a[1],9)^_aes_mul(a[2],14)^_aes_mul(a[3],11)
            s[3][c] = _aes_mul(a[0],11)^_aes_mul(a[1],13)^_aes_mul(a[2],9)^_aes_mul(a[3],14)
    for r in range(1, 4): s[r] = s[r][-r:] + s[r][:-r]
    for r in range(4):
        for c in range(4): s[r][c] = _AES_INV[s[r][c]]
    for c in range(4):
        for r in range(4): s[r][c] ^= w[0 + c][r]
    return bytes(s[r][c] for c in range(4) for r in range(4))
def _aes128_cbc_decrypt(key, iv, data):
    w = _aes_key_expansion(key); out = bytearray(); prev = iv
    for i in range(0, len(data) - (len(data) % 16), 16):
        block = data[i:i+16]
        dec = _aes_dec_block(w, block)
        out += bytes(dec[j] ^ prev[j] for j in range(16)); prev = block
    return bytes(out)

# ── RID -> DES keys ───────────────────────────────────────────
def _str_to_key(s):
    k = [s[0] >> 1,
         ((s[0] & 1) << 6) | (s[1] >> 2),
         ((s[1] & 3) << 5) | (s[2] >> 3),
         ((s[2] & 7) << 4) | (s[3] >> 4),
         ((s[3] & 15) << 3) | (s[4] >> 5),
         ((s[4] & 31) << 2) | (s[5] >> 6),
         ((s[5] & 63) << 1) | (s[6] >> 7),
         s[6] & 127]
    return bytes(((b << 1) & 0xfe) for b in k)
def _sid_to_keys(rid):
    s = _struct.pack("<I", rid)
    k1 = bytes([s[0], s[1], s[2], s[3], s[0], s[1], s[2]])
    k2 = bytes([s[3], s[0], s[1], s[2], s[3], s[0], s[1]])
    return _str_to_key(k1), _str_to_key(k2)
def _des_decode_hash(rid, obf16):
    k1, k2 = _sid_to_keys(rid)
    return _des_decrypt(k1, obf16[:8]) + _des_decrypt(k2, obf16[8:16])

_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

# ── Minimal regf reader (fallback when python-registry absent) ─
class _MiniHive:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.d = f.read()
        if self.d[:4] != b"regf":
            raise ValueError("not a regf hive")
        self.base = 0x1000
        self.root = _struct.unpack_from("<i", self.d, 0x24)[0]
    def _cell(self, off):
        pos = self.base + off
        size = _struct.unpack_from("<i", self.d, pos)[0]
        ln = abs(size) - 4
        return self.d[pos+4: pos+4+ln]
    def _nk(self, off):
        cd = self._cell(off)
        return cd if cd[:2] == b"nk" else None
    def _subkeys(self, nk):
        cnt = _struct.unpack_from("<I", nk, 0x14)[0]
        lst = _struct.unpack_from("<i", nk, 0x1c)[0]
        res = {}
        if cnt == 0 or lst == -1:
            return res
        offs = []
        def walk(cell):
            sig = cell[:2]; n = _struct.unpack_from("<H", cell, 2)[0]
            if sig in (b"lf", b"lh"):
                for i in range(n): offs.append(_struct.unpack_from("<i", cell, 4 + i*8)[0])
            elif sig == b"li":
                for i in range(n): offs.append(_struct.unpack_from("<i", cell, 4 + i*4)[0])
            elif sig == b"ri":
                for i in range(n):
                    walk(self._cell(_struct.unpack_from("<i", cell, 4 + i*4)[0]))
        try:
            walk(self._cell(lst))
        except Exception:
            return res
        for o in offs:
            sk = self._nk(o)
            if not sk:
                continue
            flags = _struct.unpack_from("<H", sk, 2)[0]
            nlen = _struct.unpack_from("<H", sk, 0x48)[0]
            raw = sk[0x4c:0x4c+nlen]
            name = raw.decode("latin-1") if (flags & 0x20) else raw.decode("utf-16le", "replace")
            res[name] = o
        return res
    def _find(self, path):
        off = self.root
        if not path:
            return off
        for part in path.split("\\"):
            if not part:
                continue
            nk = self._nk(off)
            if not nk:
                return None
            subs = self._subkeys(nk)
            match = None
            for k in subs:
                if k.lower() == part.lower():
                    match = subs[k]; break
            if match is None:
                return None
            off = match
        return off
    def value(self, path, vname):
        off = self._find(path)
        if off is None:
            return None
        nk = self._nk(off)
        if not nk:
            return None
        cnt = _struct.unpack_from("<I", nk, 0x24)[0]
        vlist = _struct.unpack_from("<i", nk, 0x28)[0]
        if cnt == 0 or vlist == -1:
            return None
        vl = self._cell(vlist)
        for i in range(cnt):
            voff = _struct.unpack_from("<i", vl, i*4)[0]
            vk = self._cell(voff)
            if vk[:2] != b"vk":
                continue
            nlen = _struct.unpack_from("<H", vk, 2)[0]
            dlen = _struct.unpack_from("<I", vk, 4)[0]
            doff = _struct.unpack_from("<i", vk, 8)[0]
            vflags = _struct.unpack_from("<H", vk, 0x10)[0]
            nm = vk[0x14:0x14+nlen]
            nm = nm.decode("latin-1") if (vflags & 1) else nm.decode("utf-16le", "replace")
            if nm.lower() != vname.lower():
                continue
            rl = dlen & 0x7fffffff
            if dlen & 0x80000000:
                return _struct.pack("<i", doff)[:rl]
            return bytes(self._cell(doff)[:rl])
        return None
    def classname(self, path):
        off = self._find(path)
        if off is None:
            return ""
        nk = self._nk(off)
        if not nk:
            return ""
        cnoff = _struct.unpack_from("<i", nk, 0x30)[0]
        cnlen = _struct.unpack_from("<H", nk, 0x4a)[0]
        if cnoff == -1 or cnlen == 0:
            return ""
        return self._cell(cnoff)[:cnlen].decode("utf-16le", "replace")
    def subkey_names(self, path):
        off = self._find(path)
        if off is None:
            return []
        nk = self._nk(off)
        return list(self._subkeys(nk).keys()) if nk else []
    def value_names(self, path):
        off = self._find(path)
        if off is None:
            return []
        nk = self._nk(off)
        if not nk:
            return []
        cnt = _struct.unpack_from("<I", nk, 0x24)[0]
        vlist = _struct.unpack_from("<i", nk, 0x28)[0]
        if cnt == 0 or vlist == -1:
            return []
        try:
            vl = self._cell(vlist)
        except Exception:
            return []
        names = []
        for i in range(cnt):
            try:
                voff = _struct.unpack_from("<i", vl, i*4)[0]
                vk = self._cell(voff)
                if vk[:2] != b"vk":
                    continue
                nlen = _struct.unpack_from("<H", vk, 2)[0]
                vflags = _struct.unpack_from("<H", vk, 0x10)[0]
                nm = vk[0x14:0x14+nlen]
                nm = nm.decode("latin-1") if (vflags & 1) else nm.decode("utf-16le", "replace")
                names.append(nm)
            except Exception:
                continue
        return names

# ── Hive abstraction (python-registry primary, MiniHive fallback)
class _Hive:
    def __init__(self, path):
        self.path = path; self.kind = None; self.reg = None; self.mh = None
        self._mh_fallback = None
        try:
            from Registry import Registry as _Reg
            self.reg = _Reg.Registry(path); self.kind = "pyreg"
        except Exception:
            self.mh = _MiniHive(path); self.kind = "mini"
    def value(self, keypath, valname):
        if self.kind == "pyreg":
            try:
                return self.reg.open(keypath).value(valname).value()
            except Exception:
                return None
        return self.mh.value(keypath, valname)
    def classname(self, keypath):
        if self.kind == "pyreg":
            try:
                k = self.reg.open(keypath)
                nk = getattr(k, "_nkrecord", None)
                if nk is not None and hasattr(nk, "classname"):
                    cn = nk.classname()
                    if cn:
                        return cn
            except Exception:
                pass
            # python-registry does not always surface class names cleanly;
            # fall back to the built-in reader for this hive.
            try:
                if self._mh_fallback is None:
                    self._mh_fallback = _MiniHive(self.path)
                return self._mh_fallback.classname(keypath)
            except Exception:
                return ""
        return self.mh.classname(keypath)
    def subkey_names(self, keypath):
        if self.kind == "pyreg":
            try:
                return [s.name() for s in self.reg.open(keypath).subkeys()]
            except Exception:
                return []
        return self.mh.subkey_names(keypath)
    def value_names(self, keypath):
        if self.kind == "pyreg":
            try:
                return [v.name() for v in self.reg.open(keypath).values()]
            except Exception:
                return []
        return self.mh.value_names(keypath)

def _control_set(system_hive):
    cur = system_hive.value("Select", "Current")
    if isinstance(cur, int):
        return cur
    if isinstance(cur, (bytes, bytearray)) and len(cur) >= 4:
        return _struct.unpack_from("<I", cur, 0)[0]
    return 1

def _get_bootkey(system_path):
    h = _Hive(system_path)
    candidates = []
    try:
        candidates.append("ControlSet%03d\\Control\\Lsa" % _control_set(h))
    except Exception:
        pass
    candidates += ["ControlSet001\\Control\\Lsa", "CurrentControlSet\\Control\\Lsa"]
    perm = [0x8,0x5,0x4,0x2,0xb,0x9,0xd,0x3,0x0,0x6,0x1,0xc,0xe,0xa,0xf,0x7]
    for lsa in candidates:
        scrambled = ""
        for sub in ("JD", "Skew1", "GBG", "Data"):
            cn = h.classname(lsa + "\\" + sub)
            if not cn:
                scrambled = ""; break
            scrambled += cn
        if len(scrambled) == 32:
            try:
                raw = bytes.fromhex(scrambled)
                return bytes(raw[perm[i]] for i in range(16))
            except Exception:
                continue
    return None

def _hashed_bootkey(sam_f, bootkey):
    rev = sam_f[0]
    if rev == 2:
        qwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
        digits = b"0123456789012345678901234567890123456789\x00"
        rc4key = _hashlib.md5(sam_f[0x70:0x80] + qwerty + bootkey + digits).digest()
        return _sam_rc4(rc4key, sam_f[0x80:0xA0]), 2
    elif rev == 3:
        data_len = _struct.unpack_from("<I", sam_f, 0x94)[0]
        salt = sam_f[0x98:0xA8]
        enc  = sam_f[0xA8:0xA8 + data_len]
        return _aes128_cbc_decrypt(bootkey, salt, enc), 3
    return None, rev

def _decrypt_user_hash(hbootkey, rid, enc_blob, kind, is_lm):
    """enc_blob is the SAM_HASH / SAM_HASH_AES structure bytes for one hash."""
    label = b"LMPASSWORD\x00" if is_lm else b"NTPASSWORD\x00"
    if kind == 2:                                   # RC4 family
        if len(enc_blob) < 0x14:
            return None
        enc = enc_blob[4:4+16]
        rc4key = _hashlib.md5(hbootkey[:0x10] + _struct.pack("<I", rid) + label).digest()
        obf = _sam_rc4(rc4key, enc)
        return _des_decode_hash(rid, obf)
    else:                                           # AES family
        if len(enc_blob) < 0x18:
            return None
        salt = enc_blob[8:24]
        data = enc_blob[24:24+16]
        if len(data) < 16:
            return None
        obf = _aes128_cbc_decrypt(hbootkey, salt, data)[:16]
        return _des_decode_hash(rid, obf)

def extract_sam_hashes(sam_path, system_path):
    """Return a list of {'Username','RID','LM Hash','NT Hash',...} dicts.

    On any failure returns a single-element list with a 'Note'/'Error' key so
    the caller can surface it in the results grid instead of crashing.
    """
    import os as _os
    if not (sam_path and system_path and _os.path.exists(sam_path) and _os.path.exists(system_path)):
        return [{"Note": "SAM and SYSTEM hives are both required for hash extraction."}]
    try:
        bootkey = _get_bootkey(system_path)
        if not bootkey:
            return [{"Error": "Could not derive boot key (SYSKEY) from SYSTEM hive."}]
        sam = _Hive(sam_path)
        F = sam.value("SAM\\Domains\\Account", "F")
        if not F:
            return [{"Error": "SAM\\Domains\\Account 'F' value not found."}]
        hbootkey, kind = _hashed_bootkey(F, bootkey)
        if not hbootkey:
            return [{"Error": "Unsupported SAM revision (F[0]=%d)." % F[0]}]
        rows = []
        users_path = "SAM\\Domains\\Account\\Users"
        for rid_name in sam.subkey_names(users_path):
            if not rid_name or rid_name.lower() == "names":
                continue
            try:
                rid = int(rid_name, 16)
            except ValueError:
                continue
            V = sam.value(users_path + "\\" + rid_name, "V")
            if not V or len(V) < 0xCC:
                continue
            try:
                name_off = _struct.unpack_from("<I", V, 0x0c)[0] + 0xCC
                name_len = _struct.unpack_from("<I", V, 0x10)[0]
                username = V[name_off:name_off+name_len].decode("utf-16le", "replace")
            except Exception:
                username = rid_name
            try:
                lm_off = _struct.unpack_from("<I", V, 0x9c)[0] + 0xCC
                lm_len = _struct.unpack_from("<I", V, 0xa0)[0]
                nt_off = _struct.unpack_from("<I", V, 0xa8)[0] + 0xCC
                nt_len = _struct.unpack_from("<I", V, 0xac)[0]
            except Exception:
                continue
            nt_hex = _EMPTY_NT
            lm_hex = _EMPTY_LM
            min_len = 0x18 if kind == 3 else 0x14
            try:
                if nt_len >= min_len:
                    blob = V[nt_off:nt_off+nt_len]
                    h = _decrypt_user_hash(hbootkey, rid, blob, kind, is_lm=False)
                    if h:
                        nt_hex = h.hex()
            except Exception:
                pass
            try:
                if lm_len >= min_len:
                    blob = V[lm_off:lm_off+lm_len]
                    h = _decrypt_user_hash(hbootkey, rid, blob, kind, is_lm=True)
                    if h:
                        lm_hex = h.hex()
            except Exception:
                pass
            rows.append({
                "Username": username,
                "RID": rid,
                "LM Hash": lm_hex,
                "NT Hash": nt_hex,
                "pwdump": "%s:%d:%s:%s:::" % (username, rid, lm_hex, nt_hex),
                "Encryption": "AES" if kind == 3 else "RC4",
            })
        if not rows:
            return [{"Note": "No user accounts recovered from SAM hive."}]
        rows.sort(key=lambda r: r.get("RID", 0))
        return rows
    except Exception as ex:
        return [{"Error": "SAM extraction failed: %s" % ex}]


# ══════════════════════════════════════════════════════════════
#  OFFLINE SECURITY HIVE PARSER  (LSA secrets + cached domain creds)
#  --------------------------------------------------------------
#  Recovers, fully in-box (no third-party deps), from a SECURITY
#  hive collected back into the case folder (reg save HKLM\SECURITY):
#    • the LSA key (Vista+ PolEKList, AES-256)
#    • LSA secrets under Policy\Secrets (DefaultPassword, _SC_*
#      service account passwords, $MACHINE.ACC, DPAPI_SYSTEM, …)
#    • cached domain logon credentials (NL$KM + MSCacheV2 / DCC2)
#  Algorithm mirrors the well-documented LSA/DCC2 scheme; output is
#  Hashcat-ready ($DCC2$, mode 2100).
# ══════════════════════════════════════════════════════════════

def _lsa_sha256(key, salt, rounds=1000):
    h = _hashlib.sha256()
    h.update(key)
    for _ in range(rounds):
        h.update(salt)
    return h.digest()

def _lsa_decrypt_aes(key, value, iv=b"\x00" * 16):
    """Vista+ LSA AES. iv all-zero => per-block (no chaining, ECB-equiv);
    a real iv => standard CBC chaining (used for DCC2 records).
    Last partial block is zero-padded, matching the OS scheme."""
    w = _aes_key_expansion(key)
    out = bytearray()
    zero_iv = (iv == b"\x00" * 16)
    prev = iv
    for i in range(0, len(value), 16):
        block = value[i:i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        dec = _aes_dec_block(w, block)
        if zero_iv:
            out += bytes(dec)
        else:
            out += bytes(dec[j] ^ prev[j] for j in range(16))
            prev = block
    return bytes(out)

def _hive_default_value(hive, keypath):
    for vn in ("", "(default)"):
        try:
            v = hive.value(keypath, vn)
            if v:
                return v
        except Exception:
            pass
    return None

def _decrypt_lsa_secret_blob(blob, key):
    """blob = full Vista+ LSA_SECRET; returns decrypted Secret bytes."""
    if not blob or len(blob) < 28 + 32:
        return None
    enc = blob[28:]
    salt = enc[:32]
    tmpkey = _lsa_sha256(key, salt)
    plain = _lsa_decrypt_aes(tmpkey, enc[32:])
    if len(plain) < 16:
        return None
    length = _struct.unpack_from("<I", plain, 0)[0]
    return plain[16:16 + length]

def _get_lsa_key(security_path, bootkey):
    h = _Hive(security_path)
    pol = _hive_default_value(h, "Policy\\PolEKList")
    if pol:
        secret = _decrypt_lsa_secret_blob(pol, bootkey)
        if secret and len(secret) >= 84:
            return secret[52:84]
    return None

def _pad4(n):
    return n + (4 - (n & 3)) if (n & 3) else n

def _format_lsa_secret(name, secret):
    row = {"Type": "LSA Secret", "Name": name,
           "Raw (hex)": secret.hex() if len(secret) <= 64 else secret[:64].hex() + "…",
           "Length": len(secret)}
    up = name.upper()
    try:
        if up.startswith("_SC_"):
            row["Service"] = name[4:]
            row["Value"] = secret.decode("utf-16le", "ignore").rstrip("\x00")
            row["Summary"] = "Service account password for '%s'" % name[4:]
        elif up == "$MACHINE.ACC":
            ntlm = ""
            try:
                ntlm = _hashlib.new("md4", secret).hexdigest()
            except Exception:
                ntlm = "(MD4 unavailable)"
            row["NTLM"] = ntlm
            row["Summary"] = "Machine account password (computer$ NTLM: %s)" % ntlm
        elif up == "DPAPI_SYSTEM":
            if len(secret) >= 44:
                row["Machine Key"] = secret[4:24].hex()
                row["User Key"] = secret[24:44].hex()
            row["Summary"] = "DPAPI machine/user master keys"
        elif up in ("DEFAULTPASSWORD", "ASPNET_SETREG"):
            row["Value"] = secret.decode("utf-16le", "ignore").rstrip("\x00")
            row["Summary"] = "Cleartext secret (%s)" % name
        else:
            txt = secret.decode("utf-16le", "ignore").rstrip("\x00")
            printable = sum(1 for c in txt if c.isprintable())
            if txt and printable >= max(1, int(len(txt) * 0.7)):
                row["Value"] = txt
            row["Summary"] = "%d-byte secret" % len(secret)
    except Exception:
        row["Summary"] = "%d-byte secret" % len(secret)
    return row

def _dump_dcc2(hive, nlkm):
    """Cached domain credentials (MSCacheV2 / DCC2) under the Cache key."""
    rows = []
    if not nlkm or len(nlkm) < 32:
        return rows
    iter_count = 10240
    try:
        ic = hive.value("Cache", "NL$IterationCount")
        n = None
        if isinstance(ic, (bytes, bytearray)) and len(ic) >= 4:
            n = _struct.unpack_from("<I", ic, 0)[0]
        elif isinstance(ic, int):
            n = ic
        if n is not None:
            iter_count = n * 1024 if (n & 0xfffffc00) == 0 else (n & 0xfffffc00)
    except Exception:
        pass
    key = nlkm[16:32]
    for vname in hive.value_names("Cache"):
        up = (vname or "").upper()
        if not up.startswith("NL$") or up in ("NL$CONTROL", "NL$ITERATIONCOUNT"):
            continue
        rec = hive.value("Cache", vname)
        if not rec or len(rec) < 96:
            continue
        try:
            userlen = _struct.unpack_from("<H", rec, 0)[0]
            domlen  = _struct.unpack_from("<H", rec, 2)[0]
            dnslen  = _struct.unpack_from("<H", rec, 60)[0]
            flags   = _struct.unpack_from("<I", rec, 48)[0]
            iv      = rec[64:80]
            enc     = rec[96:]
            if iv == b"\x00" * 16 or not (flags & 1) or not enc:
                continue
            plain = _lsa_decrypt_aes(key, enc, iv)
            enchash = plain[:16]
            body = plain[72:]
            user = body[:userlen].decode("utf-16le", "replace")
            body = body[_pad4(userlen):]
            domain = body[:domlen].decode("utf-16le", "replace")
            body = body[_pad4(domlen):]
            dnsdom = body[:dnslen].decode("utf-16le", "replace") if dnslen else ""
            if not user:
                continue
            dcc2 = "$DCC2$%d#%s#%s" % (iter_count, user.lower(), enchash.hex())
            rows.append({
                "Type": "Cached Domain Cred (DCC2)",
                "Name": vname,
                "Username": ("%s\\%s" % (domain, user)) if domain else user,
                "DNS Domain": dnsdom,
                "Hashcat (-m 2100)": dcc2,
                "Summary": "MSCacheV2 cached logon for %s" % user,
            })
        except Exception:
            continue
    return rows

def extract_lsa_secrets(security_path, system_path):
    """Return a list of {'Type','Name',...} rows for LSA secrets and cached
    domain credentials. On failure returns a single 'Note'/'Error' row."""
    import os as _os
    if not (security_path and system_path and
            _os.path.exists(security_path) and _os.path.exists(system_path)):
        return [{"Note": "SECURITY and SYSTEM hives are both required for LSA secret extraction."}]
    try:
        bootkey = _get_bootkey(system_path)
        if not bootkey:
            return [{"Error": "Could not derive boot key (SYSKEY) from SYSTEM hive."}]
        lsakey = _get_lsa_key(security_path, bootkey)
        if not lsakey:
            return [{"Error": "Could not derive LSA key (Policy\\PolEKList missing or unsupported hive style)."}]
        hive = _Hive(security_path)
        rows = []
        nlkm = None
        try:
            secret_names = hive.subkey_names("Policy\\Secrets")
        except Exception:
            secret_names = []
        for name in secret_names:
            if not name or name.lower() == "(default)":
                continue
            blob = _hive_default_value(hive, "Policy\\Secrets\\%s\\CurrVal" % name)
            if not blob:
                continue
            try:
                secret = _decrypt_lsa_secret_blob(blob, lsakey)
            except Exception:
                secret = None
            if not secret:
                continue
            if name.upper() == "NL$KM":
                nlkm = secret
            rows.append(_format_lsa_secret(name, secret))
        rows.extend(_dump_dcc2(hive, nlkm))
        if not rows:
            return [{"Note": "No LSA secrets or cached domain credentials recovered."}]
        return rows
    except Exception as ex:
        return [{"Error": "LSA secret extraction failed: %s" % ex}]


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
#  LIVE ARTIFACT COLLECTION (worker thread)
# ══════════════════════════════════════════════════════════════


def _collect_from_image(artifact_name, image_path):
    """
    Collect and PARSE non-volatile artifacts from a forensic image.
    Uses path-aware + magic-byte-validated search to prevent artifact mixing.
    Each artifact uses exact filename matching + directory path hints + header verification.
    """
    import os, struct, datetime, tempfile, shutil, json, sqlite3, codecs

    results = []

    VOLATILE = {
        "Running Processes", "Active Connections", "ARP Cache", "DNS Cache",
        "Network Interfaces", "Loaded Drivers/Modules", "System Uptime",
        "Process Memory Strings", "Injected DLLs", "Hollowed Processes",
        "Heap Allocations", "Kernel Objects",
    }
    if artifact_name in VOLATILE:
        return [{"Note": f"{artifact_name} is a volatile artifact — live system only."}]

    # ── Open image ────────────────────────────────────────────────────────────
    try:
        ifs = ForensicImageFS.get(image_path)
        if not ifs.fs:
            return [{"Error": "Cannot open image filesystem: %s" % (ifs.error or "unknown")}]
    except Exception as e:
        return [{"Error": f"ForensicImageFS init failed: {e}"}]

    # ── Magic bytes ───────────────────────────────────────────────────────────
    MAGIC_REGF   = b'regf'
    MAGIC_EVTX   = b'ElfFile\x00'
    MAGIC_LNK    = b'\x4c\x00\x00\x00'
    MAGIC_SQLITE = b'SQLite format 3'

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _safe_str(raw, enc='utf-8'):
        if isinstance(raw, (bytes, bytearray)):
            try:
                return raw.decode('utf-16-le', errors='replace').rstrip('\x00')
            except Exception:
                return raw.decode(enc, errors='replace')
        return str(raw) if raw is not None else ''

    def _clean(s):
        """Strip null bytes and non-printable chars."""
        return ''.join(c for c in str(s) if c.isprintable() and c != '\x00')

    def _fmt_ts(ts):
        try:
            return datetime.datetime.utcfromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            return str(ts)

    def _fmt_win_ft(ft):
        try:
            ts = (int(ft) - 116444736000000000) / 10_000_000
            return datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            return str(ft)

    def _rot13(s):
        return codecs.decode(str(s), 'rot_13')

    # ── Iterative filesystem walker ───────────────────────────────────────────
    def walk_fs():
        """Yield (full_path, entry_dict) for every non-dir entry in image."""
        stack   = [(None, '')]
        visited = set()
        while stack:
            folder_inode, prefix = stack.pop()
            try:
                entries = (ifs.list_dir() if folder_inode is None
                           else ifs.list_dir(inode=folder_inode))
            except Exception:
                continue
            for e in (entries or []):
                try:
                    nm = e.get('name', '')
                    if isinstance(nm, (bytes, bytearray)):
                        nm = nm.decode('utf-8', errors='replace')
                    nm = str(nm) if nm else ''
                    if not nm or nm in ('.', '..', '$OrphanFiles'):
                        continue
                    inode  = e.get('inode')
                    is_dir = bool(e.get('is_dir', False))
                    full   = (prefix.rstrip('/') + '/' + nm) if prefix else nm
                    e2     = dict(e)
                    e2['name'] = nm
                    yield full, e2
                    if is_dir and inode and inode not in visited:
                        visited.add(inode)
                        stack.append((inode, full))
                except Exception:
                    continue

    # ── Path-aware, magic-validated file finder ───────────────────────────────
    def find_files(exact_names=None, path_must=None, path_must_not=None,
                   extensions=None, name_startswith=None,
                   magic=None, max_results=50):
        """
        exact_names    : list — filename must EXACTLY match one of these (case-insensitive)
        path_must      : list — ALL of these substrings must appear in the full path (case-insensitive)
        path_must_not  : list — NONE of these substrings may appear in path
        extensions     : list — file extension must match (e.g. ['.lnk', '.pf'])
        name_startswith: list — filename must start with one of these (case-insensitive)
        magic          : bytes — first N bytes of file must match this
        """
        found = []
        en_lo = [n.lower() for n in (exact_names    or [])]
        pm_lo = [p.lower() for p in (path_must      or [])]
        pn_lo = [p.lower() for p in (path_must_not  or [])]
        ex_lo = [e.lower() for e in (extensions     or [])]
        sw_lo = [s.lower() for s in (name_startswith or [])]

        for full_path, e in walk_fs():
            if e.get('is_dir'):
                continue
            nl = e.get('name', '').lower()
            pl = full_path.lower()

            if en_lo and nl not in en_lo:
                continue
            if pm_lo and not all(p in pl for p in pm_lo):
                continue
            if pn_lo and any(p in pl for p in pn_lo):
                continue
            if ex_lo and not any(nl.endswith(x) for x in ex_lo):
                continue
            if sw_lo and not any(nl.startswith(s) for s in sw_lo):
                continue

            inode = e.get('inode')
            if inode and magic:
                try:
                    hdr = ifs.read_file(inode, max_bytes=len(magic))
                    if hdr[:len(magic)] != magic:
                        continue
                except Exception:
                    continue

            found.append((full_path, e))
            if len(found) >= max_results:
                break
        return found

    # ── Extract to temp ───────────────────────────────────────────────────────
    def extract(e_or_inode, suffix='', max_bytes=64 * 1024 * 1024):
        inode = e_or_inode if isinstance(e_or_inode, int) else e_or_inode.get('inode')
        if not inode:
            return None, b''
        try:
            data = ifs.read_file(inode, max_bytes=max_bytes)
            if not data:
                return None, b''
            fd, tmp = tempfile.mkstemp(suffix=suffix)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
            return tmp, data
        except Exception:
            return None, b''

    def cleanup(tmp):
        if tmp:
            try:
                os.unlink(tmp)
            except Exception:
                pass

    # ── Registry helper ───────────────────────────────────────────────────────
    def open_reg(e_or_inode):
        """Validate regf magic, extract hive, open with python-registry."""
        try:
            from Registry import Registry as _Reg
        except ImportError:
            return None, None, 'pip install python-registry'
        tmp, data = extract(e_or_inode, suffix='.hive')
        if not tmp:
            return None, None, 'Failed to extract hive'
        if data[:4] != MAGIC_REGF:
            cleanup(tmp)
            return None, None, f'Not a valid registry hive (magic={data[:4]!r})'
        try:
            reg = _Reg.Registry(tmp)
            return reg, tmp, None
        except Exception as ex:
            cleanup(tmp)
            return None, None, f'Registry parse error: {ex}'

    # ── SQLite helper ─────────────────────────────────────────────────────────
    def query_sqlite(e_or_inode, sql, params=()):
        tmp, data = extract(e_or_inode, suffix='.db')
        if not tmp:
            return []
        if data[:15] != MAGIC_SQLITE:
            cleanup(tmp)
            return []
        try:
            con = sqlite3.connect(tmp)
            con.row_factory = sqlite3.Row
            rows = [dict(r) for r in con.execute(sql, params).fetchall()]
            con.close()
            return rows
        except Exception:
            return []
        finally:
            cleanup(tmp)

    # ── EVTX helper ───────────────────────────────────────────────────────────
    def parse_evtx(e_or_inode, max_events=150):
        tmp, data = extract(e_or_inode, suffix='.evtx')
        if not tmp or data[:8] != MAGIC_EVTX:
            cleanup(tmp)
            return [{'Note': 'Not a valid EVTX file or file not found.'}]
        evs = []
        try:
            from Evtx.Evtx import Evtx as _Evtx
            import xml.etree.ElementTree as _ET
            with _Evtx(tmp) as log:
                for rec in log.records():
                    try:
                        root = _ET.fromstring(rec.xml())
                        ns   = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                        ev   = {}
                        sys_el = root.find('e:System', ns)
                        if sys_el is not None:
                            for child in sys_el:
                                tag = child.tag.split('}')[-1]
                                val = (child.text or '').strip() or \
                                      ' '.join(f'{k}={v}' for k, v in child.attrib.items())
                                ev[tag] = _clean(val)
                        ed_el = root.find('e:EventData', ns)
                        if ed_el is not None:
                            for d in ed_el.findall('e:Data', ns):
                                k = d.get('Name', 'Data')
                                ev[k] = _clean(d.text or '')
                        if ev:
                            evs.append(ev)
                        if len(evs) >= max_events:
                            break
                    except Exception:
                        continue
        except ImportError:
            evs.append({'Note': 'pip install python-evtx'})
        finally:
            cleanup(tmp)
        return evs

    # ── LNK parser ────────────────────────────────────────────────────────────
    def parse_lnk(data):
        info = {}
        if not data or data[:4] != MAGIC_LNK or len(data) < 76:
            return info
        try:
            flags  = struct.unpack_from('<I', data, 20)[0]
            offset = 76
            if flags & 0x01:
                idl_sz  = struct.unpack_from('<H', data, offset)[0]
                offset += 2 + idl_sz
            if flags & 0x02 and len(data) > offset + 28:
                li_sz   = struct.unpack_from('<I',  data, offset)[0]
                lp_off  = struct.unpack_from('<I',  data, offset + 16)[0]
                try:
                    raw_p = data[offset + lp_off:].split(b'\x00')[0]
                    info['LocalPath'] = raw_p.decode('latin-1', errors='replace')
                except Exception:
                    pass
                offset += li_sz
            for field in ['Description', 'RelativePath', 'WorkingDir', 'Arguments', 'IconLocation']:
                if offset + 2 > len(data):
                    break
                cnt     = struct.unpack_from('<H', data, offset)[0]
                offset += 2
                if 0 < cnt <= 32767 and offset + cnt * 2 <= len(data):
                    seg = data[offset: offset + cnt * 2]
                    val = seg.decode('utf-16-le', errors='replace').rstrip('\x00')
                    if val.strip():
                        info[field] = _clean(val)
                offset += cnt * 2
        except Exception:
            pass
        return info

    # ════════════════════════════════════════════════════════════════════════
    #  PER-ARTIFACT HANDLERS
    # ════════════════════════════════════════════════════════════════════════
    try:

        # ── OS Version ───────────────────────────────────────────────────────
        if artifact_name == 'OS Version & Build':
            for fp, e in find_files(exact_names=['software'], path_must=['config'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if err:
                    results.append({'Error': err}); continue
                try:
                    key = reg.open('Microsoft\\Windows NT\\CurrentVersion')
                    for v in key.values():
                        results.append({'Field': _clean(v.name()), 'Value': _clean(str(v.value()))[:200]})
                except Exception as ex:
                    results.append({'Error': str(ex)})
                finally:
                    cleanup(tmp)
                break

        # ── Hostname & Domain ─────────────────────────────────────────────
        elif artifact_name == 'Hostname & Domain':
            for fp, e in find_files(exact_names=['system'], path_must=['config'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if err:
                    results.append({'Error': err}); continue
                try:
                    for kp in ['ControlSet001\\Control\\ComputerName\\ComputerName',
                               'ControlSet001\\Services\\Tcpip\\Parameters']:
                        try:
                            key = reg.open(kp)
                            for v in key.values():
                                results.append({'Key': kp.split('\\')[-1],
                                                'Field': _clean(v.name()),
                                                'Value': _clean(str(v.value()))[:200]})
                        except Exception:
                            pass
                except Exception as ex:
                    results.append({'Error': str(ex)})
                finally:
                    cleanup(tmp)
                break

        # ── Installed Software ────────────────────────────────────────────
        elif artifact_name == 'Installed Software':
            for fp, e in find_files(exact_names=['software'], path_must=['config'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if err:
                    results.append({'Error': err}); continue
                try:
                    for kp in ['Microsoft\\Windows\\CurrentVersion\\Uninstall',
                               'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall']:
                        try:
                            key = reg.open(kp)
                            for sub in key.subkeys():
                                info = {'Subkey': _clean(sub.name())}
                                for v in sub.values():
                                    if v.name() in ('DisplayName', 'DisplayVersion',
                                                    'Publisher', 'InstallDate'):
                                        info[v.name()] = _clean(str(v.value()))[:150]
                                if 'DisplayName' in info:
                                    results.append(info)
                        except Exception:
                            pass
                except Exception as ex:
                    results.append({'Error': str(ex)})
                finally:
                    cleanup(tmp)
                break

        # ── Registry Run Keys ─────────────────────────────────────────────
        elif artifact_name == 'Registry Run Keys':
            # SOFTWARE hive — HKLM run keys
            for fp, e in find_files(exact_names=['software'], path_must=['config'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        for kp in [
                            'Microsoft\\Windows\\CurrentVersion\\Run',
                            'Microsoft\\Windows\\CurrentVersion\\RunOnce',
                            'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
                            'Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
                        ]:
                            try:
                                key = reg.open(kp)
                                for v in key.values():
                                    results.append({'Hive': 'SOFTWARE', 'Key': kp,
                                                    'Name': _clean(v.name()),
                                                    'Command': _clean(str(v.value()))[:300]})
                            except Exception:
                                pass
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break
            # NTUSER.DAT — HKCU run keys (each user profile)
            for fp, e in find_files(exact_names=['ntuser.dat'], path_must=['users'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        for kp in [
                            'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                            'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                        ]:
                            try:
                                key = reg.open(kp)
                                for v in key.values():
                                    results.append({'Hive': f'NTUSER ({fp})', 'Key': kp,
                                                    'Name': _clean(v.name()),
                                                    'Command': _clean(str(v.value()))[:300]})
                            except Exception:
                                pass
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)

        # ── SAM Database Hash Dump ────────────────────────────────────────
        elif artifact_name == 'SAM Database Hash Dump':
            found = find_files(exact_names=['sam'], path_must=['config'],
                               path_must_not=['samdump', 'samlib', '.log'], magic=MAGIC_REGF)
            if not found:
                results.append({'Note': 'SAM hive not found in Windows/System32/config/'})
            for fp, e in found:
                reg, tmp, err = open_reg(e)
                if err:
                    results.append({'Error': err}); continue
                try:
                    key = reg.open('SAM\\Domains\\Account\\Users\\Names')
                    for sub in key.subkeys():
                        results.append({
                            'Username':  _clean(sub.name()),
                            'LastWrite': sub.timestamp().strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'Note':      'Hash bytes require SYSTEM key — use secretsdump/Mimikatz'
                        })
                except Exception as ex:
                    results.append({'Error': f'SAM parse: {ex}'})
                finally:
                    cleanup(tmp)
                break

        # ── Local User Accounts ───────────────────────────────────────────
        elif artifact_name == 'Local User Accounts':
            for fp, e in find_files(exact_names=['sam'], path_must=['config'],
                                    path_must_not=['.log'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open('SAM\\Domains\\Account\\Users\\Names')
                        for sub in key.subkeys():
                            results.append({'Username': _clean(sub.name()),
                                            'LastWrite': sub.timestamp().strftime('%Y-%m-%d %H:%M:%S UTC')})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break
            # Linux /etc/passwd
            for fp, e in find_files(exact_names=['passwd'], path_must=['etc']):
                _, data = extract(e)
                for line in data.decode('utf-8', errors='replace').splitlines():
                    parts = line.split(':')
                    if len(parts) >= 6 and not line.startswith('#'):
                        results.append({'Username': parts[0], 'UID': parts[2],
                                        'GID': parts[3], 'Home': parts[5]})
                break

        # ── USB Device History ────────────────────────────────────────────
        elif artifact_name == 'USB Device History':
            found = find_files(exact_names=['system'], path_must=['config'],
                               path_must_not=['.log', '.alt'], magic=MAGIC_REGF)
            if not found:
                results.append({'Note': 'SYSTEM hive not found.'})
            for fp, e in found:
                reg, tmp, err = open_reg(e)
                if err:
                    results.append({'Error': err}); continue
                try:
                    GUID = '{83da6326-97a6-4088-9453-a1923f573b29}'
                    for cs in ['ControlSet001', 'ControlSet002', 'CurrentControlSet']:
                        try:
                            usb_key = reg.open(f'{cs}\\Enum\\USBSTOR')
                        except Exception:
                            continue
                        for dc in usb_key.subkeys():
                            parts = dc.name().split('&')
                            vendor  = parts[0].replace('Disk&Ven_', '').replace('Ven_', '') if parts else ''
                            product = parts[1].replace('Prod_', '') if len(parts) > 1 else ''
                            rev     = parts[2].replace('Rev_', '')  if len(parts) > 2 else ''
                            for inst in dc.subkeys():
                                info = {
                                    'Vendor':       _clean(vendor),
                                    'Product':      _clean(product),
                                    'Revision':     _clean(rev),
                                    'SerialNumber': _clean(inst.name()),
                                    'LastWrite':    inst.timestamp().strftime('%Y-%m-%d %H:%M:%S UTC'),
                                }
                                try:
                                    info['FriendlyName'] = _clean(str(inst.value('FriendlyName').value()))
                                except Exception:
                                    pass
                                for slot, label in [('0064', 'FirstInstall'),
                                                    ('0065', 'LastConnected'),
                                                    ('0066', 'LastRemoved')]:
                                    try:
                                        pk = reg.open(
                                            f'{cs}\\Enum\\USBSTOR\\{dc.name()}\\'
                                            f'{inst.name()}\\Properties\\{GUID}\\{slot}')
                                        for pv in pk.values():
                                            raw = pv.raw_data()
                                            if raw and len(raw) >= 8:
                                                ft = struct.unpack_from('<Q', raw)[0]
                                                info[label] = _fmt_win_ft(ft)
                                    except Exception:
                                        pass
                                results.append(info)
                        break
                except Exception as ex:
                    results.append({'Error': f'USB parse: {ex}'})
                finally:
                    cleanup(tmp)
                break

        # ── USB First/Last Times ──────────────────────────────────────────
        elif artifact_name == 'USB First/Last Connection Times':
            for fp, e in find_files(exact_names=['system'], path_must=['config'],
                                    path_must_not=['.log', '.alt'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if err:
                    results.append({'Error': err}); continue
                try:
                    GUID = '{83da6326-97a6-4088-9453-a1923f573b29}'
                    for cs in ['ControlSet001', 'ControlSet002']:
                        try:
                            usb_key = reg.open(f'{cs}\\Enum\\USBSTOR')
                        except Exception:
                            continue
                        for dc in usb_key.subkeys():
                            for inst in dc.subkeys():
                                for slot, label in [('0064', 'FirstInstall'),
                                                    ('0065', 'LastConnected'),
                                                    ('0066', 'LastRemoved')]:
                                    try:
                                        pk = reg.open(
                                            f'{cs}\\Enum\\USBSTOR\\{dc.name()}\\'
                                            f'{inst.name()}\\Properties\\{GUID}\\{slot}')
                                        for pv in pk.values():
                                            raw = pv.raw_data()
                                            if raw and len(raw) >= 8:
                                                ft = struct.unpack_from('<Q', raw)[0]
                                                results.append({
                                                    'Device':    _clean(inst.name())[:40],
                                                    'DevClass':  _clean(dc.name())[:40],
                                                    'Event':     label,
                                                    'Timestamp': _fmt_win_ft(ft),
                                                })
                                    except Exception:
                                        pass
                        break
                except Exception as ex:
                    results.append({'Error': str(ex)})
                finally:
                    cleanup(tmp)
                break

        # ── Shellbags ─────────────────────────────────────────────────────
        elif artifact_name == 'Shellbags':
            for fp, e in find_files(exact_names=['ntuser.dat'], path_must=['users'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        root = reg.open('Software\\Microsoft\\Windows\\Shell\\BagMRU')
                        def _walk_bags(key, kpath=''):
                            ts = ''
                            try:
                                ts = key.timestamp().strftime('%Y-%m-%d %H:%M:%S UTC')
                            except Exception:
                                pass
                            for v in key.values():
                                if v.name() in ('MRUListEx', 'NodeSlot', 'NodeSlots'):
                                    continue
                                try:
                                    raw = v.raw_data() or b''
                                    decoded = _clean(raw[2:].decode('utf-16-le', errors='replace'))
                                    if decoded.strip():
                                        results.append({'Source': fp, 'Key': kpath or 'BagMRU',
                                                        'Value': _clean(v.name()),
                                                        'Data': decoded[:200], 'LastWrite': ts})
                                except Exception:
                                    pass
                            for sub in key.subkeys():
                                _walk_bags(sub, f'{kpath}\\{sub.name()}' if kpath else sub.name())
                        _walk_bags(root)
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
            for fp, e in find_files(exact_names=['usrclass.dat'], path_must=['users'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        root = reg.open('Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU')
                        def _walk_bags2(key, kpath=''):
                            ts = ''
                            try:
                                ts = key.timestamp().strftime('%Y-%m-%d %H:%M:%S UTC')
                            except Exception:
                                pass
                            for v in key.values():
                                if v.name() in ('MRUListEx', 'NodeSlot', 'NodeSlots'):
                                    continue
                                try:
                                    raw = v.raw_data() or b''
                                    decoded = _clean(raw[2:].decode('utf-16-le', errors='replace'))
                                    if decoded.strip():
                                        results.append({'Source': fp, 'Key': kpath or 'BagMRU',
                                                        'Value': _clean(v.name()),
                                                        'Data': decoded[:200], 'LastWrite': ts})
                                except Exception:
                                    pass
                            for sub in key.subkeys():
                                _walk_bags2(sub, f'{kpath}\\{sub.name()}' if kpath else sub.name())
                        _walk_bags2(root)
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)

        # ── UserAssist Keys ───────────────────────────────────────────────
        elif artifact_name == 'UserAssist Keys':
            for fp, e in find_files(exact_names=['ntuser.dat'], path_must=['users'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        ua = reg.open(
                            'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist')
                        for guid_key in ua.subkeys():
                            try:
                                count_key = guid_key.subkey('Count')
                                for v in count_key.values():
                                    app_name  = _clean(_rot13(v.name()))
                                    run_count = last_run = ''
                                    try:
                                        raw = v.raw_data()
                                        if raw and len(raw) >= 16:
                                            run_count = struct.unpack_from('<I', raw, 4)[0]
                                            ft        = struct.unpack_from('<Q', raw, 8)[0]
                                            last_run  = _fmt_win_ft(ft)
                                    except Exception:
                                        pass
                                    results.append({'Application': app_name, 'RunCount': run_count,
                                                    'LastRun': last_run, 'GUID': _clean(guid_key.name()),
                                                    'Profile': fp})
                            except Exception:
                                pass
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)

        # ── Jump Lists ────────────────────────────────────────────────────
        elif artifact_name == 'Jump Lists':
            for fp, e in find_files(path_must=['automaticdestinations'],
                                    extensions=['-ms']):
                tmp, data = extract(e, suffix='.ms')
                if not tmp:
                    continue
                info = {'File': e.get('name', ''), 'Path': fp, 'Targets': ''}
                try:
                    import olefile
                    if olefile.isOleFile(tmp):
                        ole  = olefile.OleFileIO(tmp)
                        tgts = []
                        for stream in ole.listdir():
                            try:
                                raw = ole.openstream(stream).read()
                                if raw[:4] == MAGIC_LNK:
                                    lnk_info = parse_lnk(raw)
                                    if lnk_info.get('LocalPath'):
                                        tgts.append(lnk_info['LocalPath'])
                            except Exception:
                                pass
                        info['Targets'] = ' | '.join(tgts)[:300]
                        ole.close()
                except ImportError:
                    info['Note'] = 'pip install olefile'
                except Exception:
                    pass
                finally:
                    cleanup(tmp)
                results.append(info)

        # ── WiFi Profiles ─────────────────────────────────────────────────
        elif artifact_name == 'WiFi Profiles':
            for fp, e in find_files(path_must=['wlansvc'], extensions=['.xml']):
                tmp, data = extract(e, suffix='.xml')
                if not tmp:
                    continue
                try:
                    import xml.etree.ElementTree as _ET
                    ns   = {'w': 'http://www.microsoft.com/networking/WLAN/profile/v1'}
                    root = _ET.fromstring(data.decode('utf-8', errors='replace'))
                    ssid = auth = enc = key = ''
                    try:
                        ssid = root.find('.//w:SSID/w:name', ns).text or ''
                    except Exception:
                        pass
                    try:
                        auth = root.find('.//w:authentication', ns).text or ''
                    except Exception:
                        pass
                    try:
                        enc  = root.find('.//w:encryption', ns).text or ''
                    except Exception:
                        pass
                    try:
                        key  = root.find('.//w:keyMaterial', ns).text or ''
                    except Exception:
                        pass
                    results.append({'SSID': _clean(ssid), 'Auth': _clean(auth),
                                    'Encryption': _clean(enc), 'Key': _clean(key), 'File': fp})
                except Exception:
                    pass
                finally:
                    cleanup(tmp)

        # ── Event Logs ────────────────────────────────────────────────────
        elif artifact_name in ('Security Event Log', 'Account Logon Events',
                               'Process Creation Events (4688)'):
            for fp, e in find_files(exact_names=['security.evtx'],
                                    path_must=['winevt'], magic=MAGIC_EVTX):
                results = parse_evtx(e); break
            if not results:
                results.append({'Note': 'Security.evtx not found in Windows/System32/winevt/Logs/'})

        elif artifact_name == 'System Event Log':
            for fp, e in find_files(exact_names=['system.evtx'],
                                    path_must=['winevt'], magic=MAGIC_EVTX):
                results = parse_evtx(e); break
            if not results:
                results.append({'Note': 'System.evtx not found.'})

        elif artifact_name == 'Application Event Log':
            for fp, e in find_files(exact_names=['application.evtx'],
                                    path_must=['winevt'], magic=MAGIC_EVTX):
                results = parse_evtx(e); break
            if not results:
                results.append({'Note': 'Application.evtx not found.'})

        elif artifact_name == 'PowerShell Operational Log':
            for fp, e in find_files(
                    path_must=['winevt'],
                    name_startswith=['microsoft-windows-powershell'],
                    extensions=['.evtx'], magic=MAGIC_EVTX):
                results = parse_evtx(e); break
            if not results:
                results.append({'Note': 'PowerShell evtx not found.'})

        elif artifact_name == 'RDP Session Log':
            for fp, e in find_files(path_must=['winevt'], extensions=['.evtx'], magic=MAGIC_EVTX):
                nm = e.get('name', '').lower()
                if any(k in nm for k in ['rdp', 'terminalservices', 'localsessionmanager']):
                    results = parse_evtx(e)
                    break
            if not results:
                results.append({'Note': 'RDP evtx not found.'})

        # ── Prefetch Files ────────────────────────────────────────────────
        elif artifact_name == 'Prefetch Files':
            for fp, e in find_files(path_must=['prefetch'], extensions=['.pf']):
                _, data = extract(e, suffix='.pf')
                if not data or len(data) < 84:
                    continue
                info = {'File': e.get('name', ''), 'Path': fp, 'Size': e.get('size', 0)}
                try:
                    ver = struct.unpack_from('<I', data, 0)[0]
                    exe_name = data[16:76].decode('utf-16-le', errors='replace').rstrip('\x00').strip()
                    stem     = info['File'].replace('.pf', '')
                    pf_hash  = stem.rsplit('-', 1)[-1] if '-' in stem else ''
                    exe_stem = stem.rsplit('-', 1)[0]  if '-' in stem else stem
                    run_count = last_run = ''
                    if ver == 17:
                        run_count = struct.unpack_from('<I', data, 0x90)[0]
                        last_run  = _fmt_win_ft(struct.unpack_from('<Q', data, 0x78)[0])
                    elif ver == 23:
                        run_count = struct.unpack_from('<I', data, 0x98)[0]
                        last_run  = _fmt_win_ft(struct.unpack_from('<Q', data, 0x80)[0])
                    elif ver in (26, 30):
                        run_count = struct.unpack_from('<I', data, 0xD0)[0]
                        last_run  = _fmt_win_ft(struct.unpack_from('<Q', data, 0x80)[0])
                    info.update({'Executable': _clean(exe_stem), 'ExeHeader': _clean(exe_name),
                                 'Hash': pf_hash, 'RunCount': run_count,
                                 'LastRun': last_run, 'Version': ver})
                except Exception as ex:
                    info['ParseError'] = str(ex)
                results.append(info)

        # ── LNK / Shortcut Files ──────────────────────────────────────────
        elif artifact_name == 'LNK / Shortcut Files':
            for fp, e in find_files(path_must=['recent'], extensions=['.lnk'], magic=MAGIC_LNK):
                _, data = extract(e, suffix='.lnk')
                info = {'File': e.get('name', ''), 'Path': fp}
                info.update(parse_lnk(data))
                results.append(info)
            if not results:
                for fp, e in find_files(path_must=['desktop'], extensions=['.lnk'], magic=MAGIC_LNK):
                    _, data = extract(e, suffix='.lnk')
                    info = {'File': e.get('name', ''), 'Path': fp}
                    info.update(parse_lnk(data))
                    results.append(info)

        # ── Recycle Bin Contents ──────────────────────────────────────────
        elif artifact_name == 'Recycle Bin Contents':
            for fp, e in find_files(path_must=['recycle'], name_startswith=['$i']):
                _, data = extract(e)
                info = {'MetaFile': e.get('name', ''), 'Path': fp}
                if data and len(data) >= 28:
                    try:
                        ver   = struct.unpack_from('<Q', data, 0)[0]
                        fsize = struct.unpack_from('<Q', data, 8)[0]
                        ft    = struct.unpack_from('<Q', data, 16)[0]
                        orig  = ''
                        if ver == 2:
                            nchars = struct.unpack_from('<I', data, 24)[0]
                            if nchars > 0 and len(data) >= 28 + nchars * 2:
                                orig = data[28:28 + nchars * 2].decode('utf-16-le', errors='replace').rstrip('\x00')
                        else:
                            raw = data[28:]
                            try:
                                orig = raw.split(b'\x00\x00')[0].decode('utf-16-le', errors='replace')
                            except Exception:
                                orig = raw.decode('utf-8', errors='replace')[:260]
                        info.update({'OriginalPath': _clean(orig), 'FileSize': fsize,
                                     'DeletedTime': _fmt_win_ft(ft)})
                    except Exception as ex:
                        info['ParseError'] = str(ex)
                results.append(info)

        # ── Browser History ───────────────────────────────────────────────
        elif artifact_name == 'Browser History':
            for fp, e in find_files(exact_names=['history'], path_must=['chrome'], magic=MAGIC_SQLITE):
                rows = query_sqlite(e,
                    "SELECT url, title, visit_count, "
                    "datetime(last_visit_time/1000000-11644473600,'unixepoch') AS last_visit "
                    "FROM urls ORDER BY last_visit_time DESC LIMIT 300")
                for r in rows:
                    r['Browser'] = 'Chrome'; r['Source'] = fp; results.append(r)
            for fp, e in find_files(exact_names=['history'], path_must=['edge'], magic=MAGIC_SQLITE):
                rows = query_sqlite(e,
                    "SELECT url, title, visit_count, "
                    "datetime(last_visit_time/1000000-11644473600,'unixepoch') AS last_visit "
                    "FROM urls ORDER BY last_visit_time DESC LIMIT 300")
                for r in rows:
                    r['Browser'] = 'Edge'; r['Source'] = fp; results.append(r)
            for fp, e in find_files(exact_names=['places.sqlite'],
                                    path_must=['firefox'], magic=MAGIC_SQLITE):
                rows = query_sqlite(e,
                    "SELECT p.url, p.title, p.visit_count, "
                    "datetime(h.visit_date/1000000,'unixepoch') AS visit_time "
                    "FROM moz_places p LEFT JOIN moz_historyvisits h ON p.id=h.place_id "
                    "ORDER BY h.visit_date DESC LIMIT 300")
                for r in rows:
                    r['Browser'] = 'Firefox'; r['Source'] = fp; results.append(r)
            if not results:
                results.append({'Note': 'No browser history DBs found.'})

        # ── Browser Cookies ───────────────────────────────────────────────
        elif artifact_name == 'Browser Cookies':
            for fp, e in find_files(exact_names=['cookies'], path_must=['chrome'], magic=MAGIC_SQLITE):
                rows = query_sqlite(e,
                    "SELECT host_key, name, path, is_secure, "
                    "datetime(expires_utc/1000000-11644473600,'unixepoch') AS expires "
                    "FROM cookies ORDER BY creation_utc DESC LIMIT 300")
                for r in rows:
                    r['Browser'] = 'Chrome'; results.append(r)
            for fp, e in find_files(exact_names=['cookies.sqlite'],
                                    path_must=['firefox'], magic=MAGIC_SQLITE):
                rows = query_sqlite(e,
                    "SELECT host, name, path, isSecure, "
                    "datetime(expiry,'unixepoch') AS expires "
                    "FROM moz_cookies LIMIT 300")
                for r in rows:
                    r['Browser'] = 'Firefox'; results.append(r)
            if not results:
                results.append({'Note': 'No browser cookie DBs found.'})

        # ── Browser Saved Passwords ───────────────────────────────────────
        elif artifact_name == 'Browser Saved Passwords':
            results.append({'Note': 'Chrome/Edge passwords are DPAPI-encrypted. '
                                    'Use LaZagne or Mimikatz dpapi for decryption.'})
            for fp, e in find_files(exact_names=['logins.json'], path_must=['firefox']):
                _, data = extract(e)
                if not data:
                    continue
                try:
                    for login in json.loads(data.decode('utf-8', errors='replace')).get('logins', []):
                        results.append({'Browser': 'Firefox',
                                        'Host':    login.get('hostname', ''),
                                        'UserEnc': login.get('encryptedUsername', '')[:40],
                                        'PassEnc': login.get('encryptedPassword', '')[:40]})
                except Exception:
                    pass

        # ── Browser Extensions ────────────────────────────────────────────
        elif artifact_name == 'Browser Extensions':
            for fp, e in find_files(exact_names=['manifest.json'], path_must=['extension']):
                _, data = extract(e)
                if not data:
                    continue
                try:
                    m = json.loads(data.decode('utf-8', errors='replace'))
                    results.append({'Name':        _clean(m.get('name', ''))[:80],
                                    'Version':     _clean(m.get('version', '')),
                                    'Description': _clean(m.get('description', ''))[:100],
                                    'Permissions': _clean(str(m.get('permissions', [])))[:150],
                                    'Path':        fp})
                except Exception:
                    pass
            if not results:
                results.append({'Note': 'No extension manifests found.'})

        # ── Scheduled Tasks ───────────────────────────────────────────────
        elif artifact_name in ('Scheduled Tasks', 'Task Scheduler Jobs'):
            for fp, e in find_files(path_must=['tasks'], extensions=['.xml'],
                                    path_must_not=['eventlog', 'winevt']):
                tmp, data = extract(e, suffix='.xml')
                if not tmp:
                    continue
                try:
                    import xml.etree.ElementTree as _ET
                    ns   = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
                    root = _ET.fromstring(data.decode('utf-8', errors='replace'))
                    cmd = args = userid = trigger = ''
                    try:
                        cmd = root.find('.//t:Command', ns).text or ''
                    except Exception:
                        pass
                    try:
                        args = root.find('.//t:Arguments', ns).text or ''
                    except Exception:
                        pass
                    try:
                        userid = root.find('.//t:UserId', ns).text or ''
                    except Exception:
                        pass
                    results.append({'TaskFile': e.get('name', ''), 'Path': fp,
                                    'Command': _clean(cmd), 'Arguments': _clean(args),
                                    'UserId': _clean(userid)})
                except Exception:
                    pass
                finally:
                    cleanup(tmp)
            if not results:
                results.append({'Note': 'No scheduled task XML files found.'})

        # ── Certificate Store ─────────────────────────────────────────────
        # Explicitly exclude hive/evtx/db files — only accept real cert formats
        elif artifact_name == 'Certificate Store':
            for fp, e in find_files(extensions=['.cer', '.crt', '.pem', '.pfx', '.p12', '.der'],
                                    path_must_not=['config', 'winevt', 'prefetch']):
                _, data = extract(e)
                if not data:
                    continue
                info = {'File': e.get('name', ''), 'Path': fp, 'Size': e.get('size', 0)}
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    if data.startswith(b'-----BEGIN'):
                        cert = x509.load_pem_x509_certificate(data, default_backend())
                    else:
                        cert = x509.load_der_x509_certificate(data, default_backend())
                    info['Subject']   = _clean(cert.subject.rfc4514_string())
                    info['Issuer']    = _clean(cert.issuer.rfc4514_string())
                    info['NotBefore'] = cert.not_valid_before.strftime('%Y-%m-%d')
                    info['NotAfter']  = cert.not_valid_after.strftime('%Y-%m-%d')
                    info['Serial']    = str(cert.serial_number)
                except ImportError:
                    info['Note'] = 'pip install cryptography'
                except Exception as ex:
                    info['ParseError'] = str(ex)[:100]
                results.append(info)
            if not results:
                results.append({'Note': 'No certificate files (.cer/.crt/.pem/.pfx) found.'})

        # ── PST / OST Files ───────────────────────────────────────────────
        elif artifact_name == 'PST/OST Files (Outlook)':
            for fp, e in find_files(extensions=['.pst', '.ost']):
                results.append({'File': e.get('name', ''), 'Path': fp, 'Size': e.get('size', 0),
                                 'Note': 'Use libpff (pip install libpff-python) to parse'})
            if not results:
                results.append({'Note': 'No PST/OST files found.'})

        # ── MSG Files ─────────────────────────────────────────────────────
        elif artifact_name == 'MSG Files (Outlook)':
            for fp, e in find_files(extensions=['.msg']):
                tmp, data = extract(e, suffix='.msg')
                info = {'File': e.get('name', ''), 'Path': fp, 'Size': e.get('size', 0)}
                if tmp:
                    try:
                        import extract_msg as _emsg
                        m = _emsg.openMsg(tmp)
                        info['Subject'] = _clean(str(m.subject or ''))
                        info['Sender']  = _clean(str(m.sender  or ''))
                        info['Date']    = _clean(str(m.date    or ''))
                        m.close()
                    except ImportError:
                        info['Note'] = 'pip install extract-msg'
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                results.append(info)
            if not results:
                results.append({'Note': 'No MSG files found.'})

        # ── Thunderbird MBOX ──────────────────────────────────────────────
        elif artifact_name == 'Thunderbird MBOX':
            for fp, e in find_files(path_must=['thunderbird'],
                                    exact_names=['inbox', 'sent', 'drafts', 'trash']):
                _, data = extract(e, max_bytes=65536)
                if not data:
                    continue
                count   = data.count(b'\nFrom ')
                preview = _clean(data[:500].decode('utf-8', errors='replace'))
                results.append({'File': e.get('name', ''), 'Path': fp, 'Size': e.get('size', 0),
                                 'MessageCount': count, 'Preview': preview})
            if not results:
                results.append({'Note': 'No Thunderbird MBOX files found.'})

        # ── Email Accounts Config ─────────────────────────────────────────
        elif artifact_name == 'Email Accounts Config':
            for fp, e in find_files(exact_names=['prefs.js'], path_must=['thunderbird']):
                _, data = extract(e, max_bytes=65536)
                if not data:
                    continue
                for line in data.decode('utf-8', errors='replace').splitlines():
                    if any(k in line for k in ['mail.server', 'mail.account', 'mail.smtp']):
                        results.append({'Source': fp, 'Entry': _clean(line.strip())[:200]})
            if not results:
                results.append({'Note': 'No email account config files found.'})

        # ── Recent Files (MRU) ────────────────────────────────────────────
        elif artifact_name == 'Recent Files (MRU)':
            for fp, e in find_files(exact_names=['ntuser.dat'], path_must=['users'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        for kp in [
                            'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
                            'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
                            'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths',
                        ]:
                            try:
                                key = reg.open(kp)
                                for v in key.values():
                                    if v.name() == 'MRUListEx':
                                        continue
                                    raw = v.raw_data() or b''
                                    try:
                                        decoded = _clean(raw[2:].decode('utf-16-le', errors='replace'))
                                    except Exception:
                                        decoded = raw.hex()[:80]
                                    results.append({'Key': kp.split('\\')[-1],
                                                    'Value': _clean(v.name()),
                                                    'Data': decoded[:200]})
                            except Exception:
                                pass
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)

        # ── Startup Folder Items ──────────────────────────────────────────
        elif artifact_name == 'Startup Folder Items':
            for fp, e in find_files(path_must=['startup'],
                                    extensions=['.lnk', '.exe', '.bat', '.vbs', '.ps1', '.cmd']):
                info = {'File': e.get('name', ''), 'Path': fp, 'Size': e.get('size', 0)}
                if e.get('name', '').lower().endswith('.lnk'):
                    _, data = extract(e, suffix='.lnk')
                    info.update(parse_lnk(data))
                results.append(info)
            if not results:
                results.append({'Note': 'No startup folder items found.'})

        # ── Temp Directory Contents ───────────────────────────────────────
        elif artifact_name == 'Temp Directory Contents':
            for fp, e in find_files(path_must=['temp']):
                results.append({'Name': e.get('name', ''), 'Path': fp, 'Size': e.get('size', 0)})
                if len(results) >= 200:
                    break
            if not results:
                results.append({'Note': 'No temp directory contents found.'})

        # ── Services (Auto-Start) ─────────────────────────────────────────
        elif artifact_name == 'Services (Auto-Start)':
            for fp, e in find_files(exact_names=['system'], path_must=['config'],
                                    path_must_not=['.log', '.alt'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        for cs in ['ControlSet001', 'ControlSet002']:
                            try:
                                svc = reg.open(f'{cs}\\Services')
                                for sub in svc.subkeys():
                                    try:
                                        sv  = sub.value('Start').value()
                                        img = ''
                                        try:
                                            img = str(sub.value('ImagePath').value())
                                        except Exception:
                                            pass
                                        if sv in (0, 1, 2):
                                            results.append({
                                                'Name':      _clean(sub.name()),
                                                'ImagePath': _clean(img)[:200],
                                                'StartType': {0: 'Boot', 1: 'System', 2: 'Auto'}.get(sv, '')
                                            })
                                    except Exception:
                                        pass
                                break
                            except Exception:
                                pass
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── LSA Secrets ───────────────────────────────────────────────────
        elif artifact_name == 'LSA Secrets':
            for fp, e in find_files(exact_names=['security'], path_must=['config'],
                                    path_must_not=['.log'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open('Policy\\Secrets')
                        for sub in key.subkeys():
                            results.append({'SecretName': _clean(sub.name()),
                                            'Note': 'Value encrypted — use Mimikatz lsadump::secrets'})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── DPAPI Master Keys ─────────────────────────────────────────────
        elif artifact_name == 'DPAPI Master Keys':
            for fp, e in find_files(path_must=['protect']):
                nm = e.get('name', '')
                if len(nm) in (36, 38) or (len(nm) > 10 and all(
                        c in '0123456789abcdefABCDEF-' for c in nm)):
                    results.append({'MasterKey': nm, 'Path': fp, 'Size': e.get('size', 0),
                                    'Note': 'Decrypt with Mimikatz dpapi::masterkey'})
            if not results:
                results.append({'Note': 'No DPAPI master key files found.'})

        # ── Cached Credentials ────────────────────────────────────────────
        elif artifact_name == 'Cached Credentials':
            for fp, e in find_files(exact_names=['security'], path_must=['config'],
                                    path_must_not=['.log'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open('Cache')
                        for v in key.values():
                            if _clean(v.name()).startswith('NL$'):
                                results.append({'Entry': _clean(v.name()),
                                                'Note': 'Cached domain hash (MS-Cache v2)'})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break
            if not results:
                results.append({'Note': 'No cached credentials in SECURITY hive.'})

        # ── Firewall Rules ────────────────────────────────────────────────
        elif artifact_name == 'Firewall Rules':
            for fp, e in find_files(exact_names=['system'], path_must=['config'],
                                    path_must_not=['.log', '.alt'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open(
                            'ControlSet001\\Services\\SharedAccess\\Parameters'
                            '\\FirewallPolicy\\FirewallRules')
                        for v in key.values():
                            results.append({'RuleName': _clean(v.name()),
                                            'Rule': _clean(str(v.value()))[:300]})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── BIOS / UEFI Info ──────────────────────────────────────────────
        elif artifact_name == 'BIOS/UEFI Info':
            for fp, e in find_files(exact_names=['system'], path_must=['config'],
                                    path_must_not=['.log', '.alt'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        for cs in ['ControlSet001', 'ControlSet002']:
                            try:
                                key = reg.open(f'{cs}\\Control\\SystemInformation')
                                for v in key.values():
                                    results.append({'Field': _clean(v.name()),
                                                    'Value': _clean(str(v.value()))[:200]})
                                break
                            except Exception:
                                pass
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── Drive Letter / Volume Serial ──────────────────────────────────
        elif artifact_name in ('Drive Letter Assignments', 'Volume Serial Numbers'):
            for fp, e in find_files(exact_names=['system'], path_must=['config'],
                                    path_must_not=['.log', '.alt'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open('MountedDevices')
                        for v in key.values():
                            raw  = v.raw_data() or b''
                            info = {'MountPoint': _clean(v.name()), 'DataLen': len(raw)}
                            if len(raw) >= 12 and 'DosDevices' in v.name():
                                try:
                                    info['VolumeSerial'] = '%08X' % struct.unpack_from('<I', raw, 8)[0]
                                except Exception:
                                    pass
                            results.append(info)
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── WMI Subscriptions ─────────────────────────────────────────────
        elif artifact_name == 'WMI Subscriptions':
            for fp, e in find_files(path_must=['wbem'], extensions=['.mof']):
                _, data = extract(e, max_bytes=32768)
                if data:
                    results.append({'File': e.get('name', ''), 'Path': fp,
                                    'Content': _clean(data.decode('utf-8', errors='replace'))[:500]})
            if not results:
                results.append({'Note': 'No WMI MOF files found.'})

        # ── AppInit DLLs ──────────────────────────────────────────────────
        elif artifact_name == 'AppInit DLLs':
            for fp, e in find_files(exact_names=['software'], path_must=['config'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        for kp in [
                            'Microsoft\\Windows NT\\CurrentVersion\\Windows',
                            'Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
                        ]:
                            try:
                                key = reg.open(kp)
                                val = key.value('AppInit_DLLs').value()
                                results.append({'Key': kp, 'AppInit_DLLs': _clean(str(val)) or '(empty)'})
                            except Exception:
                                pass
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── COM Hijacking Keys ────────────────────────────────────────────
        elif artifact_name == 'COM Hijacking Keys':
            for fp, e in find_files(exact_names=['software'], path_must=['config'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open('Classes\\CLSID')
                        for sub in key.subkeys():
                            results.append({'CLSID': _clean(sub.name()),
                                            'Note': 'Potential COM hijack location'})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── $MFT Entries ──────────────────────────────────────────────────
        elif artifact_name == '$MFT Entries':
            for fp, e in find_files(exact_names=['$mft']):
                results.append({'File': '$MFT', 'Path': fp, 'Size': e.get('size', 0),
                                 'Note': 'Use analyzeMFT or python-mft for full parsing.'})
                break
            if not results:
                results.append({'Note': '$MFT not found as standalone file.'})

        # ── Alternate Data Streams ────────────────────────────────────────
        elif artifact_name == 'Alternate Data Streams':
            results.append({'Note': 'ADS enumeration requires raw NTFS MFT attribute parsing. '
                                    'Use the Filesystem Browser to inspect individual files.'})

        # ── Volume Shadow Copies ──────────────────────────────────────────
        elif artifact_name == 'Volume Shadow Copies':
            results.append({'Note': 'VSS requires live system or mounted VSS snapshot access.'})

        # ── Last Login Times ──────────────────────────────────────────────
        elif artifact_name == 'Last Login Times':
            for fp, e in find_files(exact_names=['sam'], path_must=['config'],
                                    path_must_not=['.log'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open('SAM\\Domains\\Account\\Users\\Names')
                        for sub in key.subkeys():
                            results.append({'Username': _clean(sub.name()),
                                            'LastWrite': sub.timestamp().strftime('%Y-%m-%d %H:%M:%S UTC')})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)
                break

        # ── Typed URLs ────────────────────────────────────────────────────
        elif artifact_name == 'Typed URLs':
            for fp, e in find_files(exact_names=['ntuser.dat'], path_must=['users'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open('Software\\Microsoft\\Internet Explorer\\TypedURLs')
                        for v in key.values():
                            results.append({'Entry': _clean(v.name()), 'URL': _clean(str(v.value())),
                                            'Profile': fp})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)

        # ── Windows Search History ────────────────────────────────────────
        elif artifact_name == 'Windows Search History':
            for fp, e in find_files(exact_names=['ntuser.dat'], path_must=['users'], magic=MAGIC_REGF):
                reg, tmp, err = open_reg(e)
                if not err:
                    try:
                        key = reg.open(
                            'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery')
                        for v in key.values():
                            if v.name() == 'MRUListEx':
                                continue
                            raw = v.raw_data() or b''
                            term = _clean(raw.decode('utf-16-le', errors='replace'))
                            if term:
                                results.append({'SearchTerm': term, 'ValueName': _clean(v.name()),
                                                'Profile': fp})
                    except Exception:
                        pass
                    finally:
                        cleanup(tmp)

        # ── Generic Fallback ──────────────────────────────────────────────
        else:
            results.append({
                'Artifact': artifact_name,
                'Status':   'Handler not implemented for image analysis',
                'Note':     'Image-based collection for this artifact type is not yet implemented.',
            })

    except Exception as e:
        import traceback
        results.append({'Error': str(e), 'Traceback': traceback.format_exc()[:800]})

    return results if results else [{'Note': f'No data found for: {artifact_name}'}]
def collect_artifact(name, target_path=None, target_type="local"):
    """
    Collect a named forensic artifact.

    target_path : path to analyse (local dir, image mount point, or specific file)
                  None = use local system (live collection)
    target_type : "local"     - live system collection (default)
                  "directory" - scan a specific directory tree
                  "image"     - forensic image (path = image file, use pytsk3)
                  "file"      - single file analysis
    """
    import glob, sqlite3, csv as _csv
    results = []
    OS = platform.system()   # 'Windows', 'Linux', 'Darwin'

    # Resolve the effective root path for file-based searches
    # For live collection target_path is None and we use system defaults.
    # For directory/image targets we re-root searches to target_path.
    search_root = Path(target_path) if target_path else Path("/")
    is_image_target = (target_type == "image")

    # For forensic image targets: walk via ForensicImageFS, not the host FS.
    if is_image_target and target_path:
        return _collect_from_image(name, target_path)

    # For remote targets: use native signed Windows tools over the admin share
    # (net use + wevtutil/schtasks/reg/sc/tasklist + Get-CimInstance/WinRM).
    # Evidence files are copied back to the case folder and parsed locally.
    if target_type == "remote" and target_path:
        return collect_artifact_remote(name, target_path)

    # For directory targets: redirect all home/system searches into that tree.
    effective_home = (Path(target_path) if target_path and target_type == "directory"
                      else Path.home())

    def _run(cmd, timeout=8):
        """Run a shell command, return stdout lines list."""
        try:
            out = subprocess.check_output(cmd, text=True, timeout=timeout,
                                          stderr=subprocess.DEVNULL)
            return [l for l in out.splitlines() if l.strip()]
        except Exception:
            return []

    def _ps_json(script, timeout=30):
        """Run a PowerShell snippet that emits JSON, return parsed list[dict].

        Modern replacement for the deprecated/removed `wmic` utility (gone in
        Windows 11 24H2 / Server 2025).  Always coerces the result to a list of
        dictionaries so callers can iterate uniformly.
        """
        if OS != "Windows":
            return []
        wrapped = ("$ErrorActionPreference='SilentlyContinue';" + script +
                   " | ConvertTo-Json -Depth 4 -Compress")
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", wrapped],
                text=True, timeout=timeout, stderr=subprocess.DEVNULL)
        except Exception:
            return []
        out = (out or "").strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except Exception:
            return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        return []

    def _read(path, max_bytes=65536):
        try:
            with open(path, errors='replace') as f:
                return f.read(max_bytes)
        except Exception:
            return ""

    def _sqlite_query(db_path, sql, params=()):
        """Query a SQLite DB safely (copies to temp to avoid lock issues)."""
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
        # ── SYSTEM INFORMATION ───────────────────────────────────────
        if name == "OS Version & Build":
            u = platform.uname()
            results.append({
                "System":    u.system,
                "Node":      u.node,
                "Release":   u.release,
                "Version":   u.version,
                "Machine":   u.machine,
                "Processor": u.processor,
                "Python":    sys.version.split()[0],
            })
            if OS == "Linux":
                for osr in ["/etc/os-release", "/etc/lsb-release"]:
                    if os.path.exists(osr):
                        for line in _read(osr).splitlines():
                            if "=" in line:
                                k, _, v = line.partition("=")
                                results.append({"Property": k.strip(),
                                                "Value": v.strip().strip('"')})
                        break

        elif name == "Hostname & Domain":
            hn = socket.gethostname()
            try:   ip = socket.gethostbyname(hn)
            except: ip = "N/A"
            results.append({"Hostname": hn, "FQDN": socket.getfqdn(), "IP": ip})
            if OS == "Linux":
                for f in ["/etc/hostname", "/etc/mailname"]:
                    if os.path.exists(f):
                        results.append({"Source": f, "Value": _read(f).strip()})
                for line in _run(["hostname", "--all-ip-addresses"]):
                    results.append({"All IPs": line})

        elif name == "System Uptime":
            boot = datetime.datetime.fromtimestamp(psutil.boot_time())
            up   = datetime.datetime.now() - boot
            m    = psutil.virtual_memory()
            results.append({
                "Boot Time":   boot.strftime("%Y-%m-%d %H:%M:%S"),
                "Uptime":      str(up).split('.')[0],
                "RAM Total":   fmt_size(m.total),
                "RAM Used":    fmt_size(m.used),
                "RAM %":       f"{m.percent}%",
                "RAM Available": fmt_size(m.available),
            })
            for d in psutil.disk_partitions():
                try:
                    u = psutil.disk_usage(d.mountpoint)
                    results.append({
                        "Device": d.device, "Mount": d.mountpoint,
                        "FS": d.fstype,
                        "Total": fmt_size(u.total),
                        "Used":  fmt_size(u.used),
                        "Free":  fmt_size(u.free),
                        "Used%": f"{u.percent}%",
                    })
                except Exception:
                    pass

        elif name == "Hardware Profile":
            cpu = psutil.cpu_freq()
            results.append({
                "CPU Physical Cores": str(psutil.cpu_count(logical=False)),
                "CPU Logical Cores":  str(psutil.cpu_count(logical=True)),
                "CPU Freq (MHz)":     f"{cpu.current:.0f}" if cpu else "N/A",
                "CPU Max (MHz)":      f"{cpu.max:.0f}" if cpu else "N/A",
                "CPU Usage %":        f"{psutil.cpu_percent(interval=0.5)}%",
                "RAM Total":          fmt_size(psutil.virtual_memory().total),
                "Swap Total":         fmt_size(psutil.swap_memory().total),
            })
            for i, d in enumerate(psutil.disk_partitions(all=False)):
                try:
                    u = psutil.disk_usage(d.mountpoint)
                    results.append({
                        "Disk #": str(i + 1),
                        "Device": d.device,
                        "Mount":  d.mountpoint,
                        "FS":     d.fstype,
                        "Total":  fmt_size(u.total),
                        "Used":   fmt_size(u.used),
                        "Free":   fmt_size(u.free),
                    })
                except Exception:
                    pass
            # CPU per-core
            for ci, pct in enumerate(psutil.cpu_percent(interval=0.2, percpu=True)):
                results.append({"Core": f"CPU {ci}", "Usage %": f"{pct}%"})

        elif name == "BIOS/UEFI Info":
            if OS == "Linux":
                dmi_base = "/sys/class/dmi/id"
                fields = ["bios_vendor","bios_version","bios_date",
                          "board_vendor","board_name","board_version",
                          "product_name","product_version","sys_vendor",
                          "chassis_type"]
                for field in fields:
                    p = os.path.join(dmi_base, field)
                    if os.path.exists(p):
                        results.append({"Property": field.replace("_", " ").title(),
                                        "Value":    _read(p).strip()})
                # Also try dmidecode if available
                for line in _run(["dmidecode", "-t", "0"], timeout=5):
                    if ":" in line:
                        k, _, v = line.partition(":")
                        results.append({"DMI": k.strip(), "Value": v.strip()})
            elif OS == "Windows":
                # Modern CIM replacement for deprecated `wmic bios`.
                for r in _ps_json(
                        "Get-CimInstance Win32_BIOS | "
                        "Select-Object Manufacturer,Name,Version,SMBIOSBIOSVersion,"
                        "ReleaseDate,SerialNumber"):
                    results.append({
                        "Manufacturer": r.get("Manufacturer", ""),
                        "Name":         r.get("Name", ""),
                        "Version":      r.get("SMBIOSBIOSVersion") or r.get("Version", ""),
                        "Date":         r.get("ReleaseDate", ""),
                        "Serial":       r.get("SerialNumber", ""),
                    })
                for r in _ps_json(
                        "Get-CimInstance Win32_BaseBoard | "
                        "Select-Object Manufacturer,Product,Version,SerialNumber"):
                    results.append({
                        "Manufacturer": r.get("Manufacturer", ""),
                        "Name":         "Mainboard: " + (r.get("Product") or ""),
                        "Version":      r.get("Version", ""),
                        "Serial":       r.get("SerialNumber", ""),
                    })
                if not results:
                    # Last-resort fallback for legacy hosts that still ship wmic.
                    lines = _run(["wmic", "bios", "get",
                                  "Manufacturer,Name,Version,ReleaseDate", "/format:csv"])
                    for line in lines[1:]:
                        parts = line.split(",")
                        if len(parts) >= 4:
                            results.append({"Manufacturer": parts[1], "Name": parts[2],
                                            "Version": parts[3],
                                            "Date": parts[4] if len(parts) > 4 else ""})
            else:
                results.append({"Note": "BIOS info requires root/admin on this platform."})

        elif name == "Installed Software":
            if OS == "Linux":
                # Try dpkg
                lines = _run(["dpkg", "-l"], timeout=15)
                for line in lines:
                    if line.startswith("ii"):
                        p = line.split()
                        if len(p) >= 4:
                            results.append({"Package":p[1],"Version":p[2],
                                            "Arch":p[3],"Status":"Installed"})
                if not results:
                    # Try rpm
                    lines = _run(["rpm", "-qa", "--queryformat",
                                  "%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME:date}\n"],
                                 timeout=15)
                    for line in lines:
                        parts = line.split("|")
                        if len(parts) >= 3:
                            results.append({"Package":parts[0],"Version":parts[1],
                                            "Release":parts[2],
                                            "Installed":parts[3] if len(parts)>3 else ""})
            elif OS == "Windows":
                # `wmic product` is deprecated, painfully slow, and only lists
                # MSI packages.  Enumerate the Uninstall registry keys instead
                # (covers MSI + EXE installers, 32- and 64-bit, per-user).
                hives = [
                    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                ]
                ps = ("Get-ItemProperty " + ",".join("'%s'" % h for h in hives) +
                      " | Where-Object {$_.DisplayName} | "
                      "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate")
                seen = set()
                for r in _ps_json(ps, timeout=40):
                    nm = r.get("DisplayName", "")
                    key = (nm, r.get("DisplayVersion", ""))
                    if nm and key not in seen:
                        seen.add(key)
                        results.append({"Name": nm,
                                        "Version": r.get("DisplayVersion", ""),
                                        "Vendor": r.get("Publisher", ""),
                                        "Installed": r.get("InstallDate", "")})
                if not results:
                    lines = _run(["wmic", "product", "get",
                                  "Name,Version,Vendor,InstallDate", "/format:csv"])
                    for line in lines[1:]:
                        parts = line.split(",")
                        if len(parts) >= 4 and parts[1].strip():
                            results.append({"Name": parts[1], "Version": parts[2],
                                            "Vendor": parts[3],
                                            "Installed": parts[4] if len(parts) > 4 else ""})
            elif OS == "Darwin":
                lines = _run(["system_profiler","SPApplicationsDataType","-detailLevel","mini"])
                pkg = {}
                for line in lines:
                    line = line.strip()
                    if line.endswith(":") and not line.startswith(" "):
                        if pkg: results.append(pkg)
                        pkg = {"Application": line[:-1]}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        pkg[k.strip()] = v.strip()
                if pkg:
                    results.append(pkg)

        elif name == "Loaded Drivers/Modules":
            if OS == "Linux":
                lines = _run(["lsmod"])
                for line in lines[1:]:  # skip header
                    parts = line.split()
                    if len(parts) >= 3:
                        results.append({"Module": parts[0], "Size": parts[1],
                                        "Used By": " ".join(parts[2:])})
            elif OS == "Windows":
                lines = _run(["driverquery", "/fo", "csv", "/v"])
                reader = _csv.reader(lines)
                headers = next(reader, [])
                for row in reader:
                    if row:
                        results.append(dict(zip(headers, row)))
            else:
                results.append({"Note": "Module listing not available on this platform."})

        elif name == "Scheduled Tasks":
            if OS == "Linux":
                # System crontabs
                cron_sources = ["/etc/crontab"] + \
                               glob.glob("/etc/cron.d/*") + \
                               glob.glob("/etc/cron.daily/*") + \
                               glob.glob("/etc/cron.weekly/*") + \
                               glob.glob("/etc/cron.monthly/*") + \
                               glob.glob("/var/spool/cron/crontabs/*")
                for cp in cron_sources:
                    if os.path.isfile(cp):
                        try:
                            s = os.stat(cp)
                            content = _read(cp)
                            tasks = [l for l in content.splitlines()
                                     if l.strip() and not l.startswith("#")]
                            results.append({
                                "Source":    cp,
                                "Modified":  fmt_ts(s.st_mtime),
                                "Tasks":     str(len(tasks)),
                                "Preview":   tasks[0][:80] if tasks else "(empty)",
                            })
                        except Exception:
                            pass
                # systemd timers
                for line in _run(["systemctl", "list-timers", "--all",
                                   "--no-pager", "--no-legend"]):
                    parts = line.split()
                    if len(parts) >= 5:
                        results.append({"Timer": parts[-1], "Next": parts[0],
                                        "Last": parts[4] if len(parts) > 4 else "",
                                        "Type": "systemd"})
            elif OS == "Windows":
                lines = _run(["schtasks", "/query", "/fo", "csv", "/v"])
                try:
                    reader = _csv.reader(lines)
                    headers = next(reader, [])
                    for row in reader:
                        if row and len(row) >= 3:
                            results.append(dict(zip(headers, row)))
                except Exception:
                    pass

        # ── USER & ACCOUNT ACTIVITY ──────────────────────────────────
        elif name == "Local User Accounts":
            if OS in ("Linux", "Darwin"):
                try:
                    with open("/etc/passwd") as f:
                        for line in f:
                            p = line.strip().split(":")
                            if len(p) >= 7:
                                uid = int(p[2])
                                results.append({
                                    "Username": p[0],
                                    "UID":      p[2],
                                    "GID":      p[3],
                                    "Comment":  p[4],
                                    "Home":     p[5],
                                    "Shell":    p[6],
                                    "Type":     "System" if uid < 1000 else "User",
                                })
                except Exception as e:
                    results.append({"Error": str(e)})
            elif OS == "Windows":
                # CIM replacement for deprecated `wmic useraccount`.
                for r in _ps_json(
                        "Get-CimInstance Win32_UserAccount -Filter \"LocalAccount=True\" | "
                        "Select-Object Name,SID,Disabled,PasswordRequired,Lockout,Description"):
                    results.append({
                        "Name":        r.get("Name", ""),
                        "SID":         r.get("SID", ""),
                        "Disabled":    str(r.get("Disabled", "")),
                        "PwdRequired": str(r.get("PasswordRequired", "")),
                        "Lockout":     str(r.get("Lockout", "")),
                        "Description": r.get("Description", ""),
                    })
                if not results:
                    lines = _run(["wmic", "useraccount", "get",
                                  "Name,SID,Disabled,PasswordRequired,LocalAccount",
                                  "/format:csv"])
                    for line in lines[1:]:
                        parts = line.split(",")
                        if len(parts) >= 5 and parts[1].strip():
                            results.append({"Name": parts[1],
                                            "SID": parts[5] if len(parts) > 5 else "",
                                            "Disabled": parts[2], "PwdRequired": parts[4]})
            # Current logged-in users
            for u in psutil.users():
                results.append({"User": u.name, "Terminal": u.terminal or "",
                                 "Host": u.host or "", "Started": fmt_ts(u.started),
                                 "Type": "Active Session"})

        elif name == "Last Login Times":
            if OS == "Linux":
                lines = _run(["last", "-n", "50", "-F"])
                for line in lines:
                    if line.strip() and not line.startswith("wtmp"):
                        parts = line.split()
                        if len(parts) >= 3:
                            results.append({
                                "User":     parts[0],
                                "Terminal": parts[1],
                                "From":     parts[2] if len(parts) > 2 else "",
                                "Login":    " ".join(parts[3:8]) if len(parts) > 7 else "",
                                "Duration": parts[-1] if parts[-1] != parts[2] else "",
                            })
            elif OS == "Windows":
                lines = _run(["wevtutil", "qe", "Security",
                               "/q:*[System[EventID=4624]]",
                               "/c:30", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if "Account Name:" in line:
                        ev["Account"] = line.split(":", 1)[1].strip()
                    elif "Logon Type:" in line:
                        ev["Type"] = line.split(":", 1)[1].strip()
                    elif "Date:" in line:
                        ev["Date"] = line.split(":", 1)[1].strip()
                        if ev.get("Account"):
                            results.append(dict(ev)); ev = {}

        elif name == "Recent Files (MRU)":
            home = Path.home()
            found = []
            search_dirs = [home, home/"Documents", home/"Downloads",
                           home/"Desktop", home/"Pictures"]
            if OS == "Windows":
                search_dirs += [
                    home/"AppData/Roaming/Microsoft/Windows/Recent",
                ]
            for d in search_dirs:
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
                    "File":     f.name,
                    "Directory":str(f.parent),
                    "Size":     fmt_size(s.st_size),
                    "Accessed": fmt_ts(s.st_atime),
                    "Modified": fmt_ts(s.st_mtime),
                    "Type":     detect_type(str(f)),
                })

        # ── NETWORK ARTIFACTS ────────────────────────────────────────
        elif name == "Running Processes":
            for p in psutil.process_iter(
                    ['pid','name','username','status','create_time',
                     'exe','memory_info','cpu_percent','cmdline']):
                try:
                    i = p.info
                    mem = fmt_size(i['memory_info'].rss) if i['memory_info'] else "N/A"
                    cmd = " ".join(i['cmdline'][:4]) if i.get('cmdline') else ""
                    results.append({
                        "PID":     str(i['pid']),
                        "Name":    i['name'] or "",
                        "User":    i['username'] or "",
                        "Status":  i['status'],
                        "Memory":  mem,
                        "CPU%":    f"{i['cpu_percent'] or 0:.1f}",
                        "Started": fmt_ts(i['create_time']) if i['create_time'] else "",
                        "Path":    i['exe'] or "",
                        "CmdLine": cmd[:120],
                    })
                except Exception:
                    pass

        elif name == "Active Connections":
            for c in psutil.net_connections(kind='inet'):
                try:
                    la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    try:
                        pn = psutil.Process(c.pid).name() if c.pid else ""
                    except Exception:
                        pn = ""
                    results.append({
                        "PID":      str(c.pid) if c.pid else "",
                        "Process":  pn,
                        "Protocol": c.type.name if hasattr(c.type, "name") else str(c.type),
                        "Local":    la,
                        "Remote":   ra,
                        "Status":   c.status,
                    })
                except Exception:
                    pass

        elif name == "Network Interfaces":
            stats = psutil.net_if_stats()
            counters = psutil.net_io_counters(pernic=True)
            for iface, addrs in psutil.net_if_addrs().items():
                st  = stats.get(iface)
                cnt = counters.get(iface)
                for a in addrs:
                    results.append({
                        "Interface": iface,
                        "Family":    str(a.family).replace("AddressFamily.", ""),
                        "Address":   a.address,
                        "Netmask":   a.netmask or "",
                        "Broadcast": a.broadcast or "",
                        "Speed":     f"{st.speed}Mbps" if st else "",
                        "MTU":       str(st.mtu) if st else "",
                        "Up":        "Yes" if (st and st.isup) else "No",
                        "Bytes Sent":   fmt_size(cnt.bytes_sent) if cnt else "",
                        "Bytes Recv":   fmt_size(cnt.bytes_recv) if cnt else "",
                    })

        elif name == "ARP Cache":
            if OS == "Linux":
                lines = _run(["cat", "/proc/net/arp"])
                for line in lines[1:]:  # skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        results.append({
                            "IP":        parts[0],
                            "HW Type":   parts[1],
                            "Flags":     parts[2],
                            "MAC":       parts[3],
                            "Interface": parts[5] if len(parts) > 5 else "",
                        })
            elif OS == "Windows":
                for line in _run(["arp", "-a"]):
                    parts = line.split()
                    if len(parts) >= 3 and parts[1].count("-") == 5:
                        results.append({"IP": parts[0], "MAC": parts[1], "Type": parts[2]})

        elif name == "DNS Cache":
            if OS == "Linux":
                # Check systemd-resolved
                for line in _run(["systemd-resolve", "--statistics"]):
                    results.append({"Stat": line})
                # Also check /etc/hosts
                for line in _read("/etc/hosts").splitlines():
                    if line.strip() and not line.startswith("#"):
                        results.append({"Source": "/etc/hosts", "Entry": line.strip()})
            elif OS == "Windows":
                for line in _run(["ipconfig", "/displaydns"]):
                    if "Record Name" in line or "Type" in line or "Data" in line:
                        results.append({"Entry": line.strip()})

        elif name == "Firewall Rules":
            if OS == "Linux":
                for line in _run(["iptables", "-L", "-n", "--line-numbers"],
                                  timeout=5):
                    results.append({"Rule": line})
                for line in _run(["ufw", "status", "verbose"], timeout=5):
                    results.append({"UFW": line})
            elif OS == "Windows":
                lines = _run(["netsh", "advfirewall", "firewall",
                               "show", "rule", "name=all"])
                rule = {}
                for line in lines:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        rule[k.strip()] = v.strip()
                        if k.strip() == "Action":
                            results.append(dict(rule)); rule = {}

        elif name == "WiFi Profiles":
            if OS == "Linux":
                nm_dir = "/etc/NetworkManager/system-connections"
                if os.path.isdir(nm_dir):
                    for f in os.listdir(nm_dir):
                        fp = os.path.join(nm_dir, f)
                        content = _read(fp)
                        ssid = ""
                        for line in content.splitlines():
                            if line.startswith("ssid="):
                                ssid = line.split("=", 1)[1]
                        results.append({"Profile": f, "SSID": ssid,
                                        "Path": fp})
            elif OS == "Windows":
                profiles = _run(["netsh", "wlan", "show", "profiles"])
                for line in profiles:
                    if "All User Profile" in line:
                        name_part = line.split(":", 1)[-1].strip()
                        detail = _run(["netsh", "wlan", "show", "profile",
                                       name_part, "key=clear"])
                        key = next((l.split(":", 1)[-1].strip()
                                    for l in detail if "Key Content" in l), "")
                        results.append({"SSID": name_part, "Key": key})

        elif name == "Browser History":
            home = Path.home()
            browser_dbs = []
            if OS == "Linux":
                browser_dbs += list(home.glob(".mozilla/firefox/*/places.sqlite"))
                browser_dbs += list(home.glob(".config/google-chrome/*/History"))
                browser_dbs += list(home.glob(".config/chromium/*/History"))
            elif OS == "Windows":
                browser_dbs += list((home/"AppData/Roaming/Mozilla/Firefox/Profiles").glob("*/places.sqlite")) if \
                    (home/"AppData/Roaming/Mozilla/Firefox/Profiles").exists() else []
                browser_dbs += list((home/"AppData/Local/Google/Chrome/User Data").glob("*/History")) if \
                    (home/"AppData/Local/Google/Chrome/User Data").exists() else []
            elif OS == "Darwin":
                browser_dbs += list(home.glob("Library/Application Support/Firefox/Profiles/*/places.sqlite"))
                browser_dbs += list(home.glob("Library/Application Support/Google/Chrome/*/History"))

            for db in browser_dbs[:3]:
                db = str(db)
                if "places.sqlite" in db:
                    rows = _sqlite_query(db,
                        "SELECT url, title, visit_count, last_visit_date "
                        "FROM moz_places ORDER BY last_visit_date DESC LIMIT 100")
                    for r in rows:
                        r["Browser"] = "Firefox"
                        r["Source"] = os.path.basename(os.path.dirname(db))
                        results.append(r)
                elif "History" in db:
                    rows = _sqlite_query(db,
                        "SELECT url, title, visit_count, last_visit_time "
                        "FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                    for r in rows:
                        r["Browser"] = "Chrome/Chromium"
                        r["Source"] = os.path.basename(os.path.dirname(db))
                        results.append(r)
            if not results:
                results.append({"Note": "No browser history databases found.",
                                 "Searched": str(home)})

        elif name == "Browser Cookies":
            home = Path.home()
            cookie_dbs = []
            if OS == "Linux":
                cookie_dbs += list(home.glob(".mozilla/firefox/*/cookies.sqlite"))
                cookie_dbs += list(home.glob(".config/google-chrome/*/Cookies"))
                cookie_dbs += list(home.glob(".config/chromium/*/Cookies"))
            for db in cookie_dbs[:3]:
                db = str(db)
                if "cookies.sqlite" in db:
                    rows = _sqlite_query(db,
                        "SELECT host, name, value, expiry, lastAccessed "
                        "FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 200")
                    for r in rows:
                        r["Browser"] = "Firefox"; results.append(r)
                else:
                    rows = _sqlite_query(db,
                        "SELECT host_key, name, value, expires_utc, last_access_utc "
                        "FROM cookies ORDER BY last_access_utc DESC LIMIT 200")
                    for r in rows:
                        r["Browser"] = "Chrome/Chromium"; results.append(r)
            if not results:
                results.append({"Note": "No cookie databases found."})

        # ── PERSISTENCE MECHANISMS ───────────────────────────────────
        elif name == "Registry Run Keys":
            if OS == "Windows":
                try:
                    import winreg
                    run_keys = [
                        (winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\Run"),
                        (winreg.HKEY_LOCAL_MACHINE,
                         r"Software\Microsoft\Windows\CurrentVersion\Run"),
                        (winreg.HKEY_LOCAL_MACHINE,
                         r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                        (winreg.HKEY_CURRENT_USER,
                         r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                    ]
                    for hive, key_path in run_keys:
                        try:
                            key = winreg.OpenKey(hive, key_path)
                            i = 0
                            while True:
                                try:
                                    vname, vdata, vtype = winreg.EnumValue(key, i)
                                    results.append({
                                        "Hive":  "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                                        "Key":   key_path,
                                        "Name":  vname,
                                        "Value": str(vdata)[:200],
                                        "Type":  str(vtype),
                                    })
                                    i += 1
                                except OSError:
                                    break
                        except OSError:
                            pass
                except ImportError:
                    results.append({"Note": "winreg not available (not Windows)"})
            elif OS == "Linux":
                # Linux equivalents: ~/.config/autostart, /etc/xdg/autostart
                for d in [Path.home()/".config/autostart",
                           Path("/etc/xdg/autostart")]:
                    if d.exists():
                        for f in d.iterdir():
                            if f.suffix == ".desktop":
                                content = _read(str(f))
                                exec_val = next(
                                    (l.split("=",1)[1] for l in content.splitlines()
                                     if l.startswith("Exec=")), "")
                                enabled = next(
                                    (l.split("=",1)[1] for l in content.splitlines()
                                     if l.startswith("Hidden=")), "false")
                                results.append({
                                    "Source":  str(d),
                                    "File":    f.name,
                                    "Exec":    exec_val,
                                    "Enabled": "No" if enabled.lower()=="true" else "Yes",
                                })

        elif name == "Startup Folder Items":
            if OS == "Windows":
                startup_dirs = [
                    Path.home()/"AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
                    Path("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp"),
                ]
            elif OS == "Linux":
                startup_dirs = [
                    Path.home()/".config/autostart",
                    Path("/etc/xdg/autostart"),
                    Path("/etc/init.d"),
                ]
            else:
                startup_dirs = [Path("/Library/LaunchAgents"),
                                Path.home()/"Library/LaunchAgents"]
            for d in startup_dirs:
                if d.exists():
                    for entry in d.iterdir():
                        try:
                            s = entry.stat()
                            results.append({
                                "Name":     entry.name,
                                "Directory":str(d),
                                "Size":     fmt_size(s.st_size),
                                "Modified": fmt_ts(s.st_mtime),
                                "Type":     detect_type(str(entry)),
                            })
                        except Exception:
                            pass

        elif name == "Services (Auto-Start)":
            if OS == "Linux":
                # systemd services
                lines = _run(["systemctl", "list-units", "--type=service",
                               "--all", "--no-pager", "--no-legend"])
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        results.append({
                            "Unit":        parts[0],
                            "Load":        parts[1],
                            "Active":      parts[2],
                            "Sub":         parts[3],
                            "Description": " ".join(parts[4:]) if len(parts) > 4 else "",
                        })
                # Also enabled services
                for line in _run(["systemctl", "list-unit-files",
                                   "--type=service", "--no-pager", "--no-legend"]):
                    parts = line.split()
                    if len(parts) >= 2:
                        results.append({"Service": parts[0], "State": parts[1],
                                        "Type": "unit-file"})
            elif OS == "Windows":
                lines = _run(["sc", "query", "type=", "all", "state=", "all"])
                svc = {}
                for line in lines:
                    line = line.strip()
                    if line.startswith("SERVICE_NAME:"):
                        if svc: results.append(svc)
                        svc = {"Name": line.split(":", 1)[1].strip()}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        svc[k.strip()] = v.strip()
                if svc:
                    results.append(svc)

        elif name == "WMI Subscriptions":
            if OS == "Windows":
                # Enumerate the actual WMI persistence triple from
                # root\subscription: filters, consumers, and their bindings.
                for r in _ps_json(
                        "Get-CimInstance -Namespace root/subscription "
                        "-ClassName __EventFilter | "
                        "Select-Object Name,Query,EventNamespace"):
                    results.append({"Type": "EventFilter",
                                    "Name": r.get("Name", ""),
                                    "Detail": r.get("Query", ""),
                                    "Namespace": r.get("EventNamespace", "")})
                for r in _ps_json(
                        "Get-CimInstance -Namespace root/subscription "
                        "-ClassName ActiveScriptEventConsumer | "
                        "Select-Object Name,ScriptingEngine,ScriptText,ScriptFileName"):
                    results.append({"Type": "ActiveScriptConsumer",
                                    "Name": r.get("Name", ""),
                                    "Detail": (r.get("ScriptFileName") or
                                               r.get("ScriptText") or "")[:300],
                                    "Engine": r.get("ScriptingEngine", "")})
                for r in _ps_json(
                        "Get-CimInstance -Namespace root/subscription "
                        "-ClassName CommandLineEventConsumer | "
                        "Select-Object Name,CommandLineTemplate,ExecutablePath"):
                    results.append({"Type": "CommandLineConsumer",
                                    "Name": r.get("Name", ""),
                                    "Detail": (r.get("CommandLineTemplate") or
                                               r.get("ExecutablePath") or "")[:300]})
                for r in _ps_json(
                        "Get-CimInstance -Namespace root/subscription "
                        "-ClassName __FilterToConsumerBinding | "
                        "Select-Object Filter,Consumer"):
                    results.append({"Type": "FilterToConsumerBinding",
                                    "Name": str(r.get("Filter", "")),
                                    "Detail": str(r.get("Consumer", ""))})
                if not results:
                    results.append({"Note": "No WMI event subscriptions found "
                                            "(root\\subscription is empty)."})
            else:
                results.append({"Note": "WMI is a Windows-only feature.",
                                 "Platform": OS})

        elif name == "AppInit DLLs":
            if OS == "Windows":
                try:
                    import winreg
                    for key_path in [
                        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                        r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
                    ]:
                        try:
                            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                            val, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                            results.append({"Key": key_path, "AppInit_DLLs": val or "(empty)"})
                        except Exception:
                            pass
                except ImportError:
                    results.append({"Note": "winreg not available"})
            else:
                results.append({"Note": "AppInit DLLs is Windows-specific.", "Platform": OS})

        elif name == "COM Hijacking Keys":
            if OS == "Windows":
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                        r"Software\Classes\CLSID")
                    i = 0
                    while True:
                        try:
                            clsid = winreg.EnumKey(key, i)
                            results.append({"CLSID": clsid,
                                            "Location": "HKCU\\Software\\Classes\\CLSID",
                                            "Risk": "Potential Hijack"})
                            i += 1
                        except OSError:
                            break
                except Exception:
                    results.append({"Note": "COM key enumeration failed or not Windows."})
            else:
                results.append({"Note": "COM hijacking keys are Windows-specific."})

        elif name == "Browser Extensions":
            home = Path.home()
            ext_dirs = []
            if OS == "Linux":
                ext_dirs += list(home.glob(".config/google-chrome/*/Extensions/*"))
                ext_dirs += list(home.glob(".config/chromium/*/Extensions/*"))
                ext_dirs += list(home.glob(".mozilla/firefox/*/extensions"))
            elif OS == "Windows":
                ext_dirs += list((home/"AppData/Local/Google/Chrome/User Data").glob("*/Extensions/*")) \
                    if (home/"AppData/Local/Google/Chrome/User Data").exists() else []
            for ext_dir in ext_dirs[:50]:
                manifest = Path(ext_dir) / "manifest.json"
                if not manifest.exists():
                    for sub in Path(ext_dir).rglob("manifest.json"):
                        manifest = sub; break
                if manifest.exists():
                    try:
                        with open(manifest) as mf:
                            m = json.load(mf)
                        results.append({
                            "Name":        m.get("name",""),
                            "Version":     m.get("version",""),
                            "Description": m.get("description","")[:80],
                            "Permissions": str(m.get("permissions",[])),
                            "Path":        str(ext_dir),
                        })
                    except Exception:
                        pass
            if not results:
                results.append({"Note": "No browser extensions found."})

        elif name == "Task Scheduler Jobs":
            # Alias to Scheduled Tasks
            return collect_artifact("Scheduled Tasks")

        # ── FILE SYSTEM ARTIFACTS ────────────────────────────────────
        elif name == "Recently Accessed Files":
            home = Path.home()
            found = []
            for d in [home, home/"Documents", home/"Downloads",
                      home/"Desktop", home/"Pictures"]:
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
                    "File":     f.name,
                    "Directory":str(f.parent),
                    "Size":     fmt_size(s.st_size),
                    "Accessed": fmt_ts(s.st_atime),
                    "Modified": fmt_ts(s.st_mtime),
                    "Type":     detect_type(str(f)),
                })

        elif name == "Prefetch Files":
            if OS == "Windows":
                pf_dir = Path("C:/Windows/Prefetch")
                if pf_dir.exists():
                    for f in sorted(pf_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)[:100]:
                        try:
                            s = f.stat()
                            results.append({
                                "File":    f.name,
                                "Size":    fmt_size(s.st_size),
                                "Created": fmt_ts(s.st_ctime),
                                "Modified":fmt_ts(s.st_mtime),
                                "Accessed":fmt_ts(s.st_atime),
                            })
                        except Exception:
                            pass
                else:
                    results.append({"Note": "Prefetch dir not found. May be disabled."})
            elif OS == "Linux":
                # Linux: /proc/<pid>/exe as analog — recently executed binaries
                for pid_dir in sorted(Path("/proc").iterdir(),
                                      key=lambda p: p.stat().st_mtime if p.exists() else 0,
                                      reverse=True)[:50]:
                    if pid_dir.name.isdigit():
                        try:
                            exe = os.readlink(pid_dir/"exe")
                            comm = (pid_dir/"comm").read_text().strip()
                            s = pid_dir.stat()
                            results.append({
                                "PID":     pid_dir.name,
                                "Process": comm,
                                "Exe":     exe,
                                "Started": fmt_ts(s.st_mtime),
                            })
                        except Exception:
                            pass

        elif name == "LNK / Shortcut Files":
            if OS == "Windows":
                search_dirs = [
                    Path.home()/"AppData/Roaming/Microsoft/Windows/Recent",
                    Path.home()/"Desktop",
                    Path("C:/ProgramData/Microsoft/Windows/Start Menu"),
                ]
            else:
                search_dirs = [Path.home()/".local/share/applications",
                               Path("/usr/share/applications")]
            for d in search_dirs:
                if d.exists():
                    for f in d.rglob("*.lnk" if OS=="Windows" else "*.desktop"):
                        try:
                            s = f.stat()
                            results.append({
                                "File":    f.name,
                                "Path":    str(f),
                                "Size":    fmt_size(s.st_size),
                                "Modified":fmt_ts(s.st_mtime),
                            })
                        except Exception:
                            pass

        elif name == "Temp Directory Contents":
            tmp = tempfile.gettempdir()
            entries = []
            try:
                entries = sorted(os.scandir(tmp),
                                 key=lambda e: e.stat().st_mtime, reverse=True)
            except Exception:
                pass
            for entry in entries[:80]:
                try:
                    s = entry.stat()
                    results.append({
                        "Name":    entry.name,
                        "Is Dir":  "Yes" if entry.is_dir() else "No",
                        "Size":    fmt_size(s.st_size) if entry.is_file() else "—",
                        "Created": fmt_ts(s.st_ctime),
                        "Modified":fmt_ts(s.st_mtime),
                        "Type":    "Directory" if entry.is_dir() else detect_type(entry.path),
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
                trash = Path.home()/".local/share/Trash/files"
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
                    results.append({"Note": "Trash is empty or not found.",
                                    "Path": str(trash)})

        elif name == "Volume Shadow Copies":
            if OS == "Windows":
                for line in _run(["vssadmin", "list", "shadows"]):
                    results.append({"Entry": line})
            else:
                results.append({"Note": "Volume Shadow Copies are Windows-specific.",
                                 "Alternative": "Use LVM snapshots on Linux."})

        elif name == "Alternate Data Streams":
            if OS == "Windows":
                for line in _run(["streams.exe", "-s", "C:\\Users",
                                   "-accepteula"]):
                    if ":$DATA" in line:
                        results.append({"ADS": line.strip()})
                if not results:
                    results.append({"Note": "Sysinternals streams.exe not found.",
                                    "Tip": "Download from Microsoft and re-run."})
            else:
                results.append({"Note": "ADS is an NTFS/Windows-specific feature."})

        elif name == "$MFT Entries":
            if OS == "Windows":
                results.append({"Note": "MFT parsing requires low-level disk access.",
                                 "Tip": "Use FTK Imager or mount image for full MFT."})
            else:
                results.append({"Note": "MFT is Windows NTFS-specific.",
                                 "Platform": OS})

        # ── EVENT LOGS ───────────────────────────────────────────────
        elif name == "Security Event Log":
            if OS == "Windows":
                lines = _run(["wevtutil", "qe", "Security",
                               "/c:50", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        if ev: results.append(ev); ev = {}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        ev[k.strip()] = v.strip()
                if ev:
                    results.append(ev)
            elif OS == "Linux":
                for log in ["/var/log/auth.log", "/var/log/secure"]:
                    if os.path.exists(log):
                        for line in _read(log).splitlines()[-100:]:
                            if line.strip():
                                results.append({"Log": log, "Entry": line})
                        break
                if not results:
                    results.append({"Note": "No auth log found.",
                                    "Tried": "/var/log/auth.log, /var/log/secure"})

        elif name == "System Event Log":
            if OS == "Windows":
                lines = _run(["wevtutil", "qe", "System",
                               "/c:50", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        if ev: results.append(ev); ev = {}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        ev[k.strip()] = v.strip()
            elif OS == "Linux":
                for log in ["/var/log/syslog", "/var/log/messages"]:
                    if os.path.exists(log):
                        for line in _read(log).splitlines()[-150:]:
                            if line.strip():
                                results.append({"Log": log, "Entry": line})
                        break
                # Also journalctl
                if not results:
                    for line in _run(["journalctl", "-n", "100",
                                       "--no-pager", "--output=short"]):
                        results.append({"Source": "journalctl", "Entry": line})

        elif name == "Application Event Log":
            if OS == "Windows":
                lines = _run(["wevtutil", "qe", "Application",
                               "/c:50", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        if ev: results.append(ev); ev = {}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        ev[k.strip()] = v.strip()
            elif OS == "Linux":
                for log in ["/var/log/dpkg.log", "/var/log/apt/history.log"]:
                    if os.path.exists(log):
                        for line in _read(log).splitlines()[-100:]:
                            if line.strip():
                                results.append({"Log": log, "Entry": line})

        elif name == "PowerShell Operational Log":
            if OS == "Windows":
                lines = _run(["wevtutil", "qe",
                               "Microsoft-Windows-PowerShell/Operational",
                               "/c:50", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        if ev: results.append(ev); ev = {}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        ev[k.strip()] = v.strip()
            elif OS == "Linux":
                # PowerShell Core history
                ps_hist = Path.home()/".local/share/powershell/PSReadLine/ConsoleHost_history.txt"
                if ps_hist.exists():
                    for line in _read(str(ps_hist)).splitlines()[-100:]:
                        if line.strip():
                            results.append({"Command": line.strip()})
                else:
                    results.append({"Note": "PowerShell not installed or no history found."})

        elif name == "RDP Session Log":
            if OS == "Windows":
                lines = _run(["wevtutil", "qe",
                               "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                               "/c:30", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        if ev: results.append(ev); ev = {}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        ev[k.strip()] = v.strip()
            elif OS == "Linux":
                # Check for xrdp or ssh sessions
                for log in ["/var/log/xrdp.log", "/var/log/xrdp-sesman.log"]:
                    if os.path.exists(log):
                        for line in _read(log).splitlines()[-50:]:
                            results.append({"Log": log, "Entry": line})
                for line in _run(["last", "-n", "30"]):
                    if "pts" in line or "tty" in line:
                        results.append({"Session": line})

        elif name == "Account Logon Events":
            if OS == "Linux":
                for line in _run(["last", "-n", "60", "-F"]):
                    if line.strip() and not line.startswith("wtmp"):
                        parts = line.split()
                        results.append({
                            "User":     parts[0] if parts else "",
                            "Terminal": parts[1] if len(parts)>1 else "",
                            "From":     parts[2] if len(parts)>2 else "",
                            "Login":    " ".join(parts[3:8]) if len(parts)>7 else "",
                        })
                for line in _run(["lastlog", "--time", "30"]):
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] != "Username":
                        results.append({
                            "User": parts[0], "Port": parts[1],
                            "From": parts[2],
                            "Latest": " ".join(parts[3:]),
                        })
            elif OS == "Windows":
                lines = _run(["wevtutil", "qe", "Security",
                               "/q:*[System[EventID=4624 or EventID=4634]]",
                               "/c:50", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        if ev: results.append(ev); ev = {}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        ev[k.strip()] = v.strip()

        elif name == "Process Creation Events (4688)":
            if OS == "Windows":
                lines = _run(["wevtutil", "qe", "Security",
                               "/q:*[System[EventID=4688]]",
                               "/c:50", "/rd:true", "/f:text"])
                ev = {}
                for line in lines:
                    line = line.strip()
                    if not line:
                        if ev: results.append(ev); ev = {}
                    elif ":" in line:
                        k, _, v = line.partition(":")
                        ev[k.strip()] = v.strip()
            elif OS == "Linux":
                # Linux process audit log
                for log in ["/var/log/audit/audit.log"]:
                    if os.path.exists(log):
                        for line in _read(log).splitlines()[-100:]:
                            if "type=EXECVE" in line or "type=SYSCALL" in line:
                                results.append({"Entry": line})
                if not results:
                    for line in _run(["journalctl", "-n", "100",
                                       "--no-pager", "_COMM=sudo"]):
                        results.append({"Source": "journalctl sudo", "Entry": line})

        # ── MEMORY ARTIFACTS ─────────────────────────────────────────
        elif name == "Process Memory Strings":
            suspicious = []
            for p in psutil.process_iter(['pid','name','exe']):
                try:
                    maps_file = f"/proc/{p.pid}/maps"
                    if os.path.exists(maps_file):
                        with open(maps_file) as mf:
                            maps = mf.read()
                        for line in maps.splitlines():
                            if any(x in line for x in
                                   ["/tmp/", "/dev/shm/", "deleted", "(deleted)"]):
                                results.append({
                                    "PID":     str(p.pid),
                                    "Process": p.info['name'] or "",
                                    "Mapping": line,
                                    "Risk":    "Suspicious mapping",
                                })
                except Exception:
                    pass
            if not results:
                for p in psutil.process_iter(['pid','name']):
                    try:
                        cmdline_file = f"/proc/{p.pid}/cmdline"
                        if os.path.exists(cmdline_file):
                            with open(cmdline_file, 'rb') as cf:
                                cmdline = cf.read().replace(b'\x00', b' ').decode(errors='replace')
                            if cmdline.strip():
                                results.append({"PID": str(p.pid),
                                                "Name": p.info['name'] or "",
                                                "CmdLine": cmdline.strip()[:200]})
                    except Exception:
                        pass

        elif name == "Injected DLLs":
            if OS == "Windows":
                lines = _run(["tasklist", "/m", "/fo", "csv"])
                try:
                    reader = _csv.reader(lines)
                    headers = next(reader, [])
                    for row in reader:
                        if row:
                            results.append(dict(zip(headers, row)))
                except Exception:
                    pass
            elif OS == "Linux":
                for p in psutil.process_iter(['pid','name']):
                    try:
                        maps_file = f"/proc/{p.pid}/maps"
                        if os.path.exists(maps_file):
                            with open(maps_file) as mf:
                                for line in mf:
                                    if ".so" in line and ("rwxp" in line or "rwx" in line):
                                        results.append({
                                            "PID":     str(p.pid),
                                            "Process": p.info['name'] or "",
                                            "Library": line.split()[-1] if line.split() else "",
                                            "Perms":   line.split()[1] if len(line.split())>1 else "",
                                            "Risk":    "Executable writable mapping",
                                        })
                    except Exception:
                        pass
                if not results:
                    results.append({"Note": "No suspicious injected mappings found."})

        elif name == "Hollowed Processes":
            suspicious = []
            for p in psutil.process_iter(['pid','name','exe','status']):
                try:
                    exe = p.info.get('exe') or ''
                    maps_file = f"/proc/{p.pid}/maps"
                    if OS == "Linux" and os.path.exists(maps_file):
                        with open(maps_file) as mf:
                            content = mf.read()
                        if "(deleted)" in content and exe:
                            suspicious.append({
                                "PID":     str(p.pid),
                                "Name":    p.info['name'] or "",
                                "Exe":     exe,
                                "Note":    "Executable mapping deleted from disk",
                                "Risk":    "⚠ Possible hollowing",
                            })
                except Exception:
                    pass
            if suspicious:
                results.extend(suspicious)
            else:
                results.append({"Note": "No obvious process hollowing indicators found."})

        elif name == "Heap Allocations":
            results.append({
                "Note":      "Live heap analysis requires kernel-level access.",
                "Available": "Process maps shown below.",
                "Platform":  OS,
            })
            for p in psutil.process_iter(['pid','name','memory_info']):
                try:
                    mi = p.info.get('memory_info')
                    if mi:
                        results.append({
                            "PID":    str(p.pid),
                            "Name":   p.info['name'] or "",
                            "RSS":    fmt_size(mi.rss),
                            "VMS":    fmt_size(mi.vms),
                        })
                except Exception:
                    pass

        elif name == "Kernel Objects":
            if OS == "Linux":
                for line in _run(["cat", "/proc/sys/kernel/dmesg_restrict"]):
                    results.append({"dmesg_restrict": line})
                for line in _run(["dmesg", "--level=err,warn",
                                   "--notime"], timeout=5)[:50]:
                    results.append({"dmesg": line})
                # Loaded kernel modules
                for line in _run(["lsmod"])[:30]:
                    parts = line.split()
                    if len(parts) >= 3:
                        results.append({"Module":parts[0],"Size":parts[1],
                                        "Used":parts[2]})
            else:
                results.append({"Note": "Kernel object enumeration requires OS-specific tools."})

        # ── CREDENTIALS & SECRETS ────────────────────────────────────
        elif name == "SAM Database Hash Dump":
            if OS == "Windows":
                results.append({
                    "Warning": "SAM dump requires SYSTEM privileges.",
                    "Tool":    "Use secretsdump.py or reg save HKLM\\SAM for offline extraction.",
                    "Status":  "Requires elevation",
                })
            elif OS == "Linux":
                shadow = "/etc/shadow"
                if os.path.exists(shadow):
                    try:
                        with open(shadow) as f:
                            for line in f:
                                parts = line.strip().split(":")
                                if len(parts) >= 2:
                                    algo = {"$1$":"MD5","$5$":"SHA-256",
                                            "$6$":"SHA-512","$y$":"yescrypt",
                                            "*":"Locked","!":"Locked"
                                            }.get(parts[1][:3], parts[1][:3] if parts[1] else "No Password")
                                    results.append({
                                        "User":    parts[0],
                                        "Hash":    parts[1][:32] + "…" if len(parts[1]) > 32 else parts[1],
                                        "Algorithm": algo,
                                        "Last Changed": fmt_ts(int(parts[2])*86400) if parts[2].isdigit() else parts[2],
                                    })
                    except PermissionError:
                        results.append({"Status": "Permission denied.",
                                        "Note": "Run as root to read /etc/shadow."})
                else:
                    results.append({"Note": "/etc/shadow not found."})

        elif name == "LSA Secrets":
            if OS == "Windows":
                results.append({
                    "Warning": "LSA secrets require SYSTEM privileges.",
                    "Tool":    "Use secretsdump.py with valid credentials for extraction.",
                    "Status":  "Requires elevation",
                })
            else:
                results.append({"Note": "LSA Secrets are Windows-specific."})

        elif name == "DPAPI Master Keys":
            if OS == "Windows":
                dpapi_dir = Path.home()/"AppData/Roaming/Microsoft/Protect"
                if dpapi_dir.exists():
                    for f in dpapi_dir.rglob("*"):
                        if f.is_file():
                            try:
                                s = f.stat()
                                results.append({
                                    "File":    f.name,
                                    "Path":    str(f),
                                    "Size":    fmt_size(s.st_size),
                                    "Modified":fmt_ts(s.st_mtime),
                                })
                            except Exception:
                                pass
                else:
                    results.append({"Note": "DPAPI directory not found."})
            else:
                results.append({"Note": "DPAPI is Windows-specific."})

        elif name == "Browser Saved Passwords":
            home = Path.home()
            login_dbs = []
            if OS == "Linux":
                login_dbs += list(home.glob(".config/google-chrome/*/Login Data"))
                login_dbs += list(home.glob(".config/chromium/*/Login Data"))
            elif OS == "Windows":
                login_dbs += list((home/"AppData/Local/Google/Chrome/User Data").glob("*/Login Data")) \
                    if (home/"AppData/Local/Google/Chrome/User Data").exists() else []
            for db in login_dbs[:3]:
                rows = _sqlite_query(str(db),
                    "SELECT origin_url, username_value, length(password_value) as pwd_len, "
                    "date_created FROM logins ORDER BY date_created DESC LIMIT 100")
                for r in rows:
                    r["Note"] = "Password encrypted (DPAPI/keyring)"
                    results.append(r)
            if not results:
                results.append({"Note": "No saved password databases found or accessible."})

        elif name == "Certificate Store":
            if OS == "Linux":
                cert_dirs = ["/etc/ssl/certs", "/usr/share/ca-certificates"]
                for d in cert_dirs:
                    if os.path.isdir(d):
                        for f in sorted(os.listdir(d))[:50]:
                            fp = os.path.join(d, f)
                            if os.path.isfile(fp):
                                try:
                                    s = os.stat(fp)
                                    results.append({
                                        "Certificate": f,
                                        "Directory":   d,
                                        "Size":        fmt_size(s.st_size),
                                        "Modified":    fmt_ts(s.st_mtime),
                                    })
                                except Exception:
                                    pass
            elif OS == "Windows":
                lines = _run(["certutil", "-store", "MY"])
                cert = {}
                for line in lines:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        cert[k.strip()] = v.strip()
                        if k.strip() == "Signature matches Public Key":
                            results.append(dict(cert)); cert = {}


        # ── EMAIL ARTIFACTS ──────────────────────────────────────────
        elif name == "PST/OST Files (Outlook)":
            # Find PST/OST files on the target path, then parse with pypff
            search_roots = []
            if OS == "Windows":
                search_roots += [
                    Path.home() / "AppData/Local/Microsoft/Outlook",
                    Path.home() / "Documents/Outlook Files",
                    Path("C:/Users"),
                ]
            elif OS == "Linux":
                search_roots += [Path.home(), Path("/home"), Path("/mnt"), Path("/media")]
            else:
                search_roots += [Path.home() / "Library/Group Containers"]

            pst_files = []
            for root in search_roots:
                if root.exists():
                    for ext in ("*.pst", "*.ost", "*.PST", "*.OST"):
                        pst_files.extend(list(root.rglob(ext))[:20])

            if not pst_files:
                results.append({"Note": "No PST/OST files found.",
                                 "Searched": ", ".join(str(r) for r in search_roots[:3])})
            else:
                for pf in pst_files[:10]:
                    try:
                        sz = os.path.getsize(str(pf))
                        s  = os.stat(str(pf))
                        row = {
                            "File":     pf.name,
                            "Path":     str(pf),
                            "Size":     fmt_size(sz),
                            "Modified": fmt_ts(s.st_mtime),
                            "Type":     "OST" if pf.suffix.lower() == ".ost" else "PST",
                        }
                        # Try to get folder/message count via pypff
                        try:
                            import pypff
                            pst_obj = pypff.file()
                            pst_obj.open(str(pf))
                            root_folder = pst_obj.get_root_folder()
                            def count_msgs(folder, depth=0):
                                total = folder.get_number_of_sub_messages()
                                if depth < 3:
                                    for i in range(folder.get_number_of_sub_folders()):
                                        try:
                                            total += count_msgs(folder.get_sub_folder(i), depth+1)
                                        except Exception:
                                            pass
                                return total
                            def count_folders(folder, depth=0):
                                n = folder.get_number_of_sub_folders()
                                if depth < 3:
                                    for i in range(n):
                                        try:
                                            n += count_folders(folder.get_sub_folder(i), depth+1)
                                        except Exception:
                                            pass
                                return n
                            row["Messages"] = str(count_msgs(root_folder))
                            row["Folders"]  = str(count_folders(root_folder))
                            pst_obj.close()
                        except Exception as pe:
                            row["Parse Note"] = str(pe)[:80]
                        results.append(row)
                    except Exception as e:
                        results.append({"File": str(pf), "Error": str(e)})

        elif name == "MSG Files (Outlook)":
            search_roots = [Path.home(), Path.home() / "Documents",
                            Path.home() / "Desktop", Path.home() / "Downloads"]
            if OS == "Windows":
                search_roots += [Path.home() / "AppData/Local/Microsoft/Outlook"]
            msg_files = []
            for root in search_roots:
                if root.exists():
                    msg_files.extend(list(root.rglob("*.msg"))[:50])
            for mf in msg_files[:30]:
                try:
                    import extract_msg
                    msg = extract_msg.openMsg(str(mf))
                    results.append({
                        "File":    mf.name,
                        "Path":    str(mf.parent),
                        "Subject": (msg.subject or "")[:100],
                        "Sender":  str(msg.sender or ""),
                        "To":      str(msg.to or "")[:80],
                        "Date":    str(msg.date or ""),
                        "Size":    fmt_size(os.path.getsize(str(mf))),
                        "Attachments": str(len(msg.attachments)),
                    })
                    msg.close()
                except Exception as e:
                    try:
                        s = os.stat(str(mf))
                        results.append({"File": mf.name, "Path": str(mf.parent),
                                        "Size": fmt_size(s.st_size), "Error": str(e)[:60]})
                    except Exception:
                        pass
            if not results:
                results.append({"Note": "No .msg files found in common locations."})

        elif name == "Thunderbird MBOX":
            tb_profiles = []
            if OS == "Linux":
                tb_profiles = list(Path.home().glob(".thunderbird/*/Mail/**/*.mbox")) +                               list(Path.home().glob(".thunderbird/*/Mail/**/INBOX"))
            elif OS == "Windows":
                tb_base = Path.home() / "AppData/Roaming/Thunderbird/Profiles"
                if tb_base.exists():
                    tb_profiles = list(tb_base.rglob("*.mbox")) +                                   list(tb_base.rglob("INBOX"))
            elif OS == "Darwin":
                tb_profiles = list((Path.home() / "Library/Thunderbird/Profiles").rglob("*.mbox"))
            for mbox_path in tb_profiles[:20]:
                try:
                    sz = os.path.getsize(str(mbox_path))
                    # Count messages (each starts with "From ")
                    count = 0
                    with open(str(mbox_path), "rb") as mf:
                        for line in mf:
                            if line.startswith(b"From "):
                                count += 1
                            if mf.tell() > 10*1024*1024:  # sample first 10MB
                                break
                    results.append({
                        "File":     mbox_path.name,
                        "Path":     str(mbox_path.parent),
                        "Size":     fmt_size(sz),
                        "Messages": str(count) + ("+" if sz > 10*1024*1024 else ""),
                    })
                except Exception as e:
                    results.append({"File": str(mbox_path), "Error": str(e)})
            if not results:
                results.append({"Note": "No Thunderbird MBOX files found."})

        elif name == "Email Accounts Config":
            configs = []
            if OS == "Windows":
                # Outlook profiles in registry
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Office\16.0\Outlook\Profiles")
                    i = 0
                    while True:
                        try:
                            profile = winreg.EnumKey(key, i)
                            configs.append({"Source": "Outlook Registry",
                                            "Profile": profile, "Type": "Outlook"})
                            i += 1
                        except OSError:
                            break
                except Exception:
                    pass
            # Thunderbird accounts.ini / prefs.js
            for pdir in [Path.home()/".thunderbird",
                         Path.home()/"AppData/Roaming/Thunderbird/Profiles"]:
                for prefs_file in pdir.rglob("prefs.js") if pdir.exists() else []:
                    try:
                        content = _read(str(prefs_file))
                        for line in content.splitlines():
                            if "mail.account" in line and "server" in line:
                                configs.append({"Source": str(prefs_file),
                                                "Config": line.strip()[:120],
                                                "Type": "Thunderbird"})
                    except Exception:
                        pass
            if not configs:
                configs.append({"Note": "No email account configs found.",
                                 "Platform": OS})
            results.extend(configs)

        elif name == "Email Attachments":
            results.append({"Note": "Run 'PST/OST Files' or 'MSG Files' first.",
                             "Tip": "Attachments are extracted per-message in the Email Viewer tab."})

        elif name == "Email Contacts":
            # Parse contacts from PST files
            search_roots = [Path.home()]
            if OS == "Windows":
                search_roots.append(Path.home() / "AppData/Local/Microsoft/Outlook")
            for root in search_roots:
                for pf in list(root.rglob("*.pst"))[:3] if root.exists() else []:
                    try:
                        import pypff
                        pst_obj = pypff.file()
                        pst_obj.open(str(pf))
                        def scan_contacts(folder, depth=0):
                            if depth > 4: return
                            fname = ""
                            try: fname = folder.get_name() or ""
                            except Exception: pass
                            if "contact" in fname.lower():
                                for i in range(folder.get_number_of_sub_messages()):
                                    try:
                                        msg = folder.get_sub_message(i)
                                        subj = ""
                                        try: subj = msg.get_plain_text_body()[:100].decode(errors='replace') if msg.get_plain_text_body() else ""
                                        except Exception: pass
                                        results.append({
                                            "PST": pf.name, "Folder": fname,
                                            "Contact": msg.get_subject() or subj[:60],
                                        })
                                    except Exception: pass
                            for i in range(folder.get_number_of_sub_folders()):
                                try: scan_contacts(folder.get_sub_folder(i), depth+1)
                                except Exception: pass
                        scan_contacts(pst_obj.get_root_folder())
                        pst_obj.close()
                    except Exception as e:
                        results.append({"PST": str(pf), "Error": str(e)})
            if not results:
                results.append({"Note": "No contact records extracted. Ensure PST files are accessible."})

        elif name == "Email Calendar Items":
            search_roots = [Path.home()]
            if OS == "Windows":
                search_roots.append(Path.home() / "AppData/Local/Microsoft/Outlook")
            for root in search_roots:
                for pf in list(root.rglob("*.pst"))[:3] if root.exists() else []:
                    try:
                        import pypff
                        pst_obj = pypff.file()
                        pst_obj.open(str(pf))
                        def scan_calendar(folder, depth=0):
                            if depth > 4: return
                            fname = ""
                            try: fname = folder.get_name() or ""
                            except Exception: pass
                            if "calendar" in fname.lower():
                                for i in range(folder.get_number_of_sub_messages()):
                                    try:
                                        msg = folder.get_sub_message(i)
                                        results.append({
                                            "PST":    pf.name,
                                            "Folder": fname,
                                            "Subject": msg.get_subject() or "",
                                        })
                                    except Exception: pass
                            for i in range(folder.get_number_of_sub_folders()):
                                try: scan_calendar(folder.get_sub_folder(i), depth+1)
                                except Exception: pass
                        scan_calendar(pst_obj.get_root_folder())
                        pst_obj.close()
                    except Exception as e:
                        results.append({"PST": str(pf), "Error": str(e)})
            if not results:
                results.append({"Note": "No calendar items extracted."})

        # ── SHELLBAGS (live) ─────────────────────────────────────────
        elif name == "Shellbags":
            if OS == "Windows":
                import winreg
                def _walk_bagmru(root_h, base, src):
                    def _walk(subpath, kpath):
                        try:
                            k = winreg.OpenKey(root_h, subpath)
                        except Exception:
                            return
                        try:
                            i = 0
                            while True:
                                try:
                                    vn, vd, vt = winreg.EnumValue(k, i)
                                except OSError:
                                    break
                                i += 1
                                if vn in ("MRUListEx", "NodeSlot", "NodeSlots"):
                                    continue
                                if isinstance(vd, bytes) and len(vd) > 2:
                                    decoded = vd[2:].decode("utf-16-le", errors="replace")
                                    decoded = "".join(c for c in decoded if c.isprintable())
                                    if decoded.strip():
                                        results.append({"Source": src,
                                                        "Key": kpath or "BagMRU",
                                                        "Value": vn,
                                                        "Data": decoded[:200]})
                            j = 0
                            while True:
                                try:
                                    sk = winreg.EnumKey(k, j)
                                except OSError:
                                    break
                                j += 1
                                _walk(subpath + "\\" + sk,
                                      (kpath + "\\" + sk) if kpath else sk)
                        finally:
                            winreg.CloseKey(k)
                    _walk(base, "")
                _walk_bagmru(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\Shell\BagMRU", "NTUSER.DAT")
                _walk_bagmru(winreg.HKEY_CURRENT_USER,
                             r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                             "UsrClass.dat")
                if not results:
                    results.append({"Note": "No shellbag entries found for current user."})
            else:
                results.append({"Note": "Shellbags are a Windows-only artifact.", "Platform": OS})

        # ── USERASSIST (live) ────────────────────────────────────────
        elif name == "UserAssist Keys":
            if OS == "Windows":
                import winreg, codecs
                base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
                try:
                    ua = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
                except Exception:
                    ua = None
                if ua:
                    gi = 0
                    while True:
                        try:
                            guid = winreg.EnumKey(ua, gi)
                        except OSError:
                            break
                        gi += 1
                        try:
                            ck = winreg.OpenKey(ua, guid + r"\Count")
                        except Exception:
                            continue
                        vi = 0
                        while True:
                            try:
                                vn, vd, vt = winreg.EnumValue(ck, vi)
                            except OSError:
                                break
                            vi += 1
                            app = codecs.decode(vn, "rot_13")
                            run_count = last_run = ""
                            if isinstance(vd, bytes) and len(vd) >= 16:
                                try:
                                    run_count = struct.unpack_from("<I", vd, 4)[0]
                                    ft = struct.unpack_from("<Q", vd, 8)[0]
                                    if ft:
                                        last_run = (datetime.datetime(1601, 1, 1) +
                                                    datetime.timedelta(microseconds=ft / 10)
                                                    ).strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    pass
                            results.append({"Application": app, "RunCount": run_count,
                                            "LastRun": last_run, "GUID": guid})
                        winreg.CloseKey(ck)
                    winreg.CloseKey(ua)
                if not results:
                    results.append({"Note": "No UserAssist entries found for current user."})
            else:
                results.append({"Note": "UserAssist is a Windows-only artifact.", "Platform": OS})

        # ── JUMP LISTS (live) ────────────────────────────────────────
        elif name == "Jump Lists":
            if OS == "Windows":
                recent = Path.home() / r"AppData\Roaming\Microsoft\Windows\Recent"
                for sub in ("AutomaticDestinations", "CustomDestinations"):
                    d = recent / sub
                    if not d.exists():
                        continue
                    for f in d.iterdir():
                        if not f.is_file():
                            continue
                        info = {"File": f.name, "Type": sub,
                                "Size": fmt_size(f.stat().st_size),
                                "Modified": fmt_ts(f.stat().st_mtime), "Targets": ""}
                        try:
                            import olefile
                            data = f.read_bytes()
                            if olefile.isOleFile(f):
                                ole = olefile.OleFileIO(f)
                                tgts = []
                                for stream in ole.listdir():
                                    try:
                                        raw = ole.openstream(stream).read()
                                        if raw[:4] == b"\x4c\x00\x00\x00":
                                            p = _lnk_localpath(raw)
                                            if p:
                                                tgts.append(p)
                                    except Exception:
                                        pass
                                ole.close()
                                info["Targets"] = " | ".join(tgts)[:300]
                        except ImportError:
                            info["Note"] = "pip install olefile for full target parsing"
                        except Exception:
                            pass
                        results.append(info)
                if not results:
                    results.append({"Note": "No jump lists found for current user."})
            else:
                results.append({"Note": "Jump Lists are a Windows-only artifact.", "Platform": OS})

        # ── WINDOWS SEARCH HISTORY (live) ────────────────────────────
        elif name == "Windows Search History":
            if OS == "Windows":
                import winreg
                base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
                try:
                    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
                except Exception:
                    k = None
                if k:
                    i = 0
                    while True:
                        try:
                            vn, vd, vt = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        if vn == "MRUListEx":
                            continue
                        if isinstance(vd, bytes):
                            term = vd.decode("utf-16-le", errors="replace").rstrip("\x00")
                            term = "".join(c for c in term if c.isprintable())
                            if term:
                                results.append({"SearchTerm": term, "ValueName": vn})
                    winreg.CloseKey(k)
                if not results:
                    results.append({"Note": "No Explorer search history (WordWheelQuery) found."})
            else:
                results.append({"Note": "Windows Search History is a Windows-only artifact.",
                                "Platform": OS})

        # ── TYPED URLS (live) ────────────────────────────────────────
        elif name == "Typed URLs":
            if OS == "Windows":
                import winreg
                for base, kind in [
                    (r"Software\Microsoft\Internet Explorer\TypedURLs", "TypedURL"),
                    (r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "TypedPath"),
                ]:
                    try:
                        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base)
                    except Exception:
                        continue
                    i = 0
                    while True:
                        try:
                            vn, vd, vt = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        results.append({"Type": kind, "Entry": vn, "Value": str(vd)})
                    winreg.CloseKey(k)
                if not results:
                    results.append({"Note": "No typed URLs/paths found for current user."})
            else:
                results.append({"Note": "Typed URLs is a Windows-only artifact.", "Platform": OS})

        # ── CACHED CREDENTIALS (live) ────────────────────────────────
        elif name == "Cached Credentials":
            if OS == "Windows":
                # Credential Manager (cmdkey) — stored generic/domain creds.
                cur = {}
                for line in _run(["cmdkey", "/list"], timeout=10):
                    s = line.strip()
                    if s.lower().startswith("target:"):
                        if cur:
                            results.append(cur)
                        cur = {"Source": "Credential Manager",
                               "Target": s.split(":", 1)[1].strip()}
                    elif s.lower().startswith("type:"):
                        cur["Type"] = s.split(":", 1)[1].strip()
                    elif s.lower().startswith("user:"):
                        cur["User"] = s.split(":", 1)[1].strip()
                if cur:
                    results.append(cur)
                # DPAPI-protected credential blob files on disk.
                for base in [Path.home() / r"AppData\Local\Microsoft\Credentials",
                             Path.home() / r"AppData\Roaming\Microsoft\Credentials"]:
                    if base.exists():
                        for f in base.iterdir():
                            if f.is_file():
                                results.append({"Source": "DPAPI Credential Blob",
                                                "Target": f.name,
                                                "Type": "Encrypted (DPAPI)",
                                                "User": fmt_size(f.stat().st_size)})
                results.append({"Source": "HKLM\\SECURITY\\Cache",
                                "Target": "MS-Cache v2 domain hashes",
                                "Type": "Requires SYSTEM privileges",
                                "Note": "Collect SECURITY hive offline/remotely to recover NL$ entries."})
            else:
                results.append({"Note": "Cached Credentials is a Windows-only artifact.",
                                "Platform": OS})

        # ── GENERIC FALLBACK for any uncaught names ───────────────────
        else:
            results.append({
                "Artifact":  name,
                "Status":    "Not Implemented",
                "Platform":  OS,
                "Note":      f"'{name}' requires platform-specific tools or elevated privileges. "
                             f"Deploy the remote agent on the target host for full collection.",
            })

    except Exception as e:
        results.append({"Error": str(e), "Artifact": name,
                        "Traceback": __import__('traceback').format_exc()[:500]})

    return results





# ══════════════════════════════════════════════════════════════
#  NATIVE WINDOWS REMOTE COLLECTION  (zero third-party deps)
# ══════════════════════════════════════════════════════════════
#
#  Transport is built entirely on signed, in-box Windows binaries — there is
#  NO paramiko / impacket / smbclient dependency anywhere in this path:
#    * net.exe        – authenticate to the admin share (IPC$, C$)
#    * robocopy.exe   – pull evidence files back into the case folder
#    * reg.exe        – remote registry query / hive save (\\HOST\HKLM...)
#    * wevtutil.exe   – remote event-log queries (/r /u /p)
#    * schtasks.exe   – remote scheduled-task enumeration (/s /u /p)
#    * tasklist.exe   – remote process listing (/s /u /p)
#    * sc.exe         – remote service control manager (\\HOST query)
#    * query.exe      – remote logon sessions (query session /server:)
#    * powershell.exe – Get-CimInstance over DCOM + Invoke-Command over WinRM
#
#  Workflow: copy the relevant evidence files back to the case folder, then
#  parse them locally with the same parsers used for forensic images.  Live /
#  volatile data that has no on-disk file is queried with the native tools.

# Module-level registry of configured remote targets, keyed by host.
REMOTE_TARGETS = {}     # host -> {"host","user","password","domain","case_dir"}

# Curated one-click remote triage set. Every entry has a native remote handler;
# files (prefetch, hives) are copied back to the case folder and parsed locally,
# and "SAM Database Hash Dump" auto-extracts NT/LM hashes once SAM+SYSTEM land.
REMOTE_QUICK_TRIAGE_SET = [
    # System context
    "OS Version & Build", "Hostname & Domain", "Local User Accounts",
    # Volatile / live state
    "Running Processes", "Active Connections", "Services (Auto-Start)",
    "Scheduled Tasks",
    # Persistence
    "Registry Run Keys", "WMI Subscriptions",
    # Event-log triage
    "Security Event Log", "Process Creation Events (4688)", "Account Logon Events",
    # Execution evidence
    "Prefetch Files",
    # Credentials (auto NT/LM extraction + LSA secrets / cached domain creds)
    "SAM Database Hash Dump", "LSA Secrets",
]


def register_remote_target(host, user="", password="", domain="", case_dir=""):
    """Store credentials + case folder for a remote host so the artifact
    worker can look them up by host string later."""
    host = (host or "").strip().lstrip("\\").split("\\")[0]
    if "\\" in user and not domain:
        domain, user = user.split("\\", 1)
    if not case_dir:
        base = os.path.join(os.path.expanduser("~"), "ForensicPro_Cases")
        case_dir = os.path.join(
            base, "%s_%s" % (host or "remote",
                             datetime.datetime.now().strftime("%Y%m%d_%H%M%S")))
    REMOTE_TARGETS[host] = {"host": host, "user": user, "password": password,
                            "domain": domain, "case_dir": case_dir}
    return REMOTE_TARGETS[host]


def _parse_reg_values(lines):
    """Parse reg.exe query output into list of {Key,Name,Type,Data}."""
    rows, cur_key = [], ""
    for ln in lines:
        if not ln.strip():
            continue
        if ln.lstrip().startswith("HKEY"):
            cur_key = ln.strip()
            continue
        m = re.match(r"^\s{2,}(.+?)\s{2,}(REG_[A-Z_]+)\s{2,}(.*)$", ln)
        if m:
            rows.append({"Key": cur_key, "Name": m.group(1).strip(),
                         "Type": m.group(2), "Data": m.group(3).strip()})
    return rows


def _parse_reg_subkeys(lines, parent):
    """Return immediate subkey names under <parent> from reg query output."""
    out = []
    pl = parent.lower().rstrip("\\")
    for ln in lines:
        s = ln.strip()
        if s.lower().startswith("hkey") and s.lower() != pl and "\\" in s:
            # keep only one level below parent
            rest = s[len(parent):].strip("\\") if s.lower().startswith(pl) else ""
            if rest and "\\" not in rest:
                out.append(rest)
    return out


def _parse_wevtutil_text(lines):
    """Parse `wevtutil ... /f:text` output into a list of event dicts."""
    events, cur, descbuf, in_desc = [], None, [], False

    def _flush():
        if cur is not None:
            if descbuf:
                cur["Description"] = " ".join(descbuf)[:300]
            events.append(cur)

    for ln in lines:
        if ln.startswith("Event["):
            _flush()
            cur, descbuf, in_desc = {}, [], False
            continue
        if cur is None:
            continue
        s = ln.strip()
        if s.startswith("Description:"):
            in_desc = True
            rest = s.split(":", 1)[1].strip()
            if rest:
                descbuf.append(rest)
            continue
        if (not in_desc) and ":" in s:
            k, _, v = s.partition(":")
            cur[k.strip()] = v.strip()
        elif in_desc and s:
            descbuf.append(s)
    _flush()
    return events


def _sqlite_rows_local(db_path, sql, params=()):
    """Query a (locally copied) SQLite DB safely via a temp copy."""
    import sqlite3 as _sq
    rows, tmp = [], db_path + ".rc_tmp"
    try:
        shutil.copy2(db_path, tmp)
        con = _sq.connect(tmp)
        con.row_factory = _sq.Row
        for r in con.execute(sql, params).fetchall():
            rows.append(dict(r))
        con.close()
    except Exception as e:
        rows.append({"Error": str(e)})
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
    return rows


class RemoteCollector:
    """Native-tool remote triage for a single Windows host."""

    EVTX_DIR = r"Windows\System32\winevt\Logs"
    PREFETCH = r"Windows\Prefetch"

    # artifact name -> (event channel, optional XPath filter)
    EVENT_LOG_MAP = {
        "Security Event Log":    ("Security", None),
        "System Event Log":      ("System", None),
        "Application Event Log": ("Application", None),
        "PowerShell Operational Log":
            ("Microsoft-Windows-PowerShell/Operational", None),
        "RDP Session Log":
            ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", None),
        "Account Logon Events":
            ("Security", "*[System[(EventID=4624 or EventID=4625)]]"),
        "Process Creation Events (4688)":
            ("Security", "*[System[(EventID=4688)]]"),
    }

    VOLATILE_UNSUPPORTED = {
        "Process Memory Strings", "Injected DLLs", "Hollowed Processes",
        "Heap Allocations", "Kernel Objects",
    }

    def __init__(self, cfg):
        self.host     = cfg["host"]
        self.user     = cfg.get("user", "")
        self.password = cfg.get("password", "")
        self.domain   = cfg.get("domain", "")
        self.case_dir = cfg.get("case_dir") or os.path.join(
            os.path.expanduser("~"), "ForensicPro_Cases", self.host)
        self.evidence_dir = os.path.join(self.case_dir, "evidence", self.host)
        os.makedirs(self.evidence_dir, exist_ok=True)
        self._connected = False

    # ── identity helpers ──────────────────────────────────────────
    @property
    def full_user(self):
        return ("%s\\%s" % (self.domain, self.user)) if self.domain else self.user

    def unc(self, rel, share="C$"):
        return r"\\%s\%s\%s" % (self.host, share, rel.lstrip("\\"))

    # ── low-level runners ─────────────────────────────────────────
    @staticmethod
    def _run(cmd, timeout=120, env=None):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, env=env)
            return p.returncode, p.stdout or "", p.stderr or ""
        except Exception as e:
            return 1, "", str(e)

    def _ps(self, script, timeout=120):
        """Run PowerShell with target credential available as $cred.
        Password is supplied via env var (not the command line)."""
        env = dict(os.environ)
        env["RC_PW"] = self.password
        pre = (
            "$ErrorActionPreference='Stop';"
            "$u='%s';"
            "$sp=ConvertTo-SecureString $env:RC_PW -AsPlainText -Force;"
            "$cred=New-Object System.Management.Automation.PSCredential($u,$sp);"
        ) % self.full_user.replace("'", "''")
        cmd = ["powershell", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-Command", pre + script]
        return self._run(cmd, timeout=timeout, env=env)

    def _ps_json(self, script, timeout=120):
        rc, out, err = self._ps(script + " | ConvertTo-Json -Depth 4 -Compress", timeout)
        out = (out or "").strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except Exception:
            return []
        if isinstance(data, dict):
            return [data]
        return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []

    def _cim(self, class_name, props, namespace="root/cimv2", where=None, timeout=120):
        """Get-CimInstance over a DCOM session (works without WinRM)."""
        flt = (" -Filter \"%s\"" % where) if where else ""
        sel = ",".join(props)
        script = (
            "$o=New-CimSessionOption -Protocol Dcom;"
            "$s=New-CimSession -ComputerName '%s' -Credential $cred -SessionOption $o;"
            "Get-CimInstance -CimSession $s -Namespace %s -ClassName %s%s | "
            "Select-Object %s"
        ) % (self.host, namespace, class_name, flt, sel)
        return self._ps_json(script, timeout)

    def _invoke(self, scriptblock, timeout=120):
        """Invoke-Command over WinRM (PowerShell remoting)."""
        script = (
            "Invoke-Command -ComputerName '%s' -Credential $cred -ScriptBlock {%s}"
        ) % (self.host, scriptblock)
        return self._ps_json(script, timeout)

    # ── connection management ─────────────────────────────────────
    def connect(self):
        if self._connected:
            return True, ""
        self._run(["net", "use", r"\\%s\IPC$" % self.host, "/delete", "/y"], timeout=20)
        cmd = ["net", "use", r"\\%s\IPC$" % self.host]
        if self.password:
            cmd.append(self.password)
        if self.user:
            cmd.append("/user:" + self.full_user)
        rc, out, err = self._run(cmd, timeout=30)
        if rc == 0:
            self._connected = True
            return True, "Connected to \\\\%s\\IPC$" % self.host
        return False, (err or out or "net use failed").strip()

    def disconnect(self):
        for share in ("IPC$", "C$"):
            self._run(["net", "use", r"\\%s\%s" % (self.host, share),
                       "/delete", "/y"], timeout=20)
        self._connected = False

    # ── file collection ───────────────────────────────────────────
    def copy_back(self, rel_paths, dest_subdir="", share="C$", pattern=None):
        """Copy file(s) from the admin share into the case evidence folder.
        Returns list of collected local file paths."""
        collected = []
        dest_root = (os.path.join(self.evidence_dir, dest_subdir)
                     if dest_subdir else self.evidence_dir)
        os.makedirs(dest_root, exist_ok=True)
        items = rel_paths if isinstance(rel_paths, (list, tuple)) else [rel_paths]
        if pattern:
            for rel in items:
                src = self.unc(rel, share)
                self._run(["robocopy", src, dest_root, pattern, "/COPY:DAT",
                           "/R:1", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS", "/NP"],
                          timeout=900)
            for f in Path(dest_root).rglob("*"):
                if f.is_file():
                    collected.append(str(f))
        else:
            for rel in items:
                src = self.unc(rel, share)
                name = os.path.basename(rel)
                dst = os.path.join(dest_root, name)
                try:
                    shutil.copy2(src, dst)
                    collected.append(dst)
                except Exception:
                    self._run(["robocopy", os.path.dirname(src), dest_root, name,
                               "/COPY:DAT", "/R:1", "/W:1", "/NFL", "/NDL",
                               "/NJH", "/NJS", "/NP"], timeout=300)
                    if os.path.exists(dst):
                        collected.append(dst)
        return collected

    def list_share_dir(self, rel, share="C$"):
        d = self.unc(rel, share)
        try:
            return sorted(os.path.join(d, n) for n in os.listdir(d))
        except Exception:
            return []

    def user_profiles(self):
        """Return list of (username, C$-relative profile path) on the target."""
        out = []
        for p in self.list_share_dir("Users"):
            name = os.path.basename(p.rstrip("\\"))
            if name.lower() in ("public", "default", "default user",
                                "all users", "defaultaccount"):
                continue
            if os.path.isdir(p):
                out.append((name, "Users\\" + name))
        return out

    # ── native remote query helpers ──────────────────────────────
    def wevtutil(self, log, xpath=None, count=200):
        cmd = ["wevtutil", "qe", log, "/c:%d" % count, "/rd:true",
               "/f:text", "/r:" + self.host]
        if self.user:
            cmd += ["/u:" + self.full_user, "/p:" + self.password]
        if xpath:
            cmd += ["/q:" + xpath]
        rc, out, err = self._run(cmd, timeout=240)
        return out.splitlines()

    def reg_query(self, hive_path, recurse=False):
        full = r"\\%s\%s" % (self.host, hive_path)
        cmd = ["reg", "query", full] + (["/s"] if recurse else [])
        rc, out, err = self._run(cmd, timeout=180)
        return out.splitlines() if rc == 0 else []

    def reg_save(self, hive_path, out_name):
        full = r"\\%s\%s" % (self.host, hive_path)
        dst = os.path.join(self.evidence_dir, out_name)
        try:
            if os.path.exists(dst):
                os.remove(dst)
        except Exception:
            pass
        rc, out, err = self._run(["reg", "save", full, dst, "/y"], timeout=240)
        return dst if (rc == 0 and os.path.exists(dst)) else ""

    def hku_sids(self):
        """Enumerate real user SIDs loaded under HKU on the target."""
        lines = self.reg_query("HKU")
        sids = []
        for ln in lines:
            s = ln.strip()
            if s.upper().startswith("HKEY_USERS\\"):
                sid = s.split("\\", 1)[1]
                if (sid.startswith("S-1-5-21") and not sid.endswith("_Classes")):
                    sids.append(sid)
        return sids

    # ── tabular native tools ─────────────────────────────────────
    def tasklist(self):
        cmd = ["tasklist", "/s", self.host]
        if self.user:
            cmd += ["/u", self.full_user, "/p", self.password]
        cmd += ["/v", "/fo", "csv"]
        rc, out, err = self._run(cmd, timeout=120)
        return self._csv_dicts(out)

    def schtasks(self):
        cmd = ["schtasks", "/query", "/s", self.host]
        if self.user:
            cmd += ["/u", self.full_user, "/p", self.password]
        cmd += ["/v", "/fo", "csv"]
        rc, out, err = self._run(cmd, timeout=120)
        return self._csv_dicts(out)

    def query_session(self):
        rc, out, err = self._run(["query", "session", "/server:" + self.host], timeout=60)
        rows = []
        lines = out.splitlines()
        for ln in lines[1:]:
            parts = ln.split()
            if parts:
                rows.append({"SessionName": parts[0] if len(parts) > 0 else "",
                             "Username": parts[1] if len(parts) > 1 else "",
                             "ID": parts[2] if len(parts) > 2 else "",
                             "State": parts[3] if len(parts) > 3 else ""})
        return rows

    @staticmethod
    def _csv_dicts(text):
        import csv as _csv
        lines = [l for l in text.splitlines() if l.strip()]
        if not lines:
            return []
        rdr = _csv.reader(lines)
        header = next(rdr, [])
        rows = []
        for row in rdr:
            if row and row != header:
                rows.append(dict(zip(header, row)))
        return rows


def collect_artifact_remote(name, host):
    """Dispatch a single artifact collection against a remote Windows host
    using only native, signed Windows tooling.  Returns list[dict] rows."""
    cfg = REMOTE_TARGETS.get(host)
    if not cfg:
        # Allow bare-host targets with the current logon token / no creds.
        cfg = register_remote_target(host)

    if platform.system() != "Windows":
        return [{"Error": "Remote collection uses native Windows tools and must "
                          "run from a Windows examiner host.",
                 "Host": host}]

    rc_obj = RemoteCollector(cfg)
    ok, msg = rc_obj.connect()
    if not ok:
        return [{"Error": "Could not authenticate to \\\\%s (admin share). %s" % (host, msg),
                 "Hint": "Verify credentials, that the host is reachable, and that "
                         "File & Printer Sharing / Admin shares are enabled."}]

    results = []
    try:
        # ── Volatile memory artifacts: not collectable without an agent ──
        if name in RemoteCollector.VOLATILE_UNSUPPORTED:
            return [{"Note": "%s is volatile in-memory data and cannot be acquired "
                             "remotely with native tools — use a live local "
                             "collection or a memory image." % name, "Host": host}]

        # ── EVENT LOGS (native wevtutil /r) ────────────────────────
        if name in RemoteCollector.EVENT_LOG_MAP:
            log, xpath = RemoteCollector.EVENT_LOG_MAP[name]
            # Also archive the raw .evtx back to the case folder for re-analysis.
            evtx_file = {"Security": "Security.evtx", "System": "System.evtx",
                         "Application": "Application.evtx"}.get(log)
            if evtx_file:
                got = rc_obj.copy_back([RemoteCollector.EVTX_DIR + "\\" + evtx_file],
                                       dest_subdir="EventLogs")
            events = _parse_wevtutil_text(rc_obj.wevtutil(log, xpath, count=300))
            for ev in events:
                results.append({
                    "Event ID": ev.get("Event ID", ""),
                    "Date":     ev.get("Date", ""),
                    "Source":   ev.get("Source", ""),
                    "Level":    ev.get("Level", ""),
                    "Computer": ev.get("Computer", ""),
                    "Description": ev.get("Description", "")[:200],
                })
            if not results:
                results.append({"Note": "No events returned from %s (channel may be "
                                        "empty or access denied)." % log})

        # ── RUNNING PROCESSES (tasklist /s) ────────────────────────
        elif name == "Running Processes":
            for r in rc_obj.tasklist():
                results.append({
                    "Name": r.get("Image Name", ""),
                    "PID":  r.get("PID", ""),
                    "Session": r.get("Session Name", ""),
                    "Memory": r.get("Mem Usage", ""),
                    "User": r.get("User Name", ""),
                    "Status": r.get("Status", ""),
                    "Title": r.get("Window Title", ""),
                })

        # ── SCHEDULED TASKS (schtasks /s) ──────────────────────────
        elif name in ("Scheduled Tasks", "Task Scheduler Jobs"):
            seen = set()
            for r in rc_obj.schtasks():
                tn = r.get("TaskName", "")
                if tn and tn not in seen:
                    seen.add(tn)
                    results.append({
                        "TaskName": tn,
                        "Status": r.get("Status", ""),
                        "Next Run": r.get("Next Run Time", ""),
                        "Last Run": r.get("Last Run Time", ""),
                        "Author": r.get("Author", ""),
                        "Run As": r.get("Run As User", ""),
                        "Command": r.get("Task To Run", "")[:160],
                    })

        # ── LOGON SESSIONS ─────────────────────────────────────────
        elif name == "Last Login Times":
            results.extend(rc_obj.query_session() or [])
            events = _parse_wevtutil_text(
                rc_obj.wevtutil("Security", "*[System[(EventID=4624)]]", count=80))
            for ev in events:
                results.append({"Event ID": ev.get("Event ID", "4624"),
                                "Date": ev.get("Date", ""),
                                "Description": ev.get("Description", "")[:200]})
            if not results:
                results.append({"Note": "No session/logon data returned."})

        # ── SERVICES (CIM Win32_Service) ───────────────────────────
        elif name == "Services (Auto-Start)":
            for r in rc_obj._cim("Win32_Service",
                                 ["Name", "DisplayName", "State", "StartMode",
                                  "StartName", "PathName"]):
                if str(r.get("StartMode", "")).lower() in ("auto", "automatic") or True:
                    results.append({
                        "Name": r.get("Name", ""),
                        "Display": r.get("DisplayName", ""),
                        "State": r.get("State", ""),
                        "StartMode": r.get("StartMode", ""),
                        "Account": r.get("StartName", ""),
                        "Path": (r.get("PathName") or "")[:160],
                    })
            if not results:
                results.append({"Note": "No services returned (DCOM/WMI may be blocked)."})

        # ── LOADED DRIVERS (CIM Win32_SystemDriver) ────────────────
        elif name == "Loaded Drivers/Modules":
            for r in rc_obj._cim("Win32_SystemDriver",
                                 ["Name", "State", "StartMode", "PathName"]):
                results.append({"Module": r.get("Name", ""),
                                "State": r.get("State", ""),
                                "StartMode": r.get("StartMode", ""),
                                "Path": (r.get("PathName") or "")[:160]})

        # ── NETWORK INTERFACES (CIM) ───────────────────────────────
        elif name == "Network Interfaces":
            for r in rc_obj._cim("Win32_NetworkAdapterConfiguration",
                                 ["Description", "MACAddress", "IPAddress",
                                  "DefaultIPGateway", "DHCPEnabled", "DNSServerSearchOrder"],
                                 where="IPEnabled=True"):
                ip = r.get("IPAddress")
                results.append({
                    "Interface": r.get("Description", ""),
                    "MAC": r.get("MACAddress", ""),
                    "Address": ", ".join(ip) if isinstance(ip, list) else (ip or ""),
                    "Gateway": ", ".join(r.get("DefaultIPGateway") or [])
                               if isinstance(r.get("DefaultIPGateway"), list)
                               else (r.get("DefaultIPGateway") or ""),
                    "DHCP": str(r.get("DHCPEnabled", "")),
                })

        # ── ACTIVE CONNECTIONS (WinRM Get-NetTCPConnection) ────────
        elif name == "Active Connections":
            rows = rc_obj._invoke(
                "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,"
                "RemoteAddress,RemotePort,State,OwningProcess")
            for r in rows:
                results.append({
                    "Local": "%s:%s" % (r.get("LocalAddress", ""), r.get("LocalPort", "")),
                    "Remote": "%s:%s" % (r.get("RemoteAddress", ""), r.get("RemotePort", "")),
                    "State": r.get("State", ""),
                    "PID": r.get("OwningProcess", ""),
                })
            if not results:
                results.append({"Note": "Active connections require PowerShell Remoting "
                                        "(WinRM) on the target — none returned."})

        # ── ARP / DNS CACHE (WinRM) ────────────────────────────────
        elif name == "ARP Cache":
            for r in rc_obj._invoke("Get-NetNeighbor | Select-Object "
                                    "IPAddress,LinkLayerAddress,State,InterfaceAlias"):
                results.append({"IP": r.get("IPAddress", ""),
                                "MAC": r.get("LinkLayerAddress", ""),
                                "State": r.get("State", ""),
                                "Interface": r.get("InterfaceAlias", "")})
            if not results:
                results.append({"Note": "ARP cache requires WinRM on the target."})

        elif name == "DNS Cache":
            for r in rc_obj._invoke("Get-DnsClientCache | Select-Object "
                                    "Entry,Name,Data,Type,TimeToLive"):
                results.append({"Entry": r.get("Entry", ""),
                                "Name": r.get("Name", ""),
                                "Data": r.get("Data", ""),
                                "Type": str(r.get("Type", ""))})
            if not results:
                results.append({"Note": "DNS cache requires WinRM on the target."})

        # ── OS / HOSTNAME (CIM) ────────────────────────────────────
        elif name == "OS Version & Build":
            for r in rc_obj._cim("Win32_OperatingSystem",
                                 ["Caption", "Version", "BuildNumber",
                                  "OSArchitecture", "InstallDate", "LastBootUpTime"]):
                results.append({"OS": r.get("Caption", ""),
                                "Version": r.get("Version", ""),
                                "Build": r.get("BuildNumber", ""),
                                "Arch": r.get("OSArchitecture", ""),
                                "Installed": str(r.get("InstallDate", "")),
                                "Last Boot": str(r.get("LastBootUpTime", ""))})

        elif name == "Hostname & Domain":
            for r in rc_obj._cim("Win32_ComputerSystem",
                                 ["Name", "Domain", "Workgroup", "Manufacturer",
                                  "Model", "UserName"]):
                results.append({"Hostname": r.get("Name", ""),
                                "Domain": r.get("Domain", "") or r.get("Workgroup", ""),
                                "Manufacturer": r.get("Manufacturer", ""),
                                "Model": r.get("Model", ""),
                                "LoggedOn": r.get("UserName", "")})

        # ── LOCAL USER ACCOUNTS (CIM) ──────────────────────────────
        elif name == "Local User Accounts":
            for r in rc_obj._cim("Win32_UserAccount",
                                 ["Name", "SID", "Disabled", "Lockout", "Description"],
                                 where="LocalAccount=True"):
                results.append({"Name": r.get("Name", ""),
                                "SID": r.get("SID", ""),
                                "Disabled": str(r.get("Disabled", "")),
                                "Lockout": str(r.get("Lockout", "")),
                                "Description": r.get("Description", "")})

        # ── INSTALLED SOFTWARE (remote registry Uninstall keys) ────
        elif name == "Installed Software":
            for base in [r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                         r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]:
                vals = _parse_reg_values(rc_obj.reg_query(base, recurse=True))
                cur = {}
                for v in vals:
                    if v["Name"] == "DisplayName":
                        cur["Name"] = v["Data"]
                    elif v["Name"] == "DisplayVersion":
                        cur["Version"] = v["Data"]
                    elif v["Name"] == "Publisher":
                        cur["Vendor"] = v["Data"]
                        if cur.get("Name"):
                            results.append(dict(cur))
                            cur = {}
            # de-dup
            seen, uniq = set(), []
            for r in results:
                key = (r.get("Name"), r.get("Version"))
                if key not in seen:
                    seen.add(key)
                    uniq.append(r)
            results = uniq

        # ── REGISTRY RUN KEYS (remote registry HKLM + HKU) ─────────
        elif name == "Registry Run Keys":
            run_paths = [
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            ]
            for sid in rc_obj.hku_sids():
                run_paths.append(r"HKU\%s\Software\Microsoft\Windows\CurrentVersion\Run" % sid)
                run_paths.append(r"HKU\%s\Software\Microsoft\Windows\CurrentVersion\RunOnce" % sid)
            for rp in run_paths:
                for v in _parse_reg_values(rc_obj.reg_query(rp)):
                    if v["Name"] and v["Name"] != "(Default)":
                        results.append({"Hive": rp, "Name": v["Name"],
                                        "Command": v["Data"]})
            if not results:
                results.append({"Note": "No Run-key entries returned (RemoteRegistry "
                                        "service may be disabled)."})

        # ── APPINIT DLLS (remote registry) ─────────────────────────
        elif name == "AppInit DLLs":
            for rp in [r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
                       r"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"]:
                for v in _parse_reg_values(rc_obj.reg_query(rp)):
                    if v["Name"] in ("AppInit_DLLs", "LoadAppInit_DLLs"):
                        results.append({"Key": rp, "Name": v["Name"], "Value": v["Data"]})
            if not results:
                results.append({"Note": "No AppInit_DLLs values found."})

        # ── WMI PERSISTENCE (CIM root/subscription) ────────────────
        elif name == "WMI Subscriptions":
            for r in rc_obj._cim("__EventFilter", ["Name", "Query"],
                                 namespace="root/subscription"):
                results.append({"Type": "EventFilter", "Name": r.get("Name", ""),
                                "Detail": (r.get("Query") or "")[:200]})
            for r in rc_obj._cim("CommandLineEventConsumer",
                                 ["Name", "CommandLineTemplate"],
                                 namespace="root/subscription"):
                results.append({"Type": "CmdLineConsumer", "Name": r.get("Name", ""),
                                "Detail": (r.get("CommandLineTemplate") or "")[:200]})
            for r in rc_obj._cim("ActiveScriptEventConsumer",
                                 ["Name", "ScriptFileName"],
                                 namespace="root/subscription"):
                results.append({"Type": "ScriptConsumer", "Name": r.get("Name", ""),
                                "Detail": (r.get("ScriptFileName") or "")[:200]})
            if not results:
                results.append({"Note": "No WMI event subscriptions found."})

        # ── USER REGISTRY ARTIFACTS via remote HKU ─────────────────
        elif name == "Typed URLs":
            for sid in rc_obj.hku_sids():
                for sub, kind in [("Software\\Microsoft\\Internet Explorer\\TypedURLs", "TypedURL"),
                                  ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", "TypedPath")]:
                    for v in _parse_reg_values(rc_obj.reg_query(r"HKU\%s\%s" % (sid, sub))):
                        results.append({"SID": sid, "Type": kind,
                                        "Entry": v["Name"], "Value": v["Data"]})
            if not results:
                results.append({"Note": "No typed URLs/paths in loaded user hives."})

        elif name == "UserAssist Keys":
            import codecs as _codecs
            for sid in rc_obj.hku_sids():
                base = (r"HKU\%s\Software\Microsoft\Windows\CurrentVersion"
                        r"\Explorer\UserAssist" % sid)
                for v in _parse_reg_values(rc_obj.reg_query(base, recurse=True)):
                    nm = v["Name"]
                    if nm and nm != "(Default)":
                        try:
                            app = _codecs.decode(nm, "rot_13")
                        except Exception:
                            app = nm
                        results.append({"SID": sid, "Application": app})
            if not results:
                results.append({"Note": "No UserAssist entries in loaded user hives."})

        elif name == "Windows Search History":
            for sid in rc_obj.hku_sids():
                base = (r"HKU\%s\Software\Microsoft\Windows\CurrentVersion"
                        r"\Explorer\WordWheelQuery" % sid)
                for v in _parse_reg_values(rc_obj.reg_query(base)):
                    if v["Name"] != "MRUListEx":
                        results.append({"SID": sid, "ValueName": v["Name"],
                                        "Raw": v["Data"]})
            if not results:
                results.append({"Note": "No WordWheelQuery entries in loaded user hives."})

        # ── PREFETCH (copy *.pf back) ──────────────────────────────
        elif name == "Prefetch Files":
            files = rc_obj.copy_back(RemoteCollector.PREFETCH, dest_subdir="Prefetch",
                                     pattern="*.pf")
            for f in files:
                try:
                    st = os.stat(f)
                    results.append({"File": os.path.basename(f),
                                    "Size": fmt_size(st.st_size),
                                    "Modified": fmt_ts(st.st_mtime),
                                    "Collected To": f})
                except Exception:
                    pass
            if not results:
                results.append({"Note": "No prefetch files collected (Superfetch may be "
                                        "off or path inaccessible)."})

        # ── LNK / SHORTCUTS (copy back + local parse) ──────────────
        elif name == "LNK / Shortcut Files":
            for uname, prof in rc_obj.user_profiles():
                recent = prof + r"\AppData\Roaming\Microsoft\Windows\Recent"
                files = rc_obj.copy_back(recent, dest_subdir="LNK\\" + uname,
                                         pattern="*.lnk")
                for f in files:
                    try:
                        data = open(f, "rb").read()
                        lp = _lnk_localpath(data)
                        st = os.stat(f)
                        results.append({"User": uname, "LNK": os.path.basename(f),
                                        "Target": lp,
                                        "Modified": fmt_ts(st.st_mtime)})
                    except Exception:
                        pass
            if not results:
                results.append({"Note": "No .lnk files collected."})

        # ── JUMP LISTS (copy back + OLE parse) ─────────────────────
        elif name == "Jump Lists":
            for uname, prof in rc_obj.user_profiles():
                d = prof + r"\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
                files = rc_obj.copy_back(d, dest_subdir="JumpLists\\" + uname,
                                         pattern="*.automaticDestinations-ms")
                for f in files:
                    info = {"User": uname, "File": os.path.basename(f), "Targets": ""}
                    try:
                        import olefile
                        if olefile.isOleFile(f):
                            ole = olefile.OleFileIO(f)
                            tg = []
                            for stream in ole.listdir():
                                try:
                                    raw = ole.openstream(stream).read()
                                    if raw[:4] == b"\x4c\x00\x00\x00":
                                        p = _lnk_localpath(raw)
                                        if p:
                                            tg.append(p)
                                except Exception:
                                    pass
                            ole.close()
                            info["Targets"] = " | ".join(tg)[:300]
                    except ImportError:
                        info["Note"] = "pip install olefile for target parsing"
                    except Exception:
                        pass
                    results.append(info)
            if not results:
                results.append({"Note": "No jump lists collected."})

        # ── BROWSER HISTORY (copy SQLite back + query locally) ─────
        elif name == "Browser History":
            for uname, prof in rc_obj.user_profiles():
                candidates = [
                    (prof + r"\AppData\Local\Google\Chrome\User Data\Default\History", "Chrome"),
                    (prof + r"\AppData\Local\Microsoft\Edge\User Data\Default\History", "Edge"),
                ]
                for rel, browser in candidates:
                    got = rc_obj.copy_back([rel], dest_subdir="Browser\\" + uname)
                    for db in got:
                        rows = _sqlite_rows_local(
                            db,
                            "SELECT url, title, visit_count, last_visit_time "
                            "FROM urls ORDER BY last_visit_time DESC LIMIT 200")
                        for r in rows:
                            if "Error" in r:
                                continue
                            results.append({"User": uname, "Browser": browser,
                                            "URL": r.get("url", ""),
                                            "Title": r.get("title", ""),
                                            "Visits": r.get("visit_count", "")})
                # Firefox: one places.sqlite per profile directory.
                ffp = prof + r"\AppData\Roaming\Mozilla\Firefox\Profiles"
                for pdir in rc_obj.list_share_dir(ffp):
                    if not os.path.isdir(pdir):
                        continue
                    prof_name = os.path.basename(pdir.rstrip("\\"))
                    rel = ffp + "\\" + prof_name + "\\places.sqlite"
                    got = rc_obj.copy_back([rel], dest_subdir="Browser\\" + uname + "\\" + prof_name)
                    for db in got:
                        rows = _sqlite_rows_local(
                            db,
                            "SELECT url, title, visit_count, last_visit_date "
                            "FROM moz_places ORDER BY last_visit_date DESC LIMIT 200")
                        for r in rows:
                            if "Error" in r:
                                continue
                            results.append({"User": uname, "Browser": "Firefox",
                                            "URL": r.get("url", ""),
                                            "Title": r.get("title", ""),
                                            "Visits": r.get("visit_count", "")})
            if not results:
                results.append({"Note": "No browser history databases collected."})

        # ── CREDENTIAL / HIVE ACQUISITION (reg save back) ──────────
        elif name in ("SAM Database Hash Dump", "LSA Secrets", "DPAPI Master Keys",
                      "Cached Credentials"):
            saved = {}
            for hv, fn in [("HKLM\\SAM", "SAM"), ("HKLM\\SECURITY", "SECURITY"),
                           ("HKLM\\SYSTEM", "SYSTEM")]:
                p = rc_obj.reg_save(hv, fn)
                if p:
                    saved[fn] = p
            if saved:
                for fn, p in saved.items():
                    results.append({"Collected Hive": os.path.basename(p),
                                    "Path": p,
                                    "Note": "Saved to case folder \u2014 parsed offline locally."})
                # ── AUTO-PARSE: extract NT/LM hashes once SAM+SYSTEM land ──
                if name == "SAM Database Hash Dump" and "SAM" in saved and "SYSTEM" in saved:
                    try:
                        hashes = extract_sam_hashes(saved["SAM"], saved["SYSTEM"])
                    except Exception as ex:
                        hashes = [{"Error": "Auto hash extraction failed: %s" % ex}]
                    try:
                        dump_lines = [h["pwdump"] for h in hashes if "pwdump" in h]
                        if dump_lines:
                            dump_path = os.path.join(rc_obj.evidence_dir, "sam_hashes.txt")
                            with open(dump_path, "w") as fh:
                                fh.write("\n".join(dump_lines) + "\n")
                            results.append({"Note": "Recovered %d account hash(es); "
                                            "pwdump saved to %s" % (len(dump_lines), dump_path)})
                    except Exception:
                        pass
                    results.extend(hashes)
                elif name == "SAM Database Hash Dump":
                    results.append({"Note": "SAM and SYSTEM hives are both required to "
                                            "auto-extract hashes; one was not collected."})
                # ── AUTO-PARSE: LSA secrets + cached domain creds (DCC2) ──
                if name in ("LSA Secrets", "Cached Credentials") and \
                   "SECURITY" in saved and "SYSTEM" in saved:
                    try:
                        secrets = extract_lsa_secrets(saved["SECURITY"], saved["SYSTEM"])
                    except Exception as ex:
                        secrets = [{"Error": "Auto LSA extraction failed: %s" % ex}]
                    try:
                        dcc2_lines = [s["Hashcat (-m 2100)"] for s in secrets
                                      if "Hashcat (-m 2100)" in s]
                        if dcc2_lines:
                            dcc_path = os.path.join(rc_obj.evidence_dir, "cached_domain_creds_dcc2.txt")
                            with open(dcc_path, "w") as fh:
                                fh.write("\n".join(dcc2_lines) + "\n")
                            results.append({"Note": "Recovered %d cached domain credential(s); "
                                            "Hashcat -m 2100 file saved to %s"
                                            % (len(dcc2_lines), dcc_path)})
                    except Exception:
                        pass
                    results.extend(secrets)
                elif name in ("LSA Secrets", "Cached Credentials"):
                    results.append({"Note": "SECURITY and SYSTEM hives are both required to "
                                            "auto-extract LSA secrets / cached creds; "
                                            "one was not collected."})
            else:
                results.append({"Note": "Could not save SAM/SECURITY/SYSTEM hives "
                                        "(requires admin + RemoteRegistry)."})

        # ── PST / OST (locate + copy back) ─────────────────────────
        elif name in ("PST/OST Files (Outlook)",):
            for uname, prof in rc_obj.user_profiles():
                d = prof + r"\AppData\Local\Microsoft\Outlook"
                for f in rc_obj.list_share_dir(d):
                    low = f.lower()
                    if low.endswith(".pst") or low.endswith(".ost"):
                        try:
                            sz = os.path.getsize(f)
                        except Exception:
                            sz = 0
                        row = {"User": uname, "File": os.path.basename(f),
                               "Size": fmt_size(sz), "Remote Path": f}
                        if sz and sz < 512 * 1024 * 1024:
                            got = rc_obj.copy_back(
                                [d + "\\" + os.path.basename(f)],
                                dest_subdir="Outlook\\" + uname)
                            if got:
                                row["Collected To"] = got[0]
                        else:
                            row["Note"] = "Too large for auto-copy; collect manually."
                        results.append(row)
            if not results:
                results.append({"Note": "No PST/OST files found in user profiles."})

        # ── FALLBACK: copy whole evidence path or note ─────────────
        else:
            results.append({
                "Artifact": name,
                "Host": host,
                "Status": "No remote handler",
                "Note": "This artifact has no native remote collector. Acquire the "
                        "host's disk image, or run a local live collection on the target.",
            })

    finally:
        rc_obj.disconnect()

    # Tag every row with provenance so the analyst knows the source host.
    for r in results:
        if isinstance(r, dict):
            r.setdefault("Host", host)
    if not results:
        results.append({"Note": "No data returned for %s from %s" % (name, host)})
    return results



# ══════════════════════════════════════════════════════════════
#  WORKER THREADS
# ══════════════════════════════════════════════════════════════

class ArtifactWorker(QThread):
    progress   = pyqtSignal(int, int, str)   # current, total, name
    result     = pyqtSignal(str, list)        # name, rows
    finished   = pyqtSignal()

    def __init__(self, names, target_path=None, target_type="local"):
        super().__init__()
        self.names       = names
        self.target_path = target_path   # path to scan (dir/image/file)
        self.target_type = target_type   # "local", "image", "directory", "file"

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
        self._current_path  = None
        self._current_bytes = b""
        self._current_name  = ""
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
        elif self._current_bytes:
            # Bytes mode — serve from stored buffer
            if mode == "Image":
                self._load_image_from_bytes(self._current_bytes, self._current_name)
            elif mode == "Strings":
                self._load_strings_from_bytes(self._current_bytes)
            elif mode == "Metadata":
                self._load_meta_from_bytes(self._current_name, self._current_bytes)
            # Text and Hex are already loaded in load_bytes()

    def load_path(self, path: str):
        self._current_path = path
        self.path_label.setText(os.path.basename(path))
        mode = ["Text","Hex","Image","Metadata","Strings"][self.stack.currentIndex()]
        self._load_for_mode(path, mode)

    def load_bytes(self, data: bytes, name: str = ""):
        """Load raw bytes — supports Text, Hex, Image, Strings modes."""
        self._current_path = None
        self._current_bytes = data          # keep for Image/Strings modes
        self._current_name  = name
        self.path_label.setText(name)

        # Always load hex
        self.hex_view.load_data(data)

        # Text decode
        try:
            txt = data.decode("utf-8", "replace")
            self.text_view.setPlainText(txt[:200_000])
        except Exception:
            self.text_view.setPlainText("[Binary data]")

        # Image — try immediately so switching to Image tab works
        self._load_image_from_bytes(data, name)

        # Strings
        self._load_strings_from_bytes(data)

        # Metadata from bytes (basic)
        self._load_meta_from_bytes(name, data)

        # Switch to best mode for this content
        ext = os.path.splitext(name)[1].lower()
        image_exts = {".jpg",".jpeg",".png",".gif",".bmp",".tiff",".tif",
                      ".webp",".ico",".svg"}
        if ext in image_exts:
            self._switch_mode("Image")
        elif ext in (".txt",".log",".xml",".json",".csv",".html",".htm",
                     ".py",".js",".sh",".bat",".ps1",".reg",".ini",".cfg"):
            self._switch_mode("Text")
        else:
            self._switch_mode("Hex")

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
        # Load image from a host filesystem path, delegate rendering to _render_pixmap.
        pix = QPixmap(path)
        if pix.isNull():
            try:
                with open(path, "rb") as f:
                    data = f.read()
                img = QImage.fromData(data)
                if not img.isNull():
                    pix = QPixmap.fromImage(img)
            except Exception:
                pass
        self._render_pixmap(pix)

    def _render_pixmap(self, pix):
        # Scale and display a QPixmap, or show error text if null.
        if pix is None or pix.isNull():
            self.image_label.setText(
                '<span style="color:#8b949e">[ No image preview ]</span>')
        else:
            parent = self.image_label.parent()
            w = max(parent.width()  - 20, 100) if parent else 600
            h = max(parent.height() - 20, 100) if parent else 400
            scaled = pix.scaled(
                w, h,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self.image_label.setPixmap(scaled)

    def _load_image_from_bytes(self, data: bytes, name: str = ""):
        # Load and display an image from raw bytes (forensic image files).
        pix    = QPixmap()
        loaded = False
        if data:
            try:
                img = QImage.fromData(data)
                if not img.isNull():
                    pix    = QPixmap.fromImage(img)
                    loaded = True
            except Exception:
                pass
            if not loaded:
                try:
                    p2 = QPixmap()
                    if p2.loadFromData(data):
                        pix    = p2
                        loaded = True
                except Exception:
                    pass
            if not loaded:
                try:
                    import tempfile
                    ext = os.path.splitext(name)[1] if name else ".bin"
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                        tf.write(data)
                        tmp_path = tf.name
                    pix = QPixmap(tmp_path)
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
                except Exception:
                    pix = QPixmap()
        self._render_pixmap(pix)

    def _load_strings_from_bytes(self, data: bytes):
        # Extract printable ASCII strings (>=4 chars) from raw bytes.
        try:
            strings = []
            cur     = []
            for b in data[:4 * 1024 * 1024]:
                if 32 <= b < 127:
                    cur.append(chr(b))
                else:
                    if len(cur) >= 4:
                        strings.append("".join(cur))
                    cur = []
            if len(cur) >= 4:
                strings.append("".join(cur))
            header = "[%d strings found]\n\n" % len(strings)
            self.strings_view.setPlainText(header + "\n".join(strings[:5000]))
        except Exception as e:
            self.strings_view.setPlainText("[Strings error: %s]" % e)

    def _load_meta_from_bytes(self, name: str, data: bytes):
        # Show basic metadata for a bytes buffer (no filesystem access needed).
        self.meta_table.setRowCount(0)
        self.meta_table.setColumnCount(2)
        self.meta_table.setHorizontalHeaderLabels(["Property", "Value"])
        hdr = self.meta_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        rows = [
            ("Name",   name or "(unknown)"),
            ("Size",   "%s  (%d bytes)" % (fmt_size(len(data)), len(data))),
            ("Type",   detect_type_by_name(name) if name else "Unknown"),
        ]
        if data:
            rows.append(("MD5",    hashlib.md5(data).hexdigest()))
            rows.append(("SHA-256",hashlib.sha256(data).hexdigest()))
            rows.append(("Header", " ".join("%02X" % b for b in data[:16])))
        for prop, val in rows:
            r = self.meta_table.rowCount()
            self.meta_table.insertRow(r)
            pi = QTableWidgetItem(str(prop))
            pi.setForeground(QBrush(QColor(C["fg2"])))
            vi = QTableWidgetItem(str(val))
            vi.setForeground(QBrush(QColor(C["fg"])))
            self.meta_table.setItem(r, 0, pi)
            self.meta_table.setItem(r, 1, vi)


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
                "[%d strings found]\n\n" % len(strings) + "\n".join(strings[:5000]))
        except Exception as e:
            self.strings_view.setPlainText(f"[Error: {e}]")



# ══════════════════════════════════════════════════════════════
#  FORENSIC IMAGE FILESYSTEM  (pytsk3 + libewf ctypes / ewfmount)
#
#  E01/EWF backend priority:
#    1. ctypes libewf  (libewf.so.2 on Linux, libewf.dll on Windows)
#       No pip package needed. Install once:
#         Linux:   sudo apt install ewf-tools   (or libewf2)
#         Windows: download libewf from https://github.com/libyal/libewf/releases
#    2. pyewf          pip install pyewf  (if wheel available)
#    3. ewfmount FUSE  Linux only, apt install ewf-tools
#  DD / RAW / ISO:  pytsk3 direct, no extra library needed
# ══════════════════════════════════════════════════════════════

def _load_libewf_ctypes():
    """Load libewf shared library via ctypes. Returns CDLL or None."""
    import ctypes
    # Script directory — most convenient place to drop libewf.dll on Windows
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if platform.system() == 'Windows':
        candidates = [
            os.path.join(script_dir, 'libewf.dll'),   # next to script  <-- check first
            'libewf.dll',                               # on PATH / CWD
            'libewf-2.dll',
            r'C:\Program Files\EWF Tools\libewf.dll',
            r'C:\Program Files\ewf-tools\libewf.dll',
            r'C:\ewf-tools\libewf.dll',
            r'C:\Windows\System32\libewf.dll',
        ]
    elif platform.system() == 'Darwin':
        candidates = [
            'libewf.dylib', 'libewf.2.dylib',
            '/usr/local/lib/libewf.dylib',
            '/opt/homebrew/lib/libewf.dylib',
            '/opt/homebrew/opt/libewf/lib/libewf.dylib',
        ]
    else:
        candidates = [
            'libewf.so.2', 'libewf.so',
            '/usr/lib/x86_64-linux-gnu/libewf.so.2',
            '/usr/lib/aarch64-linux-gnu/libewf.so.2',
            '/usr/lib/libewf.so.2',
        ]
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            lib.libewf_get_version.restype = ctypes.c_char_p
            lib.libewf_get_version()   # smoke-test: will throw if wrong DLL
            return lib
        except Exception:
            pass
    return None


def _ewf_available():
    """Probe for EWF backend. Returns (method_str, backend_obj) or (None, None)."""
    lib = _load_libewf_ctypes()
    if lib:
        return ('ctypes_libewf', lib)
    try:
        import pyewf
        return ('pyewf', pyewf)
    except ImportError:
        pass
    if platform.system() != 'Windows' and shutil.which('ewfmount'):
        return ('ewfmount', None)
    return (None, None)


def _make_ewf_img_class():
    """Build and return an EWFImgInfo class (deferred import of pytsk3)."""
    import pytsk3, ctypes

    class EWFImgInfo(pytsk3.Img_Info):
        """pytsk3.Img_Info backed by a ctypes libewf handle."""
        def __init__(self, lib, handle, media_size):
            self._lib        = lib
            self._handle     = handle
            self._media_size = media_size
            lib.libewf_handle_read_random.restype  = ctypes.c_ssize_t
            lib.libewf_handle_read_random.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p,
                ctypes.c_size_t, ctypes.c_int64, ctypes.c_void_p]
            super().__init__(url='')

        def read(self, offset, length):
            import ctypes as _ct
            buf = _ct.create_string_buffer(length)
            n   = self._lib.libewf_handle_read_random(
                      self._handle, buf, length, offset, None)
            return buf.raw[:max(0, n)]

        def get_size(self):
            return self._media_size

    return EWFImgInfo


class ForensicImageFS:
    """
    Unified forensic image access via pytsk3.
    Supports: E01/EWF, DD, RAW, ISO. Use ForensicImageFS.get(path).
    """
    _cache      = {}
    _mount_dirs = {}

    def __init__(self, image_path):
        self.image_path  = image_path
        self.fs          = None
        self.img         = None
        self.partitions  = []
        self.active_part = 0
        self.error       = ""
        self._mount_dir  = None
        self._ewf_handle = None
        self._ewf_lib    = None
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
            self.error = "pytsk3 not installed. Run:  pip install pytsk3"
            return
        ext    = os.path.splitext(self.image_path)[1].lower()
        is_ewf = ext in ('.e01', '.ewf', '.ex01', '.e02', '.s01', '.l01')
        if is_ewf:
            self._open_ewf(pytsk3)
        else:
            self._open_raw(pytsk3, self.image_path)

    def _open_ewf(self, pytsk3):
        """Try EWF backends in order: ctypes_libewf -> pyewf -> ewfmount."""
        import ctypes
        method, backend = _ewf_available()

        # Always normalise path: resolve to absolute, backslashes on Windows.
        # This fixes the mixed-separator bug (e.g. C:\path/to/file.E01).
        norm_path = os.path.normpath(os.path.abspath(self.image_path))

        if method == 'ctypes_libewf':
            lib = backend
            try:
                lib.libewf_handle_initialize.restype  = ctypes.c_int
                lib.libewf_handle_initialize.argtypes = [
                    ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
                lib.libewf_handle_get_media_size.restype  = ctypes.c_int
                lib.libewf_handle_get_media_size.argtypes = [
                    ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64),
                    ctypes.c_void_p]

                handle = ctypes.c_void_p()
                if lib.libewf_handle_initialize(ctypes.byref(handle), None) != 1:
                    raise RuntimeError("libewf_handle_initialize failed")

                # Build segment file list (.E01, .E02, …)
                base      = os.path.splitext(norm_path)[0]
                seg_paths = [norm_path]
                for n in range(2, 200):
                    for sfx in ('.E%02d' % n, '.e%02d' % n):
                        seg = base + sfx
                        if os.path.exists(seg):
                            seg_paths.append(os.path.normpath(seg))
                            break
                    else:
                        break   # no more segments

                on_windows = platform.system() == 'Windows'
                if on_windows:
                    # Use the wide-character API to handle Unicode paths correctly
                    try:
                        lib.libewf_handle_open_wide.restype  = ctypes.c_int
                        lib.libewf_handle_open_wide.argtypes = [
                            ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_wchar_p),
                            ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
                        c_files = (ctypes.c_wchar_p * len(seg_paths))(
                            *seg_paths)
                        ret = lib.libewf_handle_open_wide(
                            handle, c_files, len(seg_paths), 1, None)
                    except AttributeError:
                        # Older libewf without wide API — fall back to ANSI
                        lib.libewf_handle_open.restype  = ctypes.c_int
                        lib.libewf_handle_open.argtypes = [
                            ctypes.c_void_p,
                            ctypes.POINTER(ctypes.c_char_p),
                            ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
                        # Encode as filesystem encoding (handles non-ASCII
                        # if the locale/codepage supports it)
                        enc = sys.getfilesystemencoding() or 'mbcs'
                        c_files = (ctypes.c_char_p * len(seg_paths))(
                            *[p.encode(enc, errors='replace') for p in seg_paths])
                        ret = lib.libewf_handle_open(
                            handle, c_files, len(seg_paths), 1, None)
                else:
                    lib.libewf_handle_open.restype  = ctypes.c_int
                    lib.libewf_handle_open.argtypes = [
                        ctypes.c_void_p,
                        ctypes.POINTER(ctypes.c_char_p),
                        ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
                    c_files = (ctypes.c_char_p * len(seg_paths))(
                        *[p.encode('utf-8') for p in seg_paths])
                    ret = lib.libewf_handle_open(
                        handle, c_files, len(seg_paths), 1, None)

                if ret != 1:
                    raise RuntimeError(
                        "libewf_handle_open failed (ret=%d) for: %s" % (ret, norm_path))

                media_sz = ctypes.c_uint64()
                lib.libewf_handle_get_media_size(handle, ctypes.byref(media_sz), None)
                self._ewf_lib    = lib
                self._ewf_handle = handle
                EWFImgInfo       = _make_ewf_img_class()
                self.img         = EWFImgInfo(lib, handle, media_sz.value)
                self._finish_open(pytsk3)
                return
            except Exception as e:
                if self._ewf_handle:
                    try: lib.libewf_handle_close(self._ewf_handle, None)
                    except Exception: pass
                    self._ewf_handle = None
                self._ewf_lib = None
                ctypes_err = str(e)
                # On Windows with no further fallback, report clearly
                if platform.system() == 'Windows':
                    self.error = (
                        "libewf.dll failed: %s  "
                        "Download from https://github.com/libyal/libewf/releases "
                        "and place libewf.dll next to forensic_qt.py" % ctypes_err)
                    return
                # On Linux/macOS fall through to pyewf / ewfmount below

        if method == 'pyewf':
            try:
                # Normalise path before passing to pyewf glob —
                # mixed separators cause "unable to glob" on Windows
                filenames = backend.glob(norm_path)
                if not filenames:
                    # glob failed or returned empty; pass the file directly
                    filenames = [norm_path]
                ewf_h = backend.handle()
                ewf_h.open(filenames)
                self._ewf_handle = ewf_h

                # pytsk3.Img_Info(ewf_h) only works with older pyewf builds
                # that patched the C extension. Newer pyewf returns a pure
                # Python handle object — wrap it the same way as the ctypes
                # branch using a pytsk3.Img_Info subclass with read/get_size.
                try:
                    self.img = pytsk3.Img_Info(ewf_h)
                except TypeError:
                    # pytsk3 rejected the handle — use our wrapper class
                    import ctypes as _ct

                    class _PyEWFImg(pytsk3.Img_Info):
                        def __init__(self, h):
                            self._h = h
                            super().__init__(url='')
                        def read(self, offset, length):
                            self._h.seek(offset)
                            return self._h.read(length)
                        def get_size(self):
                            return self._h.get_media_size()

                    self.img = _PyEWFImg(ewf_h)

                self._finish_open(pytsk3)
                return
            except Exception as e:
                if platform.system() == 'Windows':
                    self.error = "pyewf failed: %s" % e
                    return

        if platform.system() != 'Windows' and shutil.which('ewfmount'):
            self._open_ewf_fuse(pytsk3)
            return

        self.error = (
            "No EWF library found. "
            "Windows: place libewf.dll next to forensic_qt.py "
            "(download from https://github.com/libyal/libewf/releases). "
            "Linux: sudo apt install ewf-tools  OR  install libewf2.")

    def _open_ewf_fuse(self, pytsk3):
        mnt = tempfile.mkdtemp(prefix='fpro_ewf_')
        self._mount_dir = mnt
        ForensicImageFS._mount_dirs[self.image_path] = mnt
        ret = os.system('ewfmount "%s" "%s" 2>/dev/null' % (self.image_path, mnt))
        if ret != 0:
            self.error = ("ewfmount failed (exit %d). "
                          "Try: sudo apt install ewf-tools" % ret)
            return
        ewf1 = os.path.join(mnt, 'ewf1')
        if not os.path.exists(ewf1):
            cands = sorted(os.listdir(mnt))
            ewf1  = os.path.join(mnt, cands[0]) if cands else None
        if not ewf1:
            self.error = "ewfmount produced no output in %s" % mnt
            return
        self._open_raw(pytsk3, ewf1)

    def _open_raw(self, pytsk3, raw_path):
        try:
            self.img = pytsk3.Img_Info(raw_path)
        except Exception as e:
            self.error = "pytsk3.Img_Info: %s" % e
            return
        self._finish_open(pytsk3)

    def _finish_open(self, pytsk3):
        try:
            vol = pytsk3.Volume_Info(self.img)
            for part in vol:
                desc = part.desc.decode(errors='replace').strip()
                if any(s in desc for s in
                       ('Unallocated', 'Safety', 'Meta', 'Table', 'DOS')):
                    continue
                self.partitions.append({
                    'desc':   desc,
                    'offset': part.start * vol.info.block_size,
                    'size':   part.len   * vol.info.block_size,
                    'addr':   part.addr,
                })
            for idx, p in enumerate(self.partitions):
                try:
                    self.fs = pytsk3.FS_Info(self.img, offset=p['offset'])
                    self.active_part = idx
                    return
                except Exception:
                    continue
        except Exception:
            pass
        try:
            self.fs = pytsk3.FS_Info(self.img)
            if not self.partitions:
                try:   sz = os.path.getsize(self.image_path)
                except: sz = 0
                self.partitions = [{'desc':'Whole Image','offset':0,'size':sz,'addr':0}]
        except Exception as e:
            self.error = ("No filesystem found. %s  "
                          "Supported: NTFS FAT ext2/3/4 ISO9660 HFS+" % e)

    def switch_partition(self, idx):
        if not self.img or idx >= len(self.partitions):
            return False
        try:
            import pytsk3
            self.fs = pytsk3.FS_Info(self.img, offset=self.partitions[idx]['offset'])
            self.active_part = idx
            return True
        except Exception as e:
            self.error = str(e)
            return False

    def list_dir(self, inode=None, path=None):
        if not self.fs:
            return []
        try:
            import pytsk3
        except ImportError:
            return []
        entries = []
        try:
            d = (self.fs.open_dir(inode=inode) if inode is not None
                 else self.fs.open_dir(path=path or '/'))
            for e in d:
                try:
                    name = e.info.name.name.decode(errors='replace')
                    if name in ('.', '..', '$OrphanFiles'):
                        continue
                    meta   = e.info.meta
                    is_dir = bool(meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
                    entries.append({
                        'name':   name,
                        'is_dir': is_dir,
                        'size':   meta.size   if meta else 0,
                        'mtime':  meta.mtime  if meta else 0,
                        'atime':  meta.atime  if meta else 0,
                        'ctime':  meta.crtime if meta else 0,
                        'inode':  meta.addr   if meta else 0,
                        'type':   'Directory' if is_dir else detect_type_by_name(name),
                    })
                except Exception:
                    pass
        except Exception as e:
            entries.append({'name':'[Error: %s]' % e,'is_dir':False,
                            'size':0,'mtime':0,'atime':0,'ctime':0,'inode':0,'type':'Error'})
        entries.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return entries

    def read_file(self, inode, max_bytes=4*1024*1024):
        if not self.fs:
            return b''
        try:
            f    = self.fs.open_meta(inode=inode)
            size = min(f.info.meta.size, max_bytes)
            return f.read_random(0, size)
        except Exception as e:
            return ('[Read error: %s]' % e).encode()

    def cleanup(self):
        import ctypes
        if self._ewf_handle and self._ewf_lib:
            try: self._ewf_lib.libewf_handle_close(self._ewf_handle, None)
            except Exception: pass
            self._ewf_handle = None
            self._ewf_lib    = None
        elif self._ewf_handle:
            try: self._ewf_handle.close()
            except Exception: pass
            self._ewf_handle = None
        if self._mount_dir and os.path.isdir(self._mount_dir):
            os.system('fusermount -u "%s" 2>/dev/null || umount "%s" 2>/dev/null'
                      % (self._mount_dir, self._mount_dir))
            try: os.rmdir(self._mount_dir)
            except Exception: pass
            self._mount_dir = None

    def fs_type_str(self):
        if not self.fs: return 'Unknown'
        return {2:'FAT12',4:'FAT16',8:'FAT32',0x0b:'exFAT',0x80:'ext2',
                0x81:'ext3',0x82:'ext4',0x03:'NTFS',0x0c:'ISO9660',
                0x10:'HFS+',0x12:'YAFFS2'
                }.get(self.fs.info.ftype, 'FS type %d' % self.fs.info.ftype)

    def ewf_backend(self):
        m, _ = _ewf_available()
        return m or 'none'


def detect_type_by_name(name):
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
    }.get(os.path.splitext(name)[1].lower(), 'File')

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
            ["Name","Size","Type","Modified","Created","Permissions",
             "Path","Inode","MD5","SHA-256"])
        self.file_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for i in range(1, 10):
            self.file_table.horizontalHeader().setSectionResizeMode(
                i, QHeaderView.ResizeMode.ResizeToContents)
        # Hide hash columns by default — computed on demand
        for col in (8, 9):
            self.file_table.setColumnHidden(col, True)
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
                                    data={"type": "dir", "path": str(Path.home())})
        self._add_lazy_dir_child(home_item, str(Path.home()))
        fs_root.addChild(home_item)

        for part in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(part.mountpoint)
                pct = u.percent
                label = f"💾  {part.device}  [{part.fstype}]  {pct:.0f}%"
                item = self._make_item(label, color=C['orange'],
                                       data={"type": "dir", "path": part.mountpoint})
                self._add_lazy_dir_child(item, str(part.mountpoint))
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
        """Add forensic image or disk directory to the evidence tree."""
        is_dir = os.path.isdir(path)
        if is_dir:
            label = "💾  %s" % (os.path.basename(path) or path)
            item  = self._make_item(label, color=C['orange'],
                                    data={"type": "dir", "path": path})
            self._add_lazy_dir_child(item, path)
        else:
            label = "🖴  %s" % os.path.basename(path)
            item  = self._make_item(label, color=C['orange'],
                                    data={"type": "image", "path": path})
            self._add_image_sentinel(item, path, inode=None)
        self.img_root.addChild(item)
        self.img_root.setExpanded(True)
        if not getattr(self, "_expand_connected", False):
            self.ev_tree.itemExpanded.connect(self._on_item_expanded)
            self._expand_connected = True

    def add_remote_target(self, host):
        """Add a remote Windows host to the evidence tree for native triage."""
        host = (host or "").strip()
        if not host:
            return
        # Avoid duplicates.
        for i in range(self.remote_root.childCount()):
            d = self.remote_root.child(i).data(0, Qt.ItemDataRole.UserRole) or {}
            if d.get("label") == host:
                self.remote_root.setExpanded(True)
                return
        label = "🌐  %s" % host
        item = self._make_item(label, color=C['accent'],
                               data={"type": "remote", "label": host, "path": host})
        self.remote_root.addChild(item)
        self.remote_root.setExpanded(True)

    def _add_lazy_dir_child(self, parent_item, dir_path):
        """Sentinel for host-filesystem directories."""
        s = QTreeWidgetItem(["__lazy_dir__"])
        s.setData(0, Qt.ItemDataRole.UserRole,
                  {"type": "sentinel_dir", "path": str(dir_path)})
        parent_item.addChild(s)
        if not getattr(self, "_expand_connected", False):
            self.ev_tree.itemExpanded.connect(self._on_item_expanded)
            self._expand_connected = True

    def _add_image_sentinel(self, parent_item, image_path, inode=None):
        """Sentinel for forensic image directories."""
        s = QTreeWidgetItem(["__lazy_img__"])
        s.setData(0, Qt.ItemDataRole.UserRole,
                  {"type": "sentinel_img",
                   "image_path": image_path,
                   "inode": inode})
        parent_item.addChild(s)

    def _on_item_expanded(self, item):
        """Expand handler — replaces sentinel with real children."""
        if item.childCount() != 1:
            return
        child = item.child(0)
        d = child.data(0, Qt.ItemDataRole.UserRole) or {}
        t = d.get("type", "")
        if t == "sentinel_dir" or t == "sentinel":
            item.removeChild(child)
            self._populate_dir_children(item, Path(d["path"]))
        elif t == "sentinel_img":
            item.removeChild(child)
            self._populate_image_children(item, d["image_path"], d.get("inode"))

    def _populate_dir_children(self, parent_item, dir_path):
        """Host filesystem directory listing."""
        try:
            entries = sorted(dir_path.iterdir(),
                             key=lambda x: (not x.is_dir(), x.name.lower()))
        except PermissionError:
            parent_item.addChild(self._make_item("  [Permission Denied]", color=C['red']))
            return
        except Exception as e:
            parent_item.addChild(self._make_item("  [Error: %s]" % e, color=C['red']))
            return
        dirs  = [e for e in entries if e.is_dir()]
        files = [e for e in entries if e.is_file()]
        for entry in dirs:
            child = self._make_item("📁  %s" % entry.name, color=C['orange'],
                                    data={"type": "dir", "path": str(entry)})
            self._add_lazy_dir_child(child, str(entry))
            parent_item.addChild(child)
        for entry in files[:300]:
            icon = self._file_icon(entry.name)
            try:    sz = fmt_size(entry.stat().st_size)
            except: sz = ""
            child = self._make_item("%s  %s  (%s)" % (icon, entry.name, sz),
                                    color=C['fg2'],
                                    data={"type": "file", "path": str(entry)})
            parent_item.addChild(child)
        if not dirs and not files:
            parent_item.addChild(self._make_item("  [Empty]", color=C['fg3']))

    def _populate_image_children(self, parent_item, image_path, parent_inode):
        """Forensic image directory listing via pytsk3."""
        loading = self._make_item("  ⏳ Reading filesystem…", color=C['fg2'])
        parent_item.addChild(loading)
        QApplication.processEvents()
        try:
            import pytsk3
        except ImportError:
            parent_item.removeChild(loading)
            parent_item.addChild(self._make_item(
                "  [pytsk3 not installed]", color=C['red']))
            return
        ifs = ForensicImageFS.get(image_path)
        parent_item.removeChild(loading)
        if ifs.error:
            parent_item.addChild(self._make_item(
                "  [Error: %s]" % ifs.error, color=C['red']))
            return
        if not ifs.fs:
            parent_item.addChild(self._make_item(
                "  [No readable filesystem found]", color=C['orange']))
            return
        entries = ifs.list_dir(inode=parent_inode)
        if not entries:
            parent_item.addChild(self._make_item("  [Empty]", color=C['fg3']))
            return
        dirs  = [e for e in entries if e['is_dir']]
        files = [e for e in entries if not e['is_dir']]
        for e in dirs:
            child = self._make_item("📁  %s" % e['name'], color=C['orange'],
                                    data={"type":       "img_dir",
                                          "image_path": image_path,
                                          "inode":      e['inode'],
                                          "name":       e['name']})
            self._add_image_sentinel(child, image_path, e['inode'])
            parent_item.addChild(child)
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
            parent_item.addChild(child)

    def _on_tree_select(self, item, _prev):
        if not item: return
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data: return
        t = data.get("type")
        if t == "dir":
            self._load_dir(Path(data["path"]))
        elif t == "file":
            p = Path(data["path"])
            self._load_dir(p.parent)
            self.content.load_path(str(p))
        elif t == "image":
            # Top-level image node — show header info + load hex
            p = data.get("path", "")
            if p and os.path.isfile(p):
                self.content.load_path(p)
                self._show_image_info_in_list(p)
        elif t == "img_dir":
            # Navigate image directory into file list
            self._load_image_dir(data["image_path"], data["inode"], data["name"])
        elif t == "img_file":
            # Load file from image into content viewer
            self._load_image_file(data["image_path"], data["inode"], data["name"])

    def _show_image_info_in_list(self, path):
        """Show forensic image header/partition info in the file list pane."""
        self.file_table.setSortingEnabled(False)
        self.file_table.setRowCount(0)
        self.file_table.setColumnCount(2)
        self.file_table.setHorizontalHeaderLabels(["Property", "Value"])
        hdr = self.file_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        info_rows = []
        try:
            sz = os.path.getsize(path)
            with open(path, "rb") as f:
                header = f.read(512)
            info_rows += [
                ("Image File",  path),
                ("Format",      detect_type(path)),
                ("Size",        "%s  (%d bytes)" % (fmt_size(sz), sz)),
                ("Modified",    fmt_ts(os.path.getmtime(path))),
                ("Created",     fmt_ts(os.path.getctime(path))),
            ]
            if header[:3] == b"EVF" or path.lower().endswith(".e01"):
                info_rows.append(("EWF/E01", "Expert Witness Format detected"))
            if len(header) >= 512 and header[510] == 0x55 and header[511] == 0xAA:
                info_rows.append(("MBR", "0x55AA signature — valid MBR"))
                type_names = {0x07:"NTFS",0x0B:"FAT32",0x0C:"FAT32 LBA",
                              0x82:"Linux Swap",0x83:"Linux",0x8E:"LVM",
                              0xEE:"GPT Protective",0xEF:"EFI System"}
                for i in range(4):
                    off = 446 + i * 16
                    pe  = header[off:off+16]
                    if len(pe) == 16 and pe[4] != 0:
                        pt  = pe[4]
                        lba = struct.unpack_from("<I", pe, 8)[0]
                        sec = struct.unpack_from("<I", pe, 12)[0]
                        info_rows.append((
                            "  Partition %d" % (i+1),
                            "0x%02X (%s)  LBA=%d  %s" % (
                                pt, type_names.get(pt,"Unknown"),
                                lba, fmt_size(sec*512))))
            if len(header) >= 8 and header[:8] == b"EFI PART":
                info_rows.append(("GPT", "EFI PART signature — GPT disk"))
            # Show FS type from pytsk3 if parseable
            try:
                ifs = ForensicImageFS.get(path)
                if ifs.fs:
                    info_rows.append(("Filesystem",  ifs.fs_type_str()))
                    info_rows.append(("Partitions",  str(len(ifs.partitions))))
                    for i, p2 in enumerate(ifs.partitions):
                        info_rows.append(("  Part %d" % i,
                            "%s  offset=%d  %s" % (
                                p2['desc'], p2['offset'], fmt_size(p2['size']))))
                    info_rows.append(("Tree", "Expand the node in the tree to browse files"))
                elif ifs.error:
                    info_rows.append(("FS Parse Error", ifs.error))
            except Exception as e:
                info_rows.append(("FS Info", str(e)))
        except Exception as e:
            info_rows.append(("Error", str(e)))

        for prop, val in info_rows:
            r = self.file_table.rowCount()
            self.file_table.insertRow(r)
            pi = QTableWidgetItem(str(prop))
            pi.setForeground(QBrush(QColor(C["fg2"])))
            vi = QTableWidgetItem(str(val))
            vi.setForeground(QBrush(QColor(C["fg"])))
            self.file_table.setItem(r, 0, pi)
            self.file_table.setItem(r, 1, vi)
        self.path_edit.setText("[Image]  %s" % path)
        self.main.set_status("  Image: %s  (%s)" % (
            os.path.basename(path), fmt_size(os.path.getsize(path))))

    def _load_image_dir(self, image_path, inode, name):
        """Show directory contents of an image folder in the file list."""
        self.file_table.setSortingEnabled(False)
        self.file_table.setRowCount(0)
        # Store context so double-click / select knows we're in image mode
        self._img_context = {"image_path": image_path, "inode": inode}
        ifs = ForensicImageFS.get(image_path)
        if not ifs.fs:
            return
        entries = ifs.list_dir(inode=inode)
        cols = ["Name", "Size", "Type", "Modified", "Inode"]
        self.file_table.setColumnCount(len(cols))
        self.file_table.setHorizontalHeaderLabels(cols)
        self.file_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        for c in range(1, len(cols)):
            self.file_table.horizontalHeader().setSectionResizeMode(
                c, QHeaderView.ResizeMode.ResizeToContents)
        for e in entries:
            r = self.file_table.rowCount()
            self.file_table.insertRow(r)
            icon = "📁" if e['is_dir'] else self._file_icon(e['name'])
            name_item = QTableWidgetItem("%s  %s" % (icon, e['name']))
            name_item.setData(Qt.ItemDataRole.UserRole,
                              {"is_img": True, "image_path": image_path,
                               "inode": e['inode'], "is_dir": e['is_dir'],
                               "name": e['name']})
            if e['is_dir']:
                name_item.setForeground(QBrush(QColor(C['orange'])))
            self.file_table.setItem(r, 0, name_item)
            sz_item = QTableWidgetItem(fmt_size(e['size']) if e['size'] else "")
            sz_item.setForeground(QBrush(QColor(C['fg2'])))
            self.file_table.setItem(r, 1, sz_item)
            self.file_table.setItem(r, 2, QTableWidgetItem(e.get('type','')))
            mt_item = QTableWidgetItem(fmt_ts(e['mtime']) if e['mtime'] else "")
            mt_item.setForeground(QBrush(QColor(C['fg2'])))
            self.file_table.setItem(r, 3, mt_item)
            ino_item = QTableWidgetItem(str(e['inode']))
            ino_item.setForeground(QBrush(QColor(C['fg2'])))
            self.file_table.setItem(r, 4, ino_item)
        self.path_edit.setText("[%s]  inode=%s  %s" % (
            os.path.basename(image_path), inode, name))
        self.file_table.setSortingEnabled(True)

    def _load_image_file(self, image_path, inode, name):
        """Load a file from inside the forensic image into the content viewer."""
        ifs = ForensicImageFS.get(image_path)
        if not ifs.fs:
            return
        data = ifs.read_file(inode)
        self.content.load_bytes(data, name)
        self.main.set_status("  Loaded from image: %s  (%s)" % (name, fmt_size(len(data))))

    def _on_file_select(self, selected, _):
        idxs = self.file_table.selectedItems()
        if not idxs: return
        row = self.file_table.currentRow()
        name_item = self.file_table.item(row, 0)
        if not name_item: return
        item_data = name_item.data(Qt.ItemDataRole.UserRole)
        # Image entry
        if isinstance(item_data, dict) and item_data.get("is_img"):
            d = item_data
            if not d["is_dir"]:
                self._load_image_file(d["image_path"], d["inode"], d["name"])
            return
        # Host filesystem entry
        name = item_data if isinstance(item_data, str) else name_item.text()
        path = self.current_dir / name
        if path.is_file():
            self.content.load_path(str(path))

    def _on_file_double(self, index):
        row = index.row()
        name_item = self.file_table.item(row, 0)
        if not name_item: return
        item_data = name_item.data(Qt.ItemDataRole.UserRole)
        # Image entry
        if isinstance(item_data, dict) and item_data.get("is_img"):
            d = item_data
            if d["is_dir"]:
                self._load_image_dir(d["image_path"], d["inode"], d["name"])
            else:
                self._load_image_file(d["image_path"], d["inode"], d["name"])
            return
        # Host filesystem entry
        name = item_data if isinstance(item_data, str) else name_item.text()
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
        name_item = QTableWidgetItem(f"{icon}  {name}")
        name_item.setData(Qt.ItemDataRole.UserRole, name)
        if is_dir:
            name_item.setForeground(QBrush(QColor(C['orange'])))
        self.file_table.setItem(row, 0, name_item)

        if entry and entry.exists():
            try:
                s = entry.stat()

                # Size
                size_item = QTableWidgetItem(
                    fmt_size(s.st_size) if entry.is_file() else "")
                size_item.setData(Qt.ItemDataRole.UserRole,
                                  s.st_size if entry.is_file() else -1)
                size_item.setTextAlignment(
                    Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                size_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 1, size_item)

                # Type
                ftype = "Directory" if entry.is_dir() else detect_type(str(entry))
                t_item = QTableWidgetItem(ftype)
                t_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 2, t_item)

                # Modified
                mod_item = QTableWidgetItem(fmt_ts(s.st_mtime))
                mod_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 3, mod_item)

                # Created
                cre_item = QTableWidgetItem(fmt_ts(s.st_ctime))
                cre_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 4, cre_item)

                # Permissions
                perm_item = QTableWidgetItem(oct(stat.S_IMODE(s.st_mode)))
                perm_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 5, perm_item)

                # Full path
                path_item = QTableWidgetItem(str(entry))
                path_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 6, path_item)

                # Inode
                ino_item = QTableWidgetItem(str(s.st_ino))
                ino_item.setForeground(QBrush(QColor(C['fg2'])))
                self.file_table.setItem(row, 7, ino_item)

                # MD5 / SHA-256 — empty placeholders, filled by Hash DB
                self.file_table.setItem(row, 8, QTableWidgetItem(""))
                self.file_table.setItem(row, 9, QTableWidgetItem(""))

            except Exception:
                pass

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
        item_data = name_item.data(Qt.ItemDataRole.UserRole)
        is_img_entry = isinstance(item_data, dict) and item_data.get("is_img")
        menu = QMenu(self)

        if is_img_entry:
            d = item_data
            if d["is_dir"]:
                menu.addAction("Open Directory",
                    lambda: self._load_image_dir(d["image_path"], d["inode"], d["name"]))
            else:
                menu.addAction("Preview File",
                    lambda: self._load_image_file(d["image_path"], d["inode"], d["name"]))
                menu.addAction("View in Hex", lambda: (
                    self._load_image_file(d["image_path"], d["inode"], d["name"]),
                    self.content._switch_mode("Hex")))
                menu.addSeparator()
                menu.addAction("💾 Save As…",
                    lambda: self._save_image_file_as(d["image_path"], d["inode"], d["name"]))
                menu.addAction("📧 Open in Email Viewer",
                    lambda: self._open_in_email_viewer(d["image_path"], d["inode"], d["name"]))
                bm_sub2 = menu.addMenu("Add to Bookmark…")
                for tag in ["Key Finding","File of Interest","Malware Indicator",
                            "Suspicious","IOC"]:
                    bm_sub2.addAction(tag,
                        lambda _, t=tag, dd=d: self.main._on_bookmark(
                            "Image Browser",
                            {"Name": dd["name"], "Image": dd["image_path"],
                             "Inode": str(dd["inode"]),
                             "Size": fmt_size(dd.get("size",0))}, t))
        else:
            name = item_data if isinstance(item_data, str) else name_item.text()
            path = self.current_dir / name
            menu.addAction("Open / Navigate",
                lambda: self._load_dir(path) if path.is_dir() else self.content.load_path(str(path)))
            menu.addAction("View in Hex", lambda: (
                self.content._switch_mode("Hex"),
                self.content.load_path(str(path)) if path.is_file() else None))
            menu.addAction("View Metadata", lambda: (
                self.content._switch_mode("Metadata"),
                self.content.load_path(str(path)) if path.is_file() else None))
            menu.addSeparator()
            if path.is_file():
                menu.addAction("💾 Save As…", lambda: self._save_host_file_as(path))
                if path.suffix.lower() in (".pst",".ost",".msg",".mbox"):
                    menu.addAction("📧 Open in Email Viewer",
                        lambda: self.main.email_tab.open_file(str(path)))
            menu.addSeparator()
            menu.addAction("Compute Hashes…", lambda: self._hash_file(path))
            menu.addAction("Add to Evidence",
                lambda: self.main._add_evidence_from_path(str(path)))
            menu.addSeparator()
            bm_sub = menu.addMenu("Add to Bookmark…")
            # Pre-compute safe values NOW (not inside lambda) to avoid crash
            try:
                _bm_size = fmt_size(path.stat().st_size) if path.is_file() else ""
            except Exception:
                _bm_size = ""
            _bm_type = detect_type(str(path)) if path.is_file() else "Directory"
            _bm_data = {"File": path.name, "Path": str(path),
                        "Size": _bm_size, "Type": _bm_type}
            for tag in ["Key Finding","File of Interest","Malware Indicator",
                        "Suspicious","IOC","Cleared"]:
                bm_sub.addAction(tag,
                    lambda _, t=tag, d=_bm_data: self.main._on_bookmark(
                        "File Browser", dict(d), t))

        menu.exec(self.file_table.mapToGlobal(pos))

    def _save_host_file_as(self, src_path):
        """Save a host-filesystem file to a user-chosen location."""
        dst, _ = QFileDialog.getSaveFileName(self, "Save File As",
                                              src_path.name)
        if dst:
            try:
                shutil.copy2(str(src_path), dst)
                self.main.set_status(f"  Saved: {dst}")
                QMessageBox.information(self, "Saved", f"File saved to:\n{dst}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", str(e))

    def _save_image_file_as(self, image_path, inode, name):
        """Extract a file from a forensic image and save it locally."""
        dst, _ = QFileDialog.getSaveFileName(self, "Save File As", name)
        if not dst:
            return
        try:
            ifs  = ForensicImageFS.get(image_path)
            data = ifs.read_file(inode, max_bytes=512*1024*1024)
            with open(dst, "wb") as f:
                f.write(data)
            self.main.set_status(f"  Extracted: {name}  →  {dst}")
            QMessageBox.information(self, "Saved",
                f"Extracted {name}\n({fmt_size(len(data))})\nto:\n{dst}")
        except Exception as e:
            QMessageBox.critical(self, "Extract Error", str(e))

    def _open_in_email_viewer(self, image_path, inode, name):
        """Extract file from image and open in Email Viewer tab."""
        try:
            ifs  = ForensicImageFS.get(image_path)
            data = ifs.read_file(inode, max_bytes=512*1024*1024)
            import tempfile
            tmp  = tempfile.NamedTemporaryFile(suffix=os.path.splitext(name)[1],
                                               delete=False)
            tmp.write(data); tmp.close()
            self.main.email_tab.open_file(tmp.name, display_name=name)
            self.main.tabs.setCurrentIndex(5)
        except Exception as e:
            QMessageBox.critical(self, "Email Viewer Error", str(e))

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
    # Emits (artifact_names, target_path, target_type)
    process_requested = pyqtSignal(list, str, str)

    def __init__(self):
        super().__init__()
        self._checks      = {}
        self._evidence    = []   # list of (label, type, path) populated by MainWindow
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12,8,12,8)

        # ── Evidence target selector ─────────────────────────────────
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

        # ── Header + preset buttons ──────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel("SELECT ARTIFACTS TO COLLECT")
        title.setStyleSheet(f"color:{C['accent']};font-size:10pt;font-weight:bold;")
        hdr.addWidget(title)
        hdr.addStretch()

        for label, slot in [("✓ All",           self._sel_all),
                             ("✗ None",          self._sel_none),
                             ("⚡ IR Preset",     self._preset_ir),
                             ("🦠 Malware",       self._preset_malware),
                             ("📁 Image Preset",  self._preset_image),
                             ("📧 Email Preset",  self._preset_email)]:
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

        # ── Scrollable checkbox grid ─────────────────────────────────
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

    # ── Evidence target management ───────────────────────────────────
    def refresh_evidence_list(self, evidence_items=None):
        """Repopulate target combo from evidence items list."""
        current = self.target_combo.currentData()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self.target_combo.addItem("🖥  Local System (live collection)", ("local", None))
        if evidence_items:
            self._evidence = evidence_items
        for ev in self._evidence:
            label = ev.get("label","")
            etype = ev.get("type","")
            path  = ev.get("path","")
            if etype in ("image","disk"):
                self.target_combo.addItem(f"🖴  {label}", ("image", path))
            elif etype == "dir" or (path and os.path.isdir(path)):
                self.target_combo.addItem(f"📁  {label}", ("directory", path))
            elif etype == "file" or (path and os.path.isfile(path)):
                self.target_combo.addItem(f"📄  {label}", ("file", path))
            elif etype == "remote":
                self.target_combo.addItem(f"🌐  {label}", ("remote", path))
        self.target_combo.blockSignals(False)
        # Restore selection if possible
        if current:
            for i in range(self.target_combo.count()):
                if self.target_combo.itemData(i) == current:
                    self.target_combo.setCurrentIndex(i)
                    break

    def _on_target_changed(self, idx):
        data = self.target_combo.itemData(idx)
        if not data:
            return
        ttype, tpath = data
        if ttype == "local":
            self.target_info.setText("  Live collection from the local system")
            # Enable all artifacts
            for cb in self._checks.values(): cb.setEnabled(True)
        elif ttype == "image":
            self.target_info.setText(f"  Forensic image: {tpath}  (non-volatile artifacts only)")
            # Automatically apply image preset
            self._preset_image()
        elif ttype == "directory":
            self.target_info.setText(f"  Directory: {tpath}")
            for cb in self._checks.values(): cb.setEnabled(True)
        elif ttype == "file":
            self.target_info.setText(f"  File: {tpath}")
        elif ttype == "remote":
            self.target_info.setText(
                f"  Remote target: {tpath}  (native agentless triage — "
                f"evidence copied to case folder, then analyzed locally)")
            for cb in self._checks.values(): cb.setEnabled(True)

    # ── Preset selections ────────────────────────────────────────────
    def _sel_all(self):
        for cb in self._checks.values(): cb.setChecked(True)

    def _sel_none(self):
        for cb in self._checks.values(): cb.setChecked(False)

    def _preset_ir(self):
        self._sel_none()
        for a in ["OS Version & Build","Hostname & Domain",
                "Local User Accounts","USB Device History",
                "PST/OST Files (Outlook)","MSG Files (Outlook)","Thunderbird MBOX",
                "Email Accounts Config","Email Attachments","Email Contacts","Email Calendar Items",
                "Browser History","Browser Cookies","Browser Saved Passwords",
                "Browser Extensions","Prefetch Files","LNK / Shortcut Files",
                "Recycle Bin Contents","Registry Run Keys","Startup Folder Items",
                "Scheduled Tasks","Security Event Log","System Event Log",
                "Application Event Log","PowerShell Operational Log","RDP Session Log",
                "Recently Accessed Files","Certificate Store","SAM Database Hash Dump",
                "Installed Software","Shellbags","UserAssist Keys","Jump Lists",
                "WiFi Profiles"]:
            if a in self._checks: self._checks[a].setChecked(True)

    def _preset_email(self):
        """Email-focused artifact collection."""
        self._sel_none()
        for a in ["PST/OST Files (Outlook)","MSG Files (Outlook)","Thunderbird MBOX",
                  "Email Accounts Config","Email Attachments",
                  "Email Contacts","Email Calendar Items","Browser History","Browser Cookies"]:
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

    def _preset_image(self):
        """Non-volatile artifacts suitable for forensic image analysis."""
        self._sel_none()
        for a in ["PST/OST Files (Outlook)","MSG Files (Outlook)","Thunderbird MBOX",
                  "Email Attachments","Email Contacts","Email Calendar Items",
                  "Browser History","Browser Cookies","Browser Saved Passwords",
                  "Browser Extensions","Prefetch Files","LNK / Shortcut Files",
                  "Recycle Bin Contents","Registry Run Keys","Startup Folder Items",
                  "Scheduled Tasks","Security Event Log","System Event Log",
                  "Application Event Log","PowerShell Operational Log",
                  "Recently Accessed Files","Certificate Store","SAM Database Hash Dump",
                  "Installed Software"]:
            if a in self._checks: self._checks[a].setChecked(True)

    def _preset_malware(self):
        self._sel_none()
        for a in ["Running Processes","Active Connections","Registry Run Keys",
                  "Scheduled Tasks","Services (Auto-Start)","Prefetch Files",
                  "Recently Accessed Files","Loaded Drivers/Modules",
                  "WMI Subscriptions","AppInit DLLs"]:
            if a in self._checks: self._checks[a].setChecked(True)



# ══════════════════════════════════════════════════════════════
#  RESULTS TAB
# ══════════════════════════════════════════════════════════════

    # ── Right-click context menu ──────────────────────────────────────────────
    def _show_artifact_context_menu(self, pos):
        """Show right-click context menu on the artifact results table."""
        from PyQt5.QtWidgets import QMenu, QAction, QApplication
        from PyQt5.QtGui import QClipboard

        selected = self.result_table.selectedItems()
        if not selected:
            return

        menu = QMenu(self)

        act_bookmark = QAction("⭐  Add to Bookmarks", self)
        act_bookmark.triggered.connect(self._add_selected_to_bookmarks)
        menu.addAction(act_bookmark)

        menu.addSeparator()

        act_copy_row = QAction("📋  Copy Row(s)", self)
        act_copy_row.triggered.connect(self._copy_selected_rows)
        menu.addAction(act_copy_row)

        act_copy_cell = QAction("📄  Copy Cell Value", self)
        act_copy_cell.triggered.connect(self._copy_cell_value)
        menu.addAction(act_copy_cell)

        menu.exec_(self.result_table.viewport().mapToGlobal(pos))

    def _copy_selected_rows(self):
        """Copy all selected rows as tab-separated text to clipboard."""
        from PyQt5.QtWidgets import QApplication
        tbl = self.result_table
        rows = sorted(set(i.row() for i in tbl.selectedItems()))
        lines = []
        for row in rows:
            cells = []
            for col in range(tbl.columnCount()):
                item = tbl.item(row, col)
                cells.append(item.text() if item else "")
            lines.append("\t".join(cells))
        QApplication.clipboard().setText("\n".join(lines))

    def _copy_cell_value(self):
        """Copy the current cell value to clipboard."""
        from PyQt5.QtWidgets import QApplication
        item = self.result_table.currentItem()
        if item:
            QApplication.clipboard().setText(item.text())

    def _add_selected_to_bookmarks(self):
        """
        Bookmark selected rows from the artifact results table.
        Appends them to the Bookmarks tab (QTableWidget named self.bookmark_table
        or self.bm_table) if it exists, otherwise creates a simple dialog list.
        """
        from PyQt5.QtWidgets import (QTableWidget, QTableWidgetItem,
                                      QMessageBox, QApplication)
        tbl = self.result_table
        rows = sorted(set(i.row() for i in tbl.selectedItems()))
        if not rows:
            return

        # Collect header labels
        headers = []
        for col in range(tbl.columnCount()):
            h = tbl.horizontalHeaderItem(col)
            headers.append(h.text() if h else str(col))

        # Build list of dicts for each selected row
        row_dicts = []
        for row in rows:
            rd = {}
            for col, hdr in enumerate(headers):
                item = tbl.item(row, col)
                rd[hdr] = item.text() if item else ""
            # Prepend artifact name so bookmark has context
            artifact_label = ""
            try:
                artifact_label = self._current_artifact or ""
            except Exception:
                pass
            rd["_Artifact"] = artifact_label
            row_dicts.append(rd)

        # ── Try to find an existing bookmark table in the main window ─────────
        bm_tbl = None
        bm_candidates = ["bookmark_table", "bm_table", "bookmarks_table",
                          "tbl_bookmarks", "tbl_bookmark"]
        # Walk up to MainWindow
        parent = self.parent()
        while parent:
            for cand in bm_candidates:
                if hasattr(parent, cand):
                    bm_tbl = getattr(parent, cand)
                    break
            if bm_tbl:
                break
            parent = parent.parent() if hasattr(parent, "parent") else None

        if bm_tbl and isinstance(bm_tbl, QTableWidget):
            # Append rows to existing bookmark table
            for rd in row_dicts:
                row_pos = bm_tbl.rowCount()
                bm_tbl.insertRow(row_pos)
                # Ensure enough columns
                if bm_tbl.columnCount() == 0:
                    bm_tbl.setColumnCount(len(rd))
                    bm_tbl.setHorizontalHeaderLabels(list(rd.keys()))
                for col, (k, v) in enumerate(rd.items()):
                    if col < bm_tbl.columnCount():
                        bm_tbl.setItem(row_pos, col,
                                       QTableWidgetItem(str(v)))
            QMessageBox.information(
                self, "Bookmarks",
                f"{len(row_dicts)} row(s) added to Bookmarks tab.")
        else:
            # ── Fallback: store in self._bookmarks list and show count ─────────
            if not hasattr(self, "_bookmarks"):
                self._bookmarks = []
            self._bookmarks.extend(row_dicts)
            # Try to find a tab widget and switch to bookmarks tab
            switched = False
            parent = self.parent()
            while parent and not switched:
                from PyQt5.QtWidgets import QTabWidget
                if isinstance(parent, QTabWidget):
                    for i in range(parent.count()):
                        if "bookmark" in parent.tabText(i).lower():
                            parent.setCurrentIndex(i)
                            switched = True
                            break
                parent = parent.parent() if hasattr(parent, "parent") else None

            QMessageBox.information(
                self, "Bookmarks",
                f"{len(row_dicts)} row(s) bookmarked "
                f"(total: {len(self._bookmarks)}).\n\n"
                f"No dedicated Bookmark table found — rows stored internally.\n"
                f"Export via File → Export Bookmarks if supported.")

    # ── End right-click context menu ──────────────────────────────────────────

class ResultsTab(QWidget):
    # Emits (artifact_name, row_dict, tag) when user bookmarks a row
    bookmark_requested = pyqtSignal(str, object, str)


    def _preset_image(self):
        """Non-volatile artifacts suitable for forensic image analysis."""
        self._sel_none()
        for a in ["PST/OST Files (Outlook)","MSG Files (Outlook)","Thunderbird MBOX",
                  "Email Attachments","Email Contacts","Email Calendar Items",
                  "Browser History","Browser Cookies","Browser Saved Passwords",
                  "Browser Extensions","Prefetch Files","LNK / Shortcut Files",
                  "Recycle Bin Contents","Registry Run Keys","Startup Folder Items",
                  "Scheduled Tasks","Security Event Log","System Event Log",
                  "Application Event Log","PowerShell Operational Log",
                  "Recently Accessed Files","Certificate Store","SAM Database Hash Dump",
                  "Installed Software"]:
            if a in self._checks: self._checks[a].setChecked(True)


    def _preset_malware(self):
        self._sel_none()
        for a in ["Running Processes","Active Connections","Registry Run Keys",
                  "Scheduled Tasks","Services (Auto-Start)","Prefetch Files",
                  "Recently Accessed Files","Loaded Drivers/Modules",
                  "WMI Subscriptions","AppInit DLLs"]:
            if a in self._checks: self._checks[a].setChecked(True)


    def __init__(self):
        super().__init__()
        self.results             = {}
        self._current_name       = ""
        self._current_row_data   = {}
        self._preview_mode       = "Summary"
        self._setup()

    def _setup(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        outer_split = QSplitter(Qt.Orientation.Horizontal)
        outer_split.setHandleWidth(2)

        # ── LEFT: artifact list + exports ────────────────────────────
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
        outer_split.addWidget(left)

        # ── RIGHT: header + toolbar + table + preview ─────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0,0,0,0)
        rl.setSpacing(0)

        self.result_header = QLabel("  Select an artifact from the list")
        self.result_header.setObjectName("section_header")
        self.result_header.setStyleSheet(
            f"background:{C['bg3']};color:{C['fg']};font-size:9pt;"
            f"font-weight:bold;padding:5px 10px;")
        rl.addWidget(self.result_header)

        # Filter / search bar
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
        # Preview toggle button
        self._prev_toggle = QPushButton("▼ Preview")
        self._prev_toggle.setCheckable(True)
        self._prev_toggle.setChecked(True)
        self._prev_toggle.setFixedWidth(84)
        self._prev_toggle.setStyleSheet(
            f"QPushButton{{background:{C['btn']};color:{C['fg2']};"
            f"border:1px solid {C['border']};border-radius:3px;padding:2px 6px;font-size:8pt;}}"
            f"QPushButton:checked{{background:{C['sel']};color:{C['accent']};}}")
        self._prev_toggle.toggled.connect(self._toggle_preview)
        sbl.addWidget(self._prev_toggle)
        rl.addWidget(sb)

        # Vertical splitter: table top, preview bottom
        self._v_split = QSplitter(Qt.Orientation.Vertical)
        self._v_split.setHandleWidth(4)

        self.result_table = QTableWidget(0, 1)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.result_table.setSortingEnabled(True)
        self.result_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.result_table.customContextMenuRequested.connect(self._table_ctx)
        self.result_table.currentCellChanged.connect(self._on_cell_changed)
        self._v_split.addWidget(self.result_table)

        # Preview panel widget
        prev_w = QWidget()
        prev_w.setStyleSheet(f"background:{C['bg2']};")
        pvl = QVBoxLayout(prev_w)
        pvl.setContentsMargins(0,0,0,0)
        pvl.setSpacing(0)

        # Preview toolbar
        prev_tb = QWidget()
        prev_tb.setStyleSheet(
            f"background:{C['bg3']};border-top:2px solid {C['border']};")
        ptbl = QHBoxLayout(prev_tb)
        ptbl.setContentsMargins(8,3,8,3)
        ptbl.setSpacing(4)
        self._preview_title = QLabel("ITEM PREVIEW")
        self._preview_title.setStyleSheet(
            f"color:{C['accent']};font-weight:bold;font-size:8pt;")
        ptbl.addWidget(self._preview_title)
        ptbl.addStretch()
        self._preview_mode_btns = {}
        for mode in ("Summary","Raw","Hex","Path"):
            mb = QPushButton(mode)
            mb.setCheckable(True)
            mb.setFixedHeight(22)
            mb.setStyleSheet(
                f"QPushButton{{background:{C['btn']};color:{C['fg2']};"
                f"border:1px solid {C['border']};border-radius:3px;"
                f"padding:1px 10px;font-size:8pt;margin:1px;}}"
                f"QPushButton:checked{{background:{C['sel']};color:{C['accent']};border-color:{C['accent']};}}")
            mb.clicked.connect(lambda _, m=mode: self._set_preview_mode(m))
            ptbl.addWidget(mb)
            self._preview_mode_btns[mode] = mb
        pvl.addWidget(prev_tb)

        # Stacked preview pages
        self._preview_stack = QStackedWidget()
        mono = f"font-family:'Consolas','Cascadia Code','Courier New',monospace;font-size:9pt;"

        self._preview_summary = QTextEdit()
        self._preview_summary.setReadOnly(True)
        self._preview_summary.setStyleSheet(
            f"background:{C['bg2']};color:{C['fg']};{mono}border:none;padding:8px;")
        self._preview_stack.addWidget(self._preview_summary)   # 0

        self._preview_raw = QPlainTextEdit()
        self._preview_raw.setReadOnly(True)
        self._preview_raw.setStyleSheet(
            f"background:{C['bg2']};color:{C['green']};{mono}border:none;padding:8px;")
        self._preview_stack.addWidget(self._preview_raw)       # 1

        self._preview_hex = QPlainTextEdit()
        self._preview_hex.setReadOnly(True)
        self._preview_hex.setStyleSheet(
            f"background:{C['bg2']};color:{C['orange']};{mono}border:none;padding:8px;")
        self._preview_stack.addWidget(self._preview_hex)       # 2

        self._preview_path = QTextEdit()
        self._preview_path.setReadOnly(True)
        self._preview_path.setStyleSheet(
            f"background:{C['bg2']};color:{C['fg']};font-size:9pt;border:none;padding:8px;")
        self._preview_stack.addWidget(self._preview_path)      # 3

        pvl.addWidget(self._preview_stack)
        self._v_split.addWidget(prev_w)
        self._v_split.setSizes([480, 200])
        rl.addWidget(self._v_split, 1)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(6)
        self.progress.setTextVisible(False)
        rl.addWidget(self.progress)

        outer_split.addWidget(right)
        outer_split.setSizes([220, 900])
        lay.addWidget(outer_split)

        # Initialise preview mode
        self._preview_mode_btns["Summary"].setChecked(True)

    # ── Preview toggle ────────────────────────────────────────────────
    def _toggle_preview(self, checked):
        self._v_split.widget(1).setVisible(checked)

    def _set_preview_mode(self, mode):
        self._preview_mode = mode
        for m, btn in self._preview_mode_btns.items():
            btn.setChecked(m == mode)
        self._refresh_preview(self._current_row_data)

    def _table_ctx(self, pos):
        """Right-click context menu on the artifact result table."""
        try:
            from PyQt6.QtWidgets import QMenu, QInputDialog, QApplication
            table = self.result_table
            row   = table.rowAt(pos.y())
            col   = table.columnAt(pos.x())
            if row < 0:
                return

            menu       = QMenu(table)
            act_bm     = menu.addAction("  Add to Bookmarks")
            menu.addSeparator()
            act_row    = menu.addAction("  Copy Row(s)")
            act_cell   = menu.addAction("  Copy Cell Value")
            menu.addSeparator()
            act_all    = menu.addAction("  Copy All Rows (TSV)")

            action = menu.exec(table.viewport().mapToGlobal(pos))

            if action == act_bm:
                self._ctx_add_bookmark(row)
            elif action == act_row:
                self._ctx_copy_rows()
            elif action == act_cell:
                it = table.item(row, col)
                if it:
                    QApplication.clipboard().setText(it.text())
            elif action == act_all:
                self._ctx_copy_all()
        except Exception as e:
            import traceback; traceback.print_exc()

    def _ctx_add_bookmark(self, clicked_row):
        """Emit bookmark_requested for every selected row (or clicked row)."""
        try:
            from PyQt6.QtWidgets import QInputDialog, QApplication
            from PyQt6.QtCore import Qt
            table   = self.result_table
            rows    = sorted(set(i.row() for i in table.selectedItems()))
            if not rows:
                rows = [clicked_row]

            tag, ok = QInputDialog.getText(
                self, "Add to Bookmarks",
                f"Tag / note for {len(rows)} row(s):",
                text=getattr(self, '_current_name', ''))
            if not ok:
                return

            artifact_name = getattr(self, '_current_name', 'Unknown Artifact')
            for r in rows:
                row_data = {}
                for c in range(table.columnCount()):
                    h  = table.horizontalHeaderItem(c)
                    it = table.item(r, c)
                    key = h.text() if h else str(c)
                    row_data[key] = it.text() if it else ''
                try:
                    self.bookmark_requested.emit(artifact_name, row_data, tag or artifact_name)
                except Exception:
                    # Fallback: store locally
                    if not hasattr(self, '_local_bookmarks'):
                        self._local_bookmarks = []
                    self._local_bookmarks.append({'artifact': artifact_name,
                                                  'tag': tag, 'data': row_data})
        except Exception as e:
            import traceback; traceback.print_exc()

    def _ctx_copy_rows(self):
        try:
            from PyQt6.QtWidgets import QApplication
            table = self.result_table
            rows  = sorted(set(i.row() for i in table.selectedItems()))
            if not rows:
                return
            headers = [table.horizontalHeaderItem(c).text()
                       if table.horizontalHeaderItem(c) else str(c)
                       for c in range(table.columnCount())]
            lines = ['\t'.join(headers)]
            for r in rows:
                cells = []
                for c in range(table.columnCount()):
                    it = table.item(r, c)
                    cells.append(it.text() if it else '')
                lines.append('\t'.join(cells))
            QApplication.clipboard().setText('\n'.join(lines))
        except Exception:
            pass

    def _ctx_copy_all(self):
        try:
            from PyQt6.QtWidgets import QApplication
            table = self.result_table
            headers = [table.horizontalHeaderItem(c).text()
                       if table.horizontalHeaderItem(c) else str(c)
                       for c in range(table.columnCount())]
            lines = ['\t'.join(headers)]
            for r in range(table.rowCount()):
                cells = []
                for c in range(table.columnCount()):
                    it = table.item(r, c)
                    cells.append(it.text() if it else '')
                lines.append('\t'.join(cells))
            QApplication.clipboard().setText('\n'.join(lines))
        except Exception:
            pass

    def _on_cell_changed(self, row, col, prow, pcol):
        if row < 0 or row >= self.result_table.rowCount(): return
        n = self.result_table.columnCount()
        hdrs = [self.result_table.horizontalHeaderItem(c).text()
                if self.result_table.horizontalHeaderItem(c) else str(c)
                for c in range(n)]
        rd = {hdrs[c]: (self.result_table.item(row,c).text()
              if self.result_table.item(row,c) else "") for c in range(n)}
        self._current_row_data = rd
        self._refresh_preview(rd)

    def _refresh_preview(self, rd):
        if not rd: return
        mode = self._preview_mode
        idx  = {"Summary":0,"Raw":1,"Hex":2,"Path":3}[mode]
        self._preview_stack.setCurrentIndex(idx)
        art = self._current_name

        if mode == "Summary":
            KEY_C = {
                C['green']:  ("pid","name","user","status","memory","cpu","process","exe"),
                C['orange']: ("local","remote","proto","connection","port","ip"),
                C['accent']: ("file","dir","path","size","modified","accessed","type"),
                C['purple']: ("subject","sender","from","to","date","email"),
                C['red']:    ("error","risk","malware","suspicious","warning"),
            }
            parts = [f"<div style='font-family:Segoe UI,Arial;font-size:9pt;'>",
                     f"<p style='margin:0 0 8px;'><b style='color:{C['accent']}'>"
                     f"{art}</b></p>"]
            for k, v in rd.items():
                kl = k.lower()
                col = C['fg']
                for c, keys in KEY_C.items():
                    if any(x in kl for x in keys): col = c; break
                v2 = str(v)[:300] + ("…" if len(str(v))>300 else "")
                parts.append(
                    f"<div style='margin:2px 0;padding:1px 0;'>"
                    f"<span style='color:{C['fg2']};min-width:120px;"
                    f"display:inline-block;font-size:8pt;'>{k}</span>"
                    f"<span style='color:{col};margin-left:8px;'>{v2}</span></div>")
            parts.append("</div>")
            self._preview_summary.setHtml("".join(parts))

        elif mode == "Raw":
            self._preview_raw.setPlainText(json.dumps(rd, indent=2, default=str))

        elif mode == "Hex":
            p = next((rd[k] for k in ("Path","path","Exe","exe","File","file") if k in rd and rd[k]), "")
            if p and os.path.isfile(p):
                try:
                    with open(p,"rb") as fh: data = fh.read(4096)
                    lines = []
                    for i in range(0,len(data),16):
                        ch = data[i:i+16]
                        h1 = " ".join("%02X"%b for b in ch[:8])
                        h2 = " ".join("%02X"%b for b in ch[8:])
                        ac = "".join(chr(b) if 32<=b<127 else "." for b in ch)
                        lines.append("%08X  %-23s  %-23s  %s"%(i,h1,h2,ac))
                    self._preview_hex.setPlainText("[First 4 KB: %s]\n\n"%p+"\n".join(lines))
                except Exception as e:
                    self._preview_hex.setPlainText("[Read error: %s]"%e)
            else:
                self._preview_hex.setPlainText(
                    "[Hex preview: no accessible file path in this row]\n\n"
                    "Switch to Summary or Raw to view fields.")

        elif mode == "Path":
            p = next((rd[k] for k in ("Path","path","Exe","exe","File","file") if k in rd and rd[k]), "")
            if p and os.path.exists(p):
                try:
                    s = os.stat(p)
                    info = (f"<div style='font-family:Segoe UI;font-size:9pt;'>"
                            f"<p><b style='color:{C['accent']}'>{p}</b></p>"
                            f"<p>Size: {fmt_size(s.st_size)}</p>"
                            f"<p>Modified:  {fmt_ts(s.st_mtime)}</p>"
                            f"<p>Created:   {fmt_ts(s.st_ctime)}</p>"
                            f"<p>Accessed:  {fmt_ts(s.st_atime)}</p>"
                            f"<p>Mode: {oct(s.st_mode)}</p>")
                    if os.path.isfile(p):
                        info += f"<p>Type: {detect_type(p)}</p>"
                        if s.st_size < 32*1024*1024:
                            info += f"<p>MD5: {md5_path(p)}</p>"
                    info += "</div>"
                    self._preview_path.setHtml(info)
                except Exception as e:
                    self._preview_path.setHtml(f"<p style='color:{C['red']}'>{e}</p>")
            else:
                fields = "<br>".join(
                    f"<b>{k}:</b> {v}" for k,v in rd.items()
                    if any(x in k.lower() for x in ("path","file","exe","dir","loc")))
                self._preview_path.setHtml(
                    f"<div style='font-family:Segoe UI;font-size:9pt;color:{C['fg2']};padding:8px;'>"
                    f"<p>No accessible path in this row.</p>{fields}</div>")

    # ── Table right-click ─────────────────────────────────────────────
    def _open_folder(self, p):
        d = os.path.dirname(p) if os.path.isfile(p) else p
        if platform.system()=="Windows": os.startfile(d)
        elif platform.system()=="Darwin": subprocess.Popen(["open",d])
        else: subprocess.Popen(["xdg-open",d])

    def _save_file(self, src):
        dst, _ = QFileDialog.getSaveFileName(self,"Save File As",os.path.basename(src))
        if dst:
            try:
                shutil.copy2(src,dst)
                QMessageBox.information(self,"Saved",f"Saved to:\n{dst}")
            except Exception as e:
                QMessageBox.critical(self,"Error",str(e))

    # ── Data management ───────────────────────────────────────────────
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
        self._preview_summary.setHtml("")
        self._preview_raw.setPlainText("")
        self._preview_hex.setPlainText("")
        self._current_row_data = {}

    def _on_select(self, row):
        if row < 0: return
        name = self.art_list.item(row).text().strip()
        self._show_result(name, self.results.get(name,[]))

    def _show_result(self, name: str, rows: list):
        self._current_name = name
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
                if k not in seen: all_keys.append(k); seen.add(k)
        self.result_table.setColumnCount(len(all_keys))
        self.result_table.setHorizontalHeaderLabels(all_keys)
        hdr = self.result_table.horizontalHeader()
        for i in range(len(all_keys)):
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        if all_keys:
            hdr.setSectionResizeMode(len(all_keys)-1, QHeaderView.ResizeMode.Stretch)
        self.result_table.setRowCount(len(rows))
        for ri, row in enumerate(rows):
            for ci, col in enumerate(all_keys):
                cell = QTableWidgetItem(str(row.get(col,"")))
                cell.setForeground(QBrush(QColor(C['fg'])))
                self.result_table.setItem(ri, ci, cell)
        self.result_table.setSortingEnabled(True)
        self.row_count_label.setText(f"{len(rows)} rows")
        self._filter_rows(self.filter_edit.text())
        if rows:
            self._current_row_data = rows[0]
            self._refresh_preview(rows[0])

    def _filter_rows(self, text):
        text = text.lower()
        for r in range(self.result_table.rowCount()):
            match = not text or any(
                text in (self.result_table.item(r,c).text()
                          if self.result_table.item(r,c) else "").lower()
                for c in range(self.result_table.columnCount()))
            self.result_table.setRowHidden(r, not match)
        vis = sum(1 for r in range(self.result_table.rowCount())
                  if not self.result_table.isRowHidden(r))
        self.row_count_label.setText(f"{vis}/{self.result_table.rowCount()} rows")

    def _current_rows(self):
        nm = self.art_list.currentItem().text().strip() if self.art_list.currentItem() else ""
        return self.results.get(nm,[]), nm

    def _export_csv(self):
        rows, _ = self._current_rows()
        if not rows: return
        p, _ = QFileDialog.getSaveFileName(self,"Export CSV","","CSV (*.csv)")
        if not p: return
        with open(p,"w",newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader(); w.writerows(rows)

    def _export_json(self):
        p, _ = QFileDialog.getSaveFileName(self,"Export JSON","","JSON (*.json)")
        if not p: return
        with open(p,"w") as f: json.dump(self.results, f, indent=2, default=str)

    def _export_html(self):
        p, _ = QFileDialog.getSaveFileName(self,"Export HTML","","HTML (*.html)")
        if not p: return
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        css = ("body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',sans-serif;margin:32px}"
               "h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:8px}"
               "h2{color:#3fb950;margin-top:24px;border-left:4px solid #3fb950;padding-left:10px}"
               "table{border-collapse:collapse;width:100%;margin:8px 0 20px}"
               "th{background:#21262d;color:#8b949e;padding:6px 10px;text-align:left;font-size:.85em}"
               "td{padding:5px 10px;border-bottom:1px solid #21262d;font-size:.9em}"
               "tr:nth-child(even){background:#1a2030}tr:hover td{background:#1f3354}"
               ".badge{background:#1f3354;color:#58a6ff;border-radius:10px;padding:2px 8px;"
               "font-size:.8em;margin-left:8px}")
        html = (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                f"<title>ForensicPro Report</title><style>{css}</style></head><body>"
                f"<h1>ForensicPro Enterprise Report</h1>"
                f"<p style='color:#8b949e;'>Generated: {now} | v{APP_VERSION}</p>")
        for art, rows in self.results.items():
            html += f'<h2>{art} <span class="badge">{len(rows)}</span></h2>'
            if rows:
                cols = list(rows[0].keys())
                html += "<table><tr>"+"".join(f"<th>{c}</th>" for c in cols)+"</tr>"
                for row in rows:
                    html += "<tr>"+"".join(f"<td>{row.get(c,'')}</td>" for c in cols)+"</tr>"
                html += "</table>"
        html += "</body></html>"
        with open(p,"w") as f: f.write(html)
        QMessageBox.information(self,"Exported",f"Report saved:\n{p}")


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
#  REMOTE TRIAGE TAB  (native, agentless)
# ══════════════════════════════════════════════════════════════


class AgentTab(QWidget):
    """Native (agentless) remote triage panel.

    Collection is performed with signed in-box Windows tools only — no SSH,
    paramiko, impacket or smbclient.  Evidence files are copied back to the
    case folder and analysed locally; live data is queried with native tools.
    """
    triage_requested = pyqtSignal(list, str, str)   # names, host, "remote"
    target_added     = pyqtSignal(dict)             # registered target cfg
    _msg             = pyqtSignal(str, str, bool)    # title, text, is_error

    def __init__(self, art_tab):
        super().__init__()
        self.art_tab = art_tab
        self._setup()
        self._msg.connect(self._show_msg)

    def _setup(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setHandleWidth(2)

        cfg_scroll = QScrollArea()
        cfg_scroll.setWidgetResizable(True)
        cfg_scroll.setMinimumWidth(320); cfg_scroll.setMaximumWidth(420)
        cfg_scroll.setStyleSheet(f"QScrollArea{{border:none;background:{C['bg2']}}}")
        cfg = QWidget(); cfg.setStyleSheet(f"background:{C['bg2']};")
        cl = QVBoxLayout(cfg)
        cl.setContentsMargins(12, 12, 12, 12); cl.setSpacing(5)

        def section(title):
            l = QLabel(title)
            l.setStyleSheet(
                f"color:{C['accent']};font-weight:bold;font-size:9pt;"
                f"border-bottom:1px solid {C['border']};padding-bottom:4px;margin-top:10px;")
            cl.addWidget(l)

        def field(label, attr, default="", password=False, placeholder=""):
            cl.addWidget(QLabel(label))
            le = QLineEdit(default)
            if placeholder:
                le.setPlaceholderText(placeholder)
            if password:
                le.setEchoMode(QLineEdit.EchoMode.Password)
            setattr(self, attr, le)
            cl.addWidget(le)

        section("CASE INFORMATION")
        field("Case Name", "f_case_name", "Investigation-001")
        field("Case ID",   "f_case_id",   "FC-2025-001")
        field("Examiner",  "f_examiner",  "")

        section("REMOTE WINDOWS TARGET")
        field("Host (name or IP)", "f_host", "", placeholder="e.g. WKS-1234 or 10.0.0.5")
        field("Username", "f_user", "", placeholder="DOMAIN\\user or user")
        field("Password", "f_pass", "", password=True)

        section("EVIDENCE / CASE FOLDER")
        field("Case Folder (collected evidence)", "f_output_dir", "",
              placeholder="defaults to ~/ForensicPro_Cases/<host>_<ts>")

        section("ARTIFACT PRESET")
        self.f_preset = QComboBox()
        self.f_preset.addItems([
            "Use Current Selection", "Remote Quick-Triage", "Quick Triage",
            "Full Collection", "Incident Response", "Malware Hunt"])
        self.f_preset.setCurrentText("Remote Quick-Triage")
        cl.addWidget(self.f_preset)

        section("ACTIONS")
        for label, method, accent in [
            ("\U0001f680  Remote Quick-Triage (1-click)", self._run_quick_triage, True),
            ("\u2795  Add as Evidence Target",      self._add_target,     False),
            ("\U0001f50c  Test Connection",          self._test_connection, False),
            ("\u26a1  Run Native Triage Now",        self._run_triage,     True),
            ("\U0001f4c1  Open Case Folder",          self._open_case_folder, False),
            ("\U0001f4e5  Import Results\u2026",       self._import_results, False),
        ]:
            btn = QPushButton(label)
            btn.setFixedHeight(32)
            if accent:
                btn.setObjectName("accent")
            btn.clicked.connect(method)
            cl.addWidget(btn)

        cl.addStretch()
        cfg_scroll.setWidget(cfg)
        split.addWidget(cfg_scroll)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(0)
        hdr_w = QWidget()
        hdr_w.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        hdrl = QHBoxLayout(hdr_w)
        hdrl.setContentsMargins(8, 4, 8, 4)
        hdrl.addWidget(QLabel("  REMOTE TRIAGE  —  NATIVE WINDOWS TOOLS (agentless)"))
        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet(f"color:{C['green']};font-size:8pt;")
        hdrl.addWidget(self._status_lbl)
        hdrl.addStretch()
        rl.addWidget(hdr_w)
        self.code_edit = QPlainTextEdit()
        self.code_edit.setReadOnly(True)
        self.code_edit.setStyleSheet(
            f"background:{C['bg']};color:{C['fg2']};"
            f"font-family:'Consolas','Cascadia Code','Courier New',monospace;"
            f"font-size:9pt;border:none;padding:8px;")
        self.code_edit.setPlainText(
            "Native remote triage — no third-party dependencies.\n\n"
            "Transport (signed, in-box Windows binaries only):\n"
            "  net.exe       authenticate to admin share (IPC$/C$)\n"
            "  robocopy.exe  copy evidence files back to the case folder\n"
            "  reg.exe       remote registry query / hive save (\\\\HOST\\HKLM...)\n"
            "  wevtutil.exe  remote event-log queries (/r /u /p)\n"
            "  schtasks.exe  remote scheduled tasks (/s /u /p)\n"
            "  tasklist.exe  remote process list (/s /u /p)\n"
            "  sc.exe        remote services (\\\\HOST query)\n"
            "  query.exe     remote logon sessions (query session /server:)\n"
            "  powershell    Get-CimInstance (DCOM) + Invoke-Command (WinRM)\n\n"
            "Workflow:\n"
            "  1. Fill in host + credentials + (optional) case folder.\n"
            "  2. Add as Evidence Target (or just Run Native Triage Now).\n"
            "  3. Selected artifacts are collected; files land in the case\n"
            "     folder and are analysed locally. Results appear in the\n"
            "     Analysis Results tab.\n")
        rl.addWidget(self.code_edit)
        split.addWidget(right)
        split.setSizes([380, 880])
        lay.addWidget(split)

    # ── helpers ───────────────────────────────────────────────────
    def _log(self, text):
        self.code_edit.appendPlainText(text)

    @pyqtSlot(str, str, bool)
    def _show_msg(self, title, text, is_error):
        if is_error:
            QMessageBox.critical(self, title, text)
        else:
            QMessageBox.information(self, title, text)

    def load_target(self, cfg):
        """Populate the form from a registered remote-target cfg."""
        try:
            self.f_host.setText(cfg.get("host", ""))
            u = cfg.get("user", "")
            if cfg.get("domain"):
                u = cfg["domain"] + "\\" + u
            self.f_user.setText(u)
            self.f_pass.setText(cfg.get("password", ""))
            self.f_output_dir.setText(cfg.get("case_dir", ""))
            self._status_lbl.setText("\u2713 Target loaded: " + cfg.get("host", ""))
        except Exception:
            pass

    def _get_artifacts(self):
        preset = self.f_preset.currentText()
        if preset == "Remote Quick-Triage":
            return list(REMOTE_QUICK_TRIAGE_SET)
        elif preset == "Quick Triage":
            return ["OS Version & Build", "Running Processes",
                    "Active Connections", "Local User Accounts"]
        elif preset == "Full Collection":
            return [a for cat in ARTIFACT_CATEGORIES.values() for a in cat]
        elif preset == "Incident Response":
            return ["Running Processes", "Active Connections", "Network Interfaces",
                    "OS Version & Build", "Hostname & Domain",
                    "Local User Accounts", "Scheduled Tasks", "Services (Auto-Start)",
                    "Registry Run Keys", "Security Event Log", "Prefetch Files"]
        elif preset == "Malware Hunt":
            return ["Running Processes", "Active Connections", "Registry Run Keys",
                    "Scheduled Tasks", "Loaded Drivers/Modules", "Services (Auto-Start)",
                    "WMI Subscriptions", "AppInit DLLs", "Prefetch Files",
                    "Process Creation Events (4688)"]
        else:
            arts = self.art_tab.get_selected()
            return arts or ["OS Version & Build", "Running Processes"]

    def _build_cfg(self):
        host = self.f_host.text().strip()
        if not host:
            self._msg.emit("Remote Target", "Enter a host name or IP.", True)
            return None
        user = self.f_user.text().strip()
        domain = ""
        if "\\" in user:
            domain, user = user.split("\\", 1)
        cfg = register_remote_target(
            host, user=user, password=self.f_pass.text(),
            domain=domain, case_dir=self.f_output_dir.text().strip())
        self.f_output_dir.setText(cfg["case_dir"])
        return cfg

    def _add_target(self):
        cfg = self._build_cfg()
        if not cfg:
            return
        self.target_added.emit(cfg)
        self._status_lbl.setText("\u2713 Target added: " + cfg["host"])
        self._log("[+] Registered remote target %s (case: %s)" %
                  (cfg["host"], cfg["case_dir"]))

    def _test_connection(self):
        cfg = self._build_cfg()
        if not cfg:
            return
        self._log("[*] Testing connection to %s ..." % cfg["host"])

        def run():
            try:
                rc = RemoteCollector(cfg)
                ok, msg = rc.connect()
                rc.disconnect()
                if ok:
                    self._msg.emit("Connection OK",
                                   "Authenticated to \\\\%s admin share.\n%s" %
                                   (cfg["host"], msg), False)
                else:
                    self._msg.emit("Connection Failed",
                                   "Could not connect to \\\\%s.\n%s" %
                                   (cfg["host"], msg), True)
            except Exception as e:
                self._msg.emit("Connection Error", str(e), True)
        threading.Thread(target=run, daemon=True).start()

    def _run_quick_triage(self):
        """One-click curated remote triage with the native collector."""
        cfg = self._build_cfg()
        if not cfg:
            return
        self.f_preset.setCurrentText("Remote Quick-Triage")
        arts = list(REMOTE_QUICK_TRIAGE_SET)
        self.target_added.emit(cfg)
        self._log("[*] Remote Quick-Triage of %s \u2014 %d curated artifact(s) \u2192 %s" %
                  (cfg["host"], len(arts), cfg["case_dir"]))
        self._log("    Set: " + ", ".join(arts))
        self._log("    SAM+SYSTEM hives are copied back and NT/LM hashes auto-extracted.")
        self._status_lbl.setText("\U0001f680 Quick-Triage started (%d artifacts)" % len(arts))
        self.triage_requested.emit(arts, cfg["host"], "remote")

    def _run_triage(self):
        cfg = self._build_cfg()
        if not cfg:
            return
        arts = self._get_artifacts()
        self.target_added.emit(cfg)
        self._log("[*] Starting native triage of %s — %d artifact(s) → %s" %
                  (cfg["host"], len(arts), cfg["case_dir"]))
        self._status_lbl.setText("\u26a1 Triage started (%d artifacts)" % len(arts))
        # Hand off to the main window's collection pipeline (target_type=remote).
        self.triage_requested.emit(arts, cfg["host"], "remote")

    def _open_case_folder(self):
        path = self.f_output_dir.text().strip()
        if not path:
            cfg = self._build_cfg()
            path = cfg["case_dir"] if cfg else ""
        if not path:
            return
        os.makedirs(path, exist_ok=True)
        try:
            if platform.system() == "Windows":
                os.startfile(path)             # noqa
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            self._msg.emit("Open Folder", str(e), True)

    def _import_results(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Triage Results", "", "JSON/ZIP (*.json *.zip);;All (*)")
        if not path:
            return
        try:
            if path.endswith(".zip"):
                with zipfile.ZipFile(path) as z:
                    names = [n for n in z.namelist() if n.endswith(".json")]
                    if not names:
                        raise ValueError("No JSON in archive")
                    data = json.loads(z.read(names[0]))
            else:
                with open(path) as f:
                    data = json.load(f)
            self._log("[+] Imported results from %s" % os.path.basename(path))
            return data
        except Exception as e:
            self._msg.emit("Import Error", str(e), True)
            return None


class EmailViewerTab(QWidget):
    """
    Outlook-style three-pane email viewer:
      Left   : Folder tree
      Middle : Message list (From / Subject / Date / Size)
      Right  : Message content (headers + body)
    Supports PST/OST (pypff), MSG (extract_msg), MBOX (mailbox).
    """
    def __init__(self):
        super().__init__()
        self._pst      = None   # open pypff.file handle
        self._tmp_path = None   # temp file path for extracted images
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        # ── Toolbar ──────────────────────────────────────────────────
        tb = QWidget()
        tb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(8,4,8,4); tbl.setSpacing(6)
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

        # ── Main layout: left folder tree | right vertical split ──────
        main_split = QSplitter(Qt.Orientation.Horizontal)
        main_split.setHandleWidth(2)

        # ── LEFT: folder tree ─────────────────────────────────────────
        folder_w = QWidget()
        folder_w.setMinimumWidth(160)
        folder_w.setMaximumWidth(260)
        folder_w.setStyleSheet(f"background:{C['sidebar']};")
        fl = QVBoxLayout(folder_w)
        fl.setContentsMargins(0,0,0,0); fl.setSpacing(0)
        fh = QLabel("  FOLDERS")
        fh.setObjectName("section_header")
        fl.addWidget(fh)
        self.folder_tree = QTreeWidget()
        self.folder_tree.setHeaderHidden(True)
        self.folder_tree.setStyleSheet(
            f"QTreeWidget{{background:{C['sidebar']};border:none;}}"
            f"QTreeWidget::item{{padding:3px 4px;}}"
            f"QTreeWidget::item:selected{{background:{C['sel']};color:{C['accent']};}}"
            f"QTreeWidget::item:hover{{background:{C['bg3']};}}")
        self.folder_tree.currentItemChanged.connect(self._on_folder_select)
        fl.addWidget(self.folder_tree)
        main_split.addWidget(folder_w)

        # ── RIGHT: vertical splitter (message list top | detail bottom) ──
        right_split = QSplitter(Qt.Orientation.Vertical)
        right_split.setHandleWidth(3)

        # TOP: message list table
        msg_w = QWidget()
        ml = QVBoxLayout(msg_w)
        ml.setContentsMargins(0,0,0,0); ml.setSpacing(0)
        msg_hdr = QLabel("  MESSAGES")
        msg_hdr.setObjectName("section_header")
        ml.addWidget(msg_hdr)
        self.msg_table = QTableWidget(0, 5)
        self.msg_table.setHorizontalHeaderLabels(
            ["From","Subject","Date","Size","Att."])
        self.msg_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        for c in (0, 2, 3, 4):
            self.msg_table.horizontalHeader().setSectionResizeMode(
                c, QHeaderView.ResizeMode.ResizeToContents)
        self.msg_table.verticalHeader().setVisible(False)
        self.msg_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.msg_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.msg_table.setAlternatingRowColors(True)
        self.msg_table.currentCellChanged.connect(self._on_message_select)
        self.msg_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.msg_table.customContextMenuRequested.connect(self._msg_ctx)
        ml.addWidget(self.msg_table)
        right_split.addWidget(msg_w)

        # BOTTOM: message detail (metadata panel top, body bottom)
        detail_w = QWidget()
        dl = QVBoxLayout(detail_w)
        dl.setContentsMargins(0,0,0,0); dl.setSpacing(0)

        # Metadata panel (From/To/Subject/Date)
        meta_hdr = QLabel("  MESSAGE DETAILS")
        meta_hdr.setObjectName("section_header")
        dl.addWidget(meta_hdr)
        self.header_box = QTextEdit()
        self.header_box.setReadOnly(True)
        self.header_box.setFixedHeight(100)
        self.header_box.setStyleSheet(
            f"background:{C['bg2']};color:{C['fg']};font-size:9pt;"
            f"border:none;border-bottom:1px solid {C['border']};padding:6px;")
        dl.addWidget(self.header_box)

        # Body
        body_hdr = QLabel("  MESSAGE BODY")
        body_hdr.setObjectName("section_header")
        dl.addWidget(body_hdr)
        self.body_view = QTextEdit()
        self.body_view.setReadOnly(True)
        self.body_view.setStyleSheet(
            f"background:{C['bg']};color:{C['fg']};"
            f"font-size:9pt;border:none;padding:8px;")
        dl.addWidget(self.body_view, 1)

        # Attachments bar
        self.attach_bar = QWidget()
        self.attach_bar.setStyleSheet(
            f"background:{C['bg2']};border-top:1px solid {C['border']};")
        self.attach_bar.setVisible(False)
        abl = QHBoxLayout(self.attach_bar)
        abl.setContentsMargins(8,4,8,4); abl.setSpacing(6)
        self.attach_label = QLabel("Attachments:")
        self.attach_label.setStyleSheet(f"color:{C['fg2']};font-size:8pt;")
        abl.addWidget(self.attach_label)
        self.attach_scroll = QScrollArea()
        self.attach_scroll.setWidgetResizable(True)
        self.attach_scroll.setFixedHeight(40)
        self.attach_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.attach_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.attach_scroll.setStyleSheet("border:none;background:transparent;")
        self._attach_inner = QWidget()
        self._attach_lay   = QHBoxLayout(self._attach_inner)
        self._attach_lay.setContentsMargins(0,0,0,0)
        self.attach_scroll.setWidget(self._attach_inner)
        abl.addWidget(self.attach_scroll, 1)
        dl.addWidget(self.attach_bar)

        right_split.addWidget(detail_w)
        right_split.setSizes([280, 420])
        main_split.addWidget(right_split)
        main_split.setSizes([210, 900])
        lay.addWidget(main_split)

        # Internal state
        self._messages     = []
        self._all_messages = []
        self._current_msg  = None
        self._folder_map   = {}

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
            QMessageBox.critical(self, "Open Error", str(e))

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
        pst = pypff.file()
        pst.open(path)
        self._pst = pst
        self.folder_tree.clear()
        self._folder_map = {}
        root = pst.get_root_folder()
        self._build_folder_tree(root, None)
        # Select first real folder
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

    def _on_folder_select(self, item, _prev):
        if not item: return
        folder = self._folder_map.get(id(item))
        if not folder: return
        self._load_folder_messages(folder)

    def _load_folder_messages(self, folder):
        self.msg_table.setRowCount(0)
        self._all_messages = []
        try:
            n = folder.get_number_of_sub_messages()
        except Exception:
            n = 0
        for i in range(n):
            try:
                msg   = folder.get_sub_message(i)
                subj  = self._safe_str(msg.get_subject()) or "(no subject)"
                sendr = self._safe_str(msg.get_sender_name()) or ""
                date  = ""
                try:
                    dt = msg.get_delivery_time()
                    if dt: date = str(dt)
                except Exception: pass
                size  = 0
                try: size = msg.get_size()
                except Exception: pass
                n_att = 0
                try: n_att = msg.get_number_of_attachments()
                except Exception: pass
                self._all_messages.append({
                    "index":   i,
                    "msg_obj": msg,
                    "subject": subj,
                    "sender":  sendr,
                    "date":    date,
                    "size":    size,
                    "n_att":   n_att,
                })
            except Exception:
                pass
        self.msg_count_label.setText(f"{len(self._all_messages)} messages")
        self._render_msg_table(self._all_messages)

    def _render_msg_table(self, messages):
        self.msg_table.setSortingEnabled(False)
        self.msg_table.setRowCount(len(messages))
        for r, m in enumerate(messages):
            def _item(text, color=C['fg']):
                it = QTableWidgetItem(str(text))
                it.setForeground(QBrush(QColor(color)))
                return it
            self.msg_table.setItem(r, 0, _item(m["sender"], C['accent']))
            self.msg_table.setItem(r, 1, _item(m["subject"]))
            self.msg_table.setItem(r, 2, _item(m["date"][:19] if m["date"] else "", C['fg2']))
            self.msg_table.setItem(r, 3, _item(fmt_size(m["size"]) if m["size"] else "", C['fg2']))
            att_text = str(m["n_att"]) if m["n_att"] else ""
            att_item = _item(att_text, C['orange'] if m["n_att"] else C['fg2'])
            self.msg_table.setItem(r, 4, att_item)
            # Store index for lookup
            self.msg_table.item(r, 0).setData(Qt.ItemDataRole.UserRole, m["index"])
        self.msg_table.setSortingEnabled(True)
        self._messages = messages

    def _display_message(self, m):
        """Display a pypff message object safely — every call wrapped in try/except."""
        self._current_msg = m
        msg = m.get("msg_obj")
        if not msg: return

        def _s(fn, *args):
            """Call a pypff method safely, return empty string on any error."""
            try:
                v = fn(*args)
                return self._safe_str(v)
            except Exception:
                return ""

        def _esc(s):
            """HTML-escape a string for safe insertion into HTML."""
            return (str(s).replace("&","&amp;").replace("<","&lt;")
                          .replace(">","&gt;").replace('"',"&quot;"))

        # ── Headers ──────────────────────────────────────────────────
        sender_name  = _s(msg.get_sender_name)
        sender_email = ""
        try:   sender_email = _s(msg.get_sender_email_address)
        except Exception: pass  # some pypff builds lack this method

        from_str = _esc(sender_name)
        if sender_email:
            from_str += f" &lt;{_esc(sender_email)}&gt;"

        hdr_lines = [f"<b>From:</b>&nbsp;&nbsp;&nbsp;{from_str}"]

        try:
            to_list = []
            for i in range(msg.get_number_of_recipients()):
                try:
                    r = msg.get_recipient(i)
                    dn = _s(r.get_display_name)
                    em = ""
                    try: em = _s(r.get_email_address)
                    except Exception: pass
                    to_list.append(_esc(dn or em))
                except Exception:
                    pass
            if to_list:
                hdr_lines.append(f"<b>To:</b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{'; '.join(to_list[:5])}")
        except Exception:
            pass

        hdr_lines.append(f"<b>Subject:</b> {_esc(m.get('subject',''))}")
        hdr_lines.append(f"<b>Date:</b>&nbsp;&nbsp;&nbsp;&nbsp;{_esc(str(m.get('date',''))[:24])}")

        self.header_box.setHtml(
            "<div style='font-family:Segoe UI,Arial;font-size:9pt;line-height:1.5;'>"
            + "<br>".join(hdr_lines) + "</div>")

        # ── Body ─────────────────────────────────────────────────────
        displayed = False
        # Try HTML body first
        try:
            html_body = msg.get_html_body()
            if html_body:
                decoded = (html_body.decode(errors='replace')
                           if isinstance(html_body, bytes) else str(html_body))
                if decoded.strip():
                    self.body_view.setHtml(decoded)
                    displayed = True
        except Exception:
            pass

        if not displayed:
            # Try RTF body
            try:
                rtf = msg.get_rtf_body()
                if rtf:
                    decoded = (rtf.decode(errors='replace')
                               if isinstance(rtf, bytes) else str(rtf))
                    # Strip RTF tags crudely for plain display
                    import re as _re
                    text = _re.sub(r'\[a-z]+\d*\s?|[{}]', '', decoded)
                    self.body_view.setPlainText(text[:50000])
                    displayed = True
            except Exception:
                pass

        if not displayed:
            # Plain text body
            try:
                plain = msg.get_plain_text_body()
                if plain:
                    decoded = (plain.decode(errors='replace')
                               if isinstance(plain, bytes) else str(plain))
                    self.body_view.setPlainText(decoded or "(empty body)")
                    displayed = True
            except Exception:
                pass

        if not displayed:
            self.body_view.setPlainText("(Could not decode message body)")

        # ── Attachments ───────────────────────────────────────────────
        n_att = m.get("n_att", 0)
        self.attach_bar.setVisible(n_att > 0)
        while self._attach_lay.count():
            item = self._attach_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if n_att > 0:
            self.attach_label.setText(f"Attachments ({n_att}):")
            for i in range(n_att):
                try:
                    att   = msg.get_attachment(i)
                    aname = _s(att.get_name) or f"attachment_{i}"
                    asize = 0
                    try: asize = att.get_size()
                    except Exception: pass
                    btn = QPushButton(f"📎 {aname}  ({fmt_size(asize)})")
                    btn.setFixedHeight(26)
                    btn.setStyleSheet(
                        f"QPushButton{{background:{C['bg3']};color:{C['fg']};"
                        f"border:1px solid {C['border']};border-radius:3px;"
                        f"padding:2px 8px;font-size:8pt;}}"
                        f"QPushButton:hover{{background:{C['btn_hover']};"
                        f"color:{C['accent']};}}")
                    # Capture att by value at loop time
                    btn.clicked.connect(
                        lambda _chk=False, a=att, n=aname:
                            self._save_attachment(a, n))
                    self._attach_lay.addWidget(btn)
                except Exception:
                    pass
            self._attach_lay.addStretch()

    def _save_attachment(self, att, name):
        dst, _ = QFileDialog.getSaveFileName(self, "Save Attachment", name)
        if not dst: return
        try:
            data = att.read_buffer(att.get_size())
            with open(dst, "wb") as f: f.write(data)
            QMessageBox.information(self, "Saved", f"Attachment saved:\n{dst}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

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
            "msg_obj": None,
            "subject": str(msg.subject or "(no subject)"),
            "sender":  str(msg.sender or ""),
            "date":    str(msg.date or ""),
            "size":    os.path.getsize(path),
            "n_att":   len(msg.attachments),
            "_msg_raw": msg,
            "_path":   path,
        }]
        self._render_msg_table(self._all_messages)
        # Display immediately — keep msg open, store path for re-open on select
        try:
            self._display_msg_raw(msg)
        except Exception as e:
            self.body_view.setPlainText(f"[Preview error: {e}]")
        finally:
            try: msg.close()
            except Exception: pass

    def _display_msg_raw(self, msg):
        """Display an extract_msg message object safely."""
        def _esc(v):
            s = str(v or "")
            return (s.replace("&","&amp;").replace("<","&lt;")
                     .replace(">","&gt;").replace('"',"&quot;"))
        try:
            self.header_box.setHtml(
                "<div style='font-family:Segoe UI,Arial;font-size:9pt;line-height:1.5;'>"
                f"<b>From:</b>&nbsp;&nbsp;&nbsp;{_esc(msg.sender)}<br>"
                f"<b>To:</b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{_esc(msg.to)}<br>"
                f"<b>Subject:</b> {_esc(msg.subject)}<br>"
                f"<b>Date:</b>&nbsp;&nbsp;&nbsp;&nbsp;{_esc(msg.date)}"
                "</div>")
        except Exception as e:
            self.header_box.setPlainText(f"[Header error: {e}]")

        try:
            body = None
            # Prefer HTML body
            try:
                hb = msg.htmlBody
                if hb:
                    body = hb.decode(errors='replace') if isinstance(hb, bytes) else str(hb)
                    self.body_view.setHtml(body)
            except Exception:
                hb = None
            if not hb:
                # Plain text fallback
                pb = msg.body
                if pb:
                    body = pb.decode(errors='replace') if isinstance(pb, bytes) else str(pb)
                self.body_view.setPlainText(body or "(empty body)")
        except Exception as e:
            self.body_view.setPlainText(f"[Body error: {e}]")

        try:
            atts = msg.attachments
            self.attach_bar.setVisible(bool(atts))
            while self._attach_lay.count():
                item = self._attach_lay.takeAt(0)
                if item.widget(): item.widget().deleteLater()
            for att in atts:
                try:
                    aname = att.longFilename or att.shortFilename or "attachment"
                    btn   = QPushButton(f"📎 {aname}")
                    btn.setFixedHeight(26)
                    btn.clicked.connect(
                        lambda _chk=False, a=att, n=aname:
                            self._save_att_raw(a, n))
                    self._attach_lay.addWidget(btn)
                except Exception:
                    pass
            if atts:
                self._attach_lay.addStretch()
        except Exception:
            self.attach_bar.setVisible(False)

    def _display_msg_from_path(self, path):
        """Safely re-open and display a .msg file by path (handle may be closed)."""
        if not path or not os.path.isfile(path):
            self.body_view.setPlainText("(MSG file not found)")
            return
        try:
            import extract_msg
            msg = extract_msg.openMsg(path)
            self._display_msg_raw(msg)
            try: msg.close()
            except Exception: pass
        except Exception as e:
            self.body_view.setPlainText(f"[Cannot re-open MSG: {e}]")

    def _save_att_raw(self, att, name):
        dst, _ = QFileDialog.getSaveFileName(self, "Save Attachment", name)
        if not dst: return
        try:
            with open(dst,"wb") as f: f.write(att.data)
            QMessageBox.information(self,"Saved",f"Saved to:\n{dst}")
        except Exception as e:
            QMessageBox.critical(self,"Error",str(e))

    # ── MBOX loading ─────────────────────────────────────────────────
    def _load_mbox(self, path):
        import mailbox
        try:
            mbox = mailbox.mbox(path)
        except Exception as e:
            QMessageBox.critical(self,"MBOX Error",str(e)); return
        self.folder_tree.clear()
        root_item = QTreeWidgetItem(self.folder_tree, [f"📬  {os.path.basename(path)}"])
        root_item.setForeground(0, QBrush(QColor(C['orange'])))
        self.folder_tree.addTopLevelItem(root_item)
        self._all_messages = []
        for i, msg in enumerate(mbox):
            try:
                n_att = sum(1 for part in msg.walk()
                            if part.get_content_disposition() == 'attachment')
                self._all_messages.append({
                    "index":   i,
                    "msg_obj": None,
                    "_mbox_msg": msg,
                    "subject": str(msg.get("Subject","(no subject)"))[:100],
                    "sender":  str(msg.get("From",""))[:60],
                    "date":    str(msg.get("Date",""))[:30],
                    "size":    len(msg.as_bytes()),
                    "n_att":   n_att,
                })
            except Exception: pass
            if i >= 5000: break
        self.msg_count_label.setText(f"{len(self._all_messages)} messages")
        self._render_msg_table(self._all_messages)

    def _on_message_select(self, row, _col, _pr, _pc):
        if row < 0: return
        try:
            # Use the UserRole index stored in col-0, not the visual row number.
            # Visual row changes when the table is sorted; UserRole stays stable.
            item0 = self.msg_table.item(row, 0)
            if not item0: return
            msg_idx = item0.data(Qt.ItemDataRole.UserRole)
            # Locate the message dict by its stored index
            m = next((x for x in self._all_messages if x.get("index") == msg_idx), None)
            if m is None:
                # Fallback: try direct list lookup
                if row < len(self._messages):
                    m = self._messages[row]
                else:
                    return
            self._current_msg = m
            if "_mbox_msg" in m:
                self._display_mbox_msg(m["_mbox_msg"])
            elif "_msg_raw" in m:
                # Re-open the MSG file safely instead of using closed handle
                self._display_msg_from_path(m.get("_path",""))
            elif m.get("msg_obj"):
                self._display_message(m)
        except Exception as e:
            self.body_view.setPlainText(f"[Display error: {e}]")

    def _display_mbox_msg(self, msg):
        """Display a mailbox.Message (MBOX/EML) safely with HTML escaping."""
        def _hdr(key):
            try:
                v = msg.get(key, "") or ""
                # Decode encoded header (e.g. =?utf-8?b?...?=)
                import email.header as _eh
                parts = _eh.decode_header(str(v))
                decoded = ""
                for part, enc in parts:
                    if isinstance(part, bytes):
                        decoded += part.decode(enc or "utf-8", errors="replace")
                    else:
                        decoded += str(part)
                # HTML-escape for safe rendering
                return (decoded.replace("&","&amp;").replace("<","&lt;")
                                .replace(">","&gt;").replace('"',"&quot;"))
            except Exception:
                return ""

        try:
            self.header_box.setHtml(
                "<div style='font-family:Segoe UI,Arial;font-size:9pt;line-height:1.5;'>"
                f"<b>From:</b>&nbsp;&nbsp;&nbsp;{_hdr('From')}<br>"
                f"<b>To:</b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{_hdr('To')}<br>"
                f"<b>Subject:</b> {_hdr('Subject')}<br>"
                f"<b>Date:</b>&nbsp;&nbsp;&nbsp;&nbsp;{_hdr('Date')}"
                "</div>")
        except Exception as e:
            self.header_box.setPlainText(f"[Header error: {e}]")

        # Walk MIME parts for body and attachments
        body      = ""
        html_body = ""
        attachments = []
        try:
            for part in msg.walk():
                try:
                    ct   = part.get_content_type()
                    disp = part.get_content_disposition() or ""
                    if "attachment" in disp:
                        attachments.append(part)
                        continue
                    if ct == "text/html" and not html_body:
                        raw = part.get_payload(decode=True)
                        if raw:
                            enc = part.get_content_charset() or "utf-8"
                            html_body = raw.decode(enc, errors="replace")
                    elif ct == "text/plain" and not body:
                        raw = part.get_payload(decode=True)
                        if raw:
                            enc = part.get_content_charset() or "utf-8"
                            body = raw.decode(enc, errors="replace")
                except Exception:
                    pass
        except Exception:
            pass

        try:
            if html_body:
                self.body_view.setHtml(html_body)
            else:
                self.body_view.setPlainText(body or "(empty body)")
        except Exception as e:
            self.body_view.setPlainText(f"[Body render error: {e}]")

        # Attachments bar
        self.attach_bar.setVisible(bool(attachments))
        while self._attach_lay.count():
            item = self._attach_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for att in attachments:
            try:
                aname = att.get_filename() or "attachment"
                btn   = QPushButton(f"📎 {aname}")
                btn.setFixedHeight(26)
                btn.clicked.connect(
                    lambda _chk=False, a=att, n=aname:
                        self._save_mbox_att(a, n))
                self._attach_lay.addWidget(btn)
            except Exception:
                pass
        if attachments:
            self._attach_lay.addStretch()

    def _save_mbox_att(self, part, name):
        dst, _ = QFileDialog.getSaveFileName(self,"Save Attachment",name)
        if not dst: return
        try:
            with open(dst,"wb") as f:
                f.write(part.get_payload(decode=True))
            QMessageBox.information(self,"Saved",f"Saved to:\n{dst}")
        except Exception as e:
            QMessageBox.critical(self,"Error",str(e))

    # ── EML loading ──────────────────────────────────────────────────
    def _load_eml(self, path):
        import email
        with open(path,"rb") as f:
            msg = email.message_from_bytes(f.read())
        self.folder_tree.clear()
        root_item = QTreeWidgetItem(self.folder_tree,[f"📧  {os.path.basename(path)}"])
        root_item.setForeground(0, QBrush(QColor(C['orange'])))
        self.folder_tree.addTopLevelItem(root_item)
        n_att = sum(1 for p in msg.walk() if p.get_content_disposition()=="attachment")
        self._all_messages = [{
            "index":0,"msg_obj":None,"_mbox_msg":msg,
            "subject":str(msg.get("Subject",""))[:100],
            "sender": str(msg.get("From",""))[:60],
            "date":   str(msg.get("Date",""))[:30],
            "size":   os.path.getsize(path),
            "n_att":  n_att,
        }]
        self.msg_count_label.setText("1 message")
        self._render_msg_table(self._all_messages)
        self._display_mbox_msg(msg)

    # ── Filter / search ──────────────────────────────────────────────
    def _filter_messages(self, text):
        text = text.lower()
        if not text:
            filtered = self._all_messages
        else:
            filtered = [m for m in self._all_messages
                        if text in m["subject"].lower()
                        or text in m["sender"].lower()
                        or text in m["date"].lower()]
        self._render_msg_table(filtered)
        self.msg_count_label.setText(
            f"{len(filtered)} / {len(self._all_messages)} messages")

    # ── Context menu ─────────────────────────────────────────────────
    def _msg_ctx(self, pos):
        row = self.msg_table.rowAt(pos.y())
        if row < 0: return
        # Get message dict safely via UserRole
        item0 = self.msg_table.item(row, 0)
        msg_idx = item0.data(Qt.ItemDataRole.UserRole) if item0 else None
        m = next((x for x in self._all_messages
                   if x.get("index") == msg_idx), None)
        if m is None and row < len(self._messages):
            m = self._messages[row]

        menu = QMenu(self)
        menu.addAction("📧 Export as .EML…",
            lambda: self._export_as_eml(m))
        menu.addAction("📧 Export as .MSG…",
            lambda: self._export_as_msg(m))
        menu.addAction("💾 Export Message Text…",
            self._export_selected)
        menu.addSeparator()
        menu.addAction("📋 Copy Subject",
            lambda: QApplication.clipboard().setText(
                m["subject"] if m else ""))
        menu.addAction("📋 Copy Sender",
            lambda: QApplication.clipboard().setText(
                m["sender"] if m else ""))
        menu.addAction("📋 Copy All Headers",
            lambda: self._copy_headers(m))
        menu.addSeparator()
        menu.addAction("🔖 Bookmark this Message",
            lambda: self._bookmark_msg(m))
        menu.exec(self.msg_table.mapToGlobal(pos))

    def _export_as_eml(self, m):
        """Export a message as standard .eml (RFC 2822) format."""
        if not m:
            QMessageBox.warning(self,"No Message","Select a message first.")
            return
        subj = m.get("subject","message")[:40].replace("/","_").replace("\\","_")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export as EML", f"{subj}.eml", "EML (*.eml);;All (*)")
        if not path: return
        try:
            import email.mime.multipart, email.mime.text
            msg_obj = m.get("msg_obj")
            mbox_msg = m.get("_mbox_msg")

            if mbox_msg:
                # MBOX/EML — already email.message.Message, just write it
                with open(path,"wb") as f:
                    import email.generator
                    gen = email.generator.BytesGenerator(f)
                    gen.flatten(mbox_msg)
            elif msg_obj:
                # pypff — reconstruct from parts
                eml = email.mime.multipart.MIMEMultipart("mixed")
                eml["From"]    = self._safe_str(msg_obj.get_sender_name())
                eml["Subject"] = self._safe_str(msg_obj.get_subject())
                try:
                    body_bytes = msg_obj.get_plain_text_body()
                    if body_bytes:
                        body_txt = body_bytes.decode(errors="replace") if isinstance(body_bytes,bytes) else str(body_bytes)
                        eml.attach(email.mime.text.MIMEText(body_txt,"plain","utf-8"))
                except Exception: pass
                try:
                    html_bytes = msg_obj.get_html_body()
                    if html_bytes:
                        html_txt = html_bytes.decode(errors="replace") if isinstance(html_bytes,bytes) else str(html_bytes)
                        eml.attach(email.mime.text.MIMEText(html_txt,"html","utf-8"))
                except Exception: pass
                with open(path,"wb") as f:
                    import email.generator
                    gen = email.generator.BytesGenerator(f)
                    gen.flatten(eml)
            else:
                # MSG path
                msg_path = m.get("_path","")
                if msg_path and os.path.isfile(msg_path):
                    import extract_msg
                    msg = extract_msg.openMsg(msg_path)
                    try:
                        eml = email.mime.multipart.MIMEMultipart("mixed")
                        eml["From"]    = str(msg.sender or "")
                        eml["To"]      = str(msg.to or "")
                        eml["Subject"] = str(msg.subject or "")
                        eml["Date"]    = str(msg.date or "")
                        body = msg.body or ""
                        if isinstance(body,bytes): body = body.decode(errors="replace")
                        eml.attach(email.mime.text.MIMEText(body,"plain","utf-8"))
                        if msg.htmlBody:
                            hb = msg.htmlBody
                            if isinstance(hb,bytes): hb = hb.decode(errors="replace")
                            eml.attach(email.mime.text.MIMEText(hb,"html","utf-8"))
                    finally:
                        try: msg.close()
                        except Exception: pass
                    with open(path,"wb") as f:
                        import email.generator
                        gen = email.generator.BytesGenerator(f)
                        gen.flatten(eml)
                else:
                    QMessageBox.warning(self,"Export","Cannot locate source for this message.")
                    return
            QMessageBox.information(self,"Exported",f"Saved EML:\n{path}")
        except Exception as e:
            QMessageBox.critical(self,"Export Error",str(e))

    def _export_as_msg(self, m):
        """Export a message as .msg (Outlook format) if possible."""
        if not m:
            QMessageBox.warning(self,"No Message","Select a message first.")
            return
        # If source is already a .msg file, just copy it
        src_path = m.get("_path","")
        if src_path and os.path.isfile(src_path) and src_path.lower().endswith(".msg"):
            subj = m.get("subject","message")[:40].replace("/","_")
            dst, _ = QFileDialog.getSaveFileName(
                self,"Save MSG",f"{subj}.msg","MSG (*.msg);;All (*)")
            if dst:
                try:
                    shutil.copy2(src_path, dst)
                    QMessageBox.information(self,"Saved",f"Saved MSG:\n{dst}")
                except Exception as e:
                    QMessageBox.critical(self,"Error",str(e))
        else:
            # Fall back to EML export
            QMessageBox.information(self,"Export as MSG",
                "Direct MSG export is only available for .msg source files.\n"
                "Exporting as .EML instead.")
            self._export_as_eml(m)

    def _copy_headers(self, m):
        if not m: return
        lines = [
            f"From:    {m.get('sender','')}",
            f"Subject: {m.get('subject','')}",
            f"Date:    {m.get('date','')}",
        ]
        QApplication.clipboard().setText("\n".join(lines))

    def _bookmark_msg(self, m):
        if not m: return
        try:
            self.parent().parent()._on_bookmark(
                "Email", {"Subject": m.get("subject",""),
                          "From": m.get("sender",""),
                          "Date": m.get("date","")},
                "File of Interest")
        except Exception:
            pass

    # ── Export ───────────────────────────────────────────────────────
    def _export_selected(self):
        rows = self.msg_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self,"Export","Select one or more messages first.")
            return
        dst_dir = QFileDialog.getExistingDirectory(self,"Export Messages To")
        if not dst_dir: return
        exported = 0
        for idx in rows:
            r = idx.row()
            if r >= len(self._messages): continue
            m = self._messages[r]
            fn = os.path.join(dst_dir,
                f"msg_{r:04d}_{m['subject'][:30]}.txt".replace("/","_"))
            try:
                with open(fn,"w",encoding="utf-8") as f:
                    f.write(f"From:    {m['sender']}\n")
                    f.write(f"Subject: {m['subject']}\n")
                    f.write(f"Date:    {m['date']}\n\n")
                    if m.get("msg_obj"):
                        try:
                            body = m["msg_obj"].get_plain_text_body()
                            if body: f.write(body.decode(errors='replace') if isinstance(body,bytes) else str(body))
                        except Exception: pass
                exported += 1
            except Exception:
                pass
        QMessageBox.information(self,"Export",f"Exported {exported} message(s) to:\n{dst_dir}")

    # ── Helpers ──────────────────────────────────────────────────────
    def _safe_str(self, val):
        if val is None: return ""
        if isinstance(val, bytes): return val.decode(errors='replace')
        return str(val)

    def _close_current(self):
        if self._pst:
            try: self._pst.close()
            except Exception: pass
            self._pst = None
        self.folder_tree.clear()
        self.msg_table.setRowCount(0)
        self.header_box.clear()
        self.body_view.clear()
        self.attach_bar.setVisible(False)
        self._messages = []
        self._all_messages = []
        self._folder_map = {}



# ══════════════════════════════════════════════════════════════
#  BOOKMARK TAB
# ══════════════════════════════════════════════════════════════

# Default bookmark categories with icons and colours
BOOKMARK_TABS_DEF = [
    ("⭐ Key Findings",        C['yellow'],  "Top-level findings worth highlighting in the report."),
    ("🔴 Malware Indicators",  C['red'],     "Files, processes or registry keys linked to malware."),
    ("🟡 Suspicious Items",    C['orange'],  "Items that need further investigation."),
    ("📌 IOCs",                C['purple'],  "Indicators of Compromise: hashes, IPs, domains, paths."),
    ("👤 User Activity",       C['green'],   "Logon events, file access, browser history."),
    ("🌐 Network Artifacts",   C['accent'],  "Connections, DNS, cookies, Wi-Fi profiles."),
    ("📁 Files of Interest",   C['fg'],      "Files extracted or flagged during analysis."),
    ("🟢 Cleared",             C['fg2'],     "Items reviewed and considered benign."),
]

# Map tag strings → tab index
TAG_TO_TAB = {
    "Key Finding":       0, "Malware Indicator": 1, "Suspicious":    2,
    "IOC":               3, "User Activity":     4, "Network Activity": 5,
    "File of Interest":  6, "Cleared":           7,
}


class BookmarkTab(QWidget):
    """
    Bookmark manager — sidebar with category list, main table, detail panel.
    Completely avoids QTabWidget (which caused signal-during-sort crashes).
    """
    navigate_to = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._tables     = {}   # cat_idx -> QTableWidget
        self._details    = {}   # cat_idx -> QTextEdit
        self._cur_idx    = 0
        self._setup()

    def _setup(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        lay.setSpacing(0)

        # ── Top toolbar ───────────────────────────────────────────────
        tb = QWidget()
        tb.setStyleSheet(f"background:{C['bg3']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(8,4,8,4); tbl.setSpacing(6)
        title = QLabel("🔖  BOOKMARKS")
        title.setStyleSheet(f"color:{C['accent']};font-weight:bold;font-size:10pt;")
        tbl.addWidget(title)
        tbl.addStretch()
        for label, slot in [("💾 Export All…", self._export_all),
                             ("🗑 Clear Category", self._clear_current),
                             ("🗑 Clear All",      self._clear_all)]:
            btn = QPushButton(label)
            btn.setFixedHeight(26); btn.clicked.connect(slot)
            tbl.addWidget(btn)
        self.bm_count = QLabel("0 bookmarks")
        self.bm_count.setStyleSheet(f"color:{C['fg2']};font-size:9pt;padding:0 8px;")
        tbl.addWidget(self.bm_count)
        lay.addWidget(tb)

        # ── Body: sidebar + stacked content ──────────────────────────
        body_split = QSplitter(Qt.Orientation.Horizontal)
        body_split.setHandleWidth(2)

        # LEFT sidebar — category list
        sidebar = QWidget()
        sidebar.setMinimumWidth(160); sidebar.setMaximumWidth(220)
        sidebar.setStyleSheet(f"background:{C['sidebar']};")
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(0,0,0,0); sl.setSpacing(0)
        sh = QLabel("  CATEGORIES")
        sh.setStyleSheet(f"background:{C['bg3']};color:{C['fg2']};font-size:8pt;"
                         f"font-weight:bold;padding:5px 8px;"
                         f"border-bottom:1px solid {C['border']};")
        sl.addWidget(sh)

        self.cat_list = QListWidget()
        self.cat_list.setStyleSheet(
            f"QListWidget{{background:{C['sidebar']};border:none;outline:none;}}"
            f"QListWidget::item{{padding:8px 12px;color:{C['fg']};font-size:9pt;"
            f"border-bottom:1px solid {C['border']};}}"
            f"QListWidget::item:selected{{background:{C['sel']};color:{C['accent']};"
            f"border-left:3px solid {C['accent']};}}"
            f"QListWidget::item:hover:!selected{{background:{C['bg3']};}}")
        self.cat_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.cat_list.currentRowChanged.connect(self._on_cat_select)

        # Populate sidebar items
        for label, col, desc in BOOKMARK_TABS_DEF:
            item = QListWidgetItem(label)
            item.setForeground(QBrush(QColor(col)))
            item.setToolTip(desc)
            # Count badge — updated dynamically
            item.setData(Qt.ItemDataRole.UserRole, 0)
            self.cat_list.addItem(item)

        sl.addWidget(self.cat_list)
        body_split.addWidget(sidebar)

        # RIGHT: stacked widget (one page per category)
        self._stack = QStackedWidget()

        COLS = ["Artifact", "Tag", "Timestamp", "Summary", "Notes"]
        for idx, (tab_label, col, desc) in enumerate(BOOKMARK_TABS_DEF):
            page = QWidget()
            page.setStyleSheet(f"background:{C['bg']};")
            pl = QVBoxLayout(page)
            pl.setContentsMargins(0,0,0,0); pl.setSpacing(0)

            desc_bar = QLabel(f"  {desc}")
            desc_bar.setStyleSheet(
                f"background:{C['bg2']};color:{C['fg2']};font-size:8pt;"
                f"padding:4px 8px;border-bottom:1px solid {C['border']};")
            pl.addWidget(desc_bar)

            vs = QSplitter(Qt.Orientation.Vertical)
            vs.setHandleWidth(3)

            tbl_w = QTableWidget(0, len(COLS))
            tbl_w.setHorizontalHeaderLabels(COLS)
            tbl_w.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            tbl_w.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
            for ci in (0, 1, 2):
                tbl_w.horizontalHeader().setSectionResizeMode(
                    ci, QHeaderView.ResizeMode.ResizeToContents)
            tbl_w.verticalHeader().setVisible(False)
            tbl_w.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            tbl_w.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked)
            tbl_w.setAlternatingRowColors(True)
            tbl_w.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            tbl_w.customContextMenuRequested.connect(
                lambda pos, t=tbl_w, i=idx: self._bm_ctx(pos, t, i))
            # Store detail ref on table; connect selection AFTER setup
            vs.addWidget(tbl_w)
            self._tables[idx] = tbl_w

            detail_w = QWidget()
            detail_w.setStyleSheet(f"background:{C['bg2']};")
            dl = QVBoxLayout(detail_w)
            dl.setContentsMargins(0,0,0,0); dl.setSpacing(0)
            dh = QLabel("  ITEM DETAIL")
            dh.setStyleSheet(
                f"background:{C['bg3']};color:{C['fg2']};font-size:8pt;"
                f"font-weight:bold;padding:3px 8px;"
                f"border-top:1px solid {C['border']};")
            dl.addWidget(dh)
            det = QTextEdit()
            det.setReadOnly(True)
            det.setStyleSheet(
                f"background:{C['bg2']};color:{C['fg']};"
                f"font-family:'Consolas','Courier New',monospace;"
                f"font-size:9pt;border:none;padding:6px;")
            dl.addWidget(det)
            self._details[idx] = det
            tbl_w._detail_ref  = det
            vs.addWidget(detail_w)
            vs.setSizes([300, 160])
            pl.addWidget(vs)
            self._stack.addWidget(page)

            # Use clicked instead of itemSelectionChanged to avoid
            # firing during programmatic operations (sort, blockSignals, etc.)
            tbl_w.clicked.connect(
                lambda idx_model, t=tbl_w, i=idx:
                    self._on_row_select(t, i))

        body_split.addWidget(self._stack)
        body_split.setSizes([190, 900])
        lay.addWidget(body_split)

        # Select first category
        self.cat_list.setCurrentRow(0)

    def _on_cat_select(self, idx):
        if idx < 0: return
        self._cur_idx = idx
        self._stack.setCurrentIndex(idx)
        self._update_count()

    def _on_row_select(self, tbl, idx):
        try:
            rows = tbl.selectedItems()
            if not rows: return
            row = tbl.currentRow()
            if row < 0 or row >= tbl.rowCount(): return
            art_item = tbl.item(row, 0)
            if not art_item: return
            rd = art_item.data(Qt.ItemDataRole.UserRole) or {}
            tag_item = tbl.item(row, 1)
            ts_item  = tbl.item(row, 2)
            det      = self._details.get(idx)
            if not det: return

            def _e(s):
                return (str(s).replace("&","&amp;")
                               .replace("<","&lt;").replace(">","&gt;"))

            html  = ["<div style='font-family:Segoe UI,Arial;font-size:9pt;'>"]
            html.append(
                f"<p><b style='color:{C['accent']}'>{_e(art_item.text())}</b>"
                f"&nbsp;<span style='color:{C['orange']}'>"
                f"{_e(tag_item.text() if tag_item else '')}</span>"
                f"&nbsp;&nbsp;<span style='color:{C['fg2']};font-size:8pt;'>"
                f"{_e(ts_item.text() if ts_item else '')}</span></p>"
                f"<hr style='border-color:{C['border']};margin:4px 0;'>")
            for k, v in rd.items():
                html.append(
                    f"<div style='margin:2px 0;'>"
                    f"<span style='color:{C['fg2']};min-width:130px;"
                    f"display:inline-block;font-size:8pt;'>{_e(k)}:</span>"
                    f"<span style='color:{C['fg']};'>&nbsp;{_e(str(v)[:500])}"
                    f"</span></div>")
            html.append("</div>")
            det.setHtml("".join(html))
        except Exception as e:
            try:
                det = self._details.get(idx)
                if det: det.setPlainText(f"[Error: {e}]")
            except Exception:
                pass

    # ── Add bookmark ──────────────────────────────────────────────────
    def add_bookmark(self, artifact_name: str, row_data: dict, tag: str):
        try:
            cat_idx = TAG_TO_TAB.get(tag, 0)
            cat_idx = min(cat_idx, len(BOOKMARK_TABS_DEF) - 1)
            tbl     = self._tables.get(cat_idx)
            if tbl is None:
                return

            summary  = "  |  ".join(
                f"{k}: {str(v)[:40]}" for k, v in list(row_data.items())[:4])
            ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            tag_col  = (C['red']    if 'Malware'   in tag else
                        C['orange'] if 'Suspicious' in tag else
                        C['yellow'] if 'Key'        in tag else
                        C['purple'] if 'IOC'        in tag else
                        C['green']  if ('User' in tag or 'Cleared' in tag) else
                        C['accent'])

            # Disable ALL signals + sorting for the ENTIRE insert sequence
            tbl.blockSignals(True)
            tbl.setSortingEnabled(False)

            new_row = tbl.rowCount()
            tbl.insertRow(new_row)

            cells = [
                (str(artifact_name), C['accent'], False, dict(row_data)),
                (str(tag),           tag_col,     False, None),
                (str(ts),            C['fg2'],    False, None),
                (str(summary),       C['fg'],     False, None),
                ("",                 C['fg'],     True,  None),
            ]
            for ci, (val, color, editable, udata) in enumerate(cells):
                cell = QTableWidgetItem(val)
                cell.setForeground(QBrush(QColor(color)))
                flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
                if editable:
                    flags |= Qt.ItemFlag.ItemIsEditable
                    cell.setToolTip("Double-click to add notes")
                cell.setFlags(flags)
                if udata is not None:
                    cell.setData(Qt.ItemDataRole.UserRole, udata)
                tbl.setItem(new_row, ci, cell)

            # Re-enable signals ONLY — never re-enable sorting on bookmark tables.
            # setSortingEnabled(True) triggers an immediate synchronous re-sort
            # which fires itemSelectionChanged before blockSignals(False) runs,
            # causing a crash. Bookmark tables are append-only audit logs;
            # sorting is not needed.
            tbl.blockSignals(False)

            # Defer sidebar/stack UI updates to the next event loop tick so no
            # signal can fire while we are still inside this call frame.
            _ts      = ts
            _cat_idx = cat_idx
            _tbl     = tbl

            def _post_insert():
                try:
                    self._update_count()
                    self.cat_list.blockSignals(True)
                    self.cat_list.setCurrentRow(_cat_idx)
                    self.cat_list.blockSignals(False)
                    self._stack.blockSignals(True)
                    self._stack.setCurrentIndex(_cat_idx)
                    self._stack.blockSignals(False)
                    self._cur_idx = _cat_idx
                    # Scroll to the new row (last row, since no sorting)
                    last = _tbl.rowCount() - 1
                    if last >= 0:
                        item = _tbl.item(last, 0)
                        if item:
                            _tbl.scrollToItem(
                                item, QAbstractItemView.ScrollHint.EnsureVisible)
                except Exception as ex:
                    print(f"[_post_insert] {ex}")

            QTimer.singleShot(0, _post_insert)

        except Exception as e:
            import traceback
            print(f"[BookmarkTab.add_bookmark] {e}\n{traceback.format_exc()}")

    def _current_table(self):
        return self._tables.get(self._cur_idx)

    def _safe_remove(self, tbl, row):
        """Remove a bookmark row without triggering sort-related crashes."""
        try:
            tbl.blockSignals(True)
            tbl.removeRow(row)
            tbl.blockSignals(False)
            self._update_count()
        except Exception as e:
            try: tbl.blockSignals(False)
            except Exception: pass
            print(f"[_safe_remove] {e}")

    def _update_count(self):
        total = sum(t.rowCount() for t in self._tables.values())
        cur   = (self._tables[self._cur_idx].rowCount()
                 if self._cur_idx in self._tables else 0)
        self.bm_count.setText(f"{total} total  |  {cur} in category")
        # Update sidebar badges
        for i in range(self.cat_list.count()):
            n    = self._tables.get(i, {})
            cnt  = n.rowCount() if hasattr(n, 'rowCount') else 0
            base = BOOKMARK_TABS_DEF[i][0] if i < len(BOOKMARK_TABS_DEF) else ""
            item = self.cat_list.item(i)
            if item:
                item.setText(f"{base}  ({cnt})" if cnt else base)

    def _bm_ctx(self, pos, tbl, idx):
        row = tbl.rowAt(pos.y())
        if row < 0: return
        item0 = tbl.item(row, 0)
        rd    = item0.data(Qt.ItemDataRole.UserRole) if item0 else {}
        art   = item0.text() if item0 else ""
        menu  = QMenu(self)
        menu.addAction("🔍 Go to Artifact in Results",
            lambda: self.navigate_to.emit(art))
        menu.addAction("📋 Copy Summary",
            lambda: QApplication.clipboard().setText(
                tbl.item(row,3).text() if tbl.item(row,3) else ""))
        menu.addAction("📋 Copy as JSON",
            lambda: QApplication.clipboard().setText(
                json.dumps(rd, default=str)))
        menu.addSeparator()
        move_m = menu.addMenu("Move to Category…")
        for i, (lbl, _, _d) in enumerate(BOOKMARK_TABS_DEF):
            if i != idx:
                move_m.addAction(lbl,
                    lambda _, ti=i, r=row, t=tbl: self._move_row(t, r, ti))
        menu.addSeparator()
        menu.addAction("🗑 Remove", lambda: self._safe_remove(tbl, row))
        menu.exec(tbl.mapToGlobal(pos))

    def _move_row(self, src_tbl, row, dest_idx):
        item0 = src_tbl.item(row, 0)
        if not item0: return
        rd  = item0.data(Qt.ItemDataRole.UserRole) or {}
        art = item0.text()
        tag = BOOKMARK_TABS_DEF[dest_idx][0].split()[-1]
        src_tbl.removeRow(row)
        self.add_bookmark(art, rd, tag)

    def _clear_current(self):
        tbl = self._current_table()
        if not tbl or tbl.rowCount() == 0: return
        if QMessageBox.question(
                self, "Clear Category",
                f"Remove all {tbl.rowCount()} bookmark(s) from this category?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            tbl.setRowCount(0)
            self._update_count()

    def _clear_all(self):
        total = sum(t.rowCount() for t in self._tables.values())
        if total == 0: return
        if QMessageBox.question(
                self, "Clear All",
                f"Remove all {total} bookmarks?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            for t in self._tables.values(): t.setRowCount(0)
            self._update_count()

    def _export_all(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Bookmarks", "bookmarks",
            "JSON (*.json);;CSV (*.csv);;HTML (*.html)")
        if not path: return
        all_bm = []
        for ti, (tab_label, _, _d) in enumerate(BOOKMARK_TABS_DEF):
            tbl = self._tables.get(ti)
            if not tbl: continue
            for r in range(tbl.rowCount()):
                item0 = tbl.item(r, 0)
                rd    = item0.data(Qt.ItemDataRole.UserRole) if item0 else {}
                all_bm.append({
                    "category":  tab_label,
                    "artifact":  item0.text() if item0 else "",
                    "tag":       tbl.item(r,1).text() if tbl.item(r,1) else "",
                    "timestamp": tbl.item(r,2).text() if tbl.item(r,2) else "",
                    "notes":     tbl.item(r,4).text() if tbl.item(r,4) else "",
                    "data":      rd,
                })
        if path.endswith(".json"):
            with open(path,"w") as f: json.dump(all_bm, f, indent=2, default=str)
        elif path.endswith(".csv"):
            import csv as _csv
            with open(path,"w",newline="") as f:
                w = _csv.writer(f)
                w.writerow(["Category","Artifact","Tag","Timestamp","Notes","Summary"])
                for bm in all_bm:
                    summary = " | ".join(
                        f"{k}: {v}" for k,v in list(bm["data"].items())[:4])
                    w.writerow([bm["category"],bm["artifact"],bm["tag"],
                                bm["timestamp"],bm["notes"],summary])
        else:
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rows_html = ""
            for bm in all_bm:
                summary = " | ".join(f"{k}: {v}" for k,v in list(bm["data"].items())[:4])
                rows_html += (f"<tr><td>{bm['category']}</td>"
                              f"<td>{bm['artifact']}</td>"
                              f"<td>{bm['tag']}</td>"
                              f"<td>{bm['timestamp']}</td>"
                              f"<td>{summary}</td>"
                              f"<td>{bm['notes']}</td></tr>")
            html = (f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    f"<title>Bookmarks</title><style>"
                    f"body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',sans-serif;margin:32px}}"
                    f"h1{{color:#58a6ff}}table{{border-collapse:collapse;width:100%}}"
                    f"th{{background:#21262d;color:#8b949e;padding:6px 10px;text-align:left}}"
                    f"td{{padding:5px 10px;border-bottom:1px solid #21262d}}"
                    f"tr:nth-child(even){{background:#1a2030}}</style></head><body>"
                    f"<h1>ForensicPro Bookmarks — {now}</h1>"
                    f"<table><tr><th>Category</th><th>Artifact</th><th>Tag</th>"
                    f"<th>Timestamp</th><th>Summary</th><th>Notes</th></tr>"
                    f"{rows_html}</table></body></html>")
            with open(path,"w") as f: f.write(html)
        QMessageBox.information(self,"Exported",
            f"Exported {len(all_bm)} bookmark(s) to:\n{path}")


# ══════════════════════════════════════════════════════════════
#  CASE DIALOG
# ══════════════════════════════════════════════════════════════

class CaseDialog(QDialog):
    """Create / edit case metadata (File ▸ New Case)."""

    def __init__(self, parent=None, case_info=None):
        super().__init__(parent)
        self.setWindowTitle("New Case")
        self.setMinimumWidth(460)
        try:
            self.setStyleSheet(STYLESHEET)
        except Exception:
            pass

        ci = case_info or {}
        lay = QFormLayout(self)

        self.f_name = QLineEdit(ci.get("name", "New Case"))
        self.f_name.setPlaceholderText("Case name / title")

        # Default a fresh, unique-ish case number based on the year.
        default_num = ci.get("number") or f"FC-{datetime.datetime.now():%Y}-001"
        self.f_number = QLineEdit(default_num)
        self.f_number.setPlaceholderText("FC-2025-001")

        self.f_examiner = QLineEdit(ci.get("examiner", ""))
        self.f_examiner.setPlaceholderText("Examiner name")

        self.f_notes = QPlainTextEdit(ci.get("notes", ""))
        self.f_notes.setPlaceholderText("Case notes / description (optional)")
        self.f_notes.setFixedHeight(110)

        lay.addRow("Case Name:", self.f_name)
        lay.addRow("Case Number:", self.f_number)
        lay.addRow("Examiner:", self.f_examiner)
        lay.addRow("Notes:", self.f_notes)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._on_accept)
        btns.rejected.connect(self.reject)
        lay.addRow(btns)

    def _on_accept(self):
        if not self.f_name.text().strip():
            QMessageBox.warning(self, "New Case", "Please enter a case name.")
            return
        self.accept()

    def values(self):
        return {
            "name":     self.f_name.text().strip() or "New Case",
            "number":   self.f_number.text().strip(),
            "examiner": self.f_examiner.text().strip(),
            "notes":    self.f_notes.toPlainText().strip(),
        }


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
            ("Add Remote Target…",        self._ssh_connect),
            ("Remote Triage (Native)…",   lambda: self.tabs.setCurrentIndex(4)),
        ])
        menu("&View", [
            ("Evidence Browser",  lambda: self.tabs.setCurrentIndex(0)),
            ("Artifact Selection",lambda: self.tabs.setCurrentIndex(1)),
            ("Analysis Results",  lambda: self.tabs.setCurrentIndex(2)),
            ("Timeline",          lambda: self.tabs.setCurrentIndex(3)),
            ("Remote Triage",     lambda: self.tabs.setCurrentIndex(4)),
            ("Email Viewer",      lambda: self.tabs.setCurrentIndex(5)),
            ("Bookmarks",         lambda: self.tabs.setCurrentIndex(6)),
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
        tbtn("⚡ Remote Triage",   lambda: self.tabs.setCurrentIndex(4))
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
        self.tabs.addTab(self.results_tab, "📋  Analysis Results")

        # Tab 3: Timeline
        self.timeline_tab = TimelineTab()
        self.tabs.addTab(self.timeline_tab, "📅  Timeline")

        # Tab 4: Remote Triage (native, agentless)
        self.agent_tab = AgentTab(self.art_tab)
        self.agent_tab.triage_requested.connect(self._run_collection)
        self.agent_tab.target_added.connect(self._on_remote_target_added)
        self.tabs.addTab(self.agent_tab, "⚡  Remote Triage")

        # Tab 5: Email Viewer
        self.email_tab = EmailViewerTab()
        self.tabs.addTab(self.email_tab, "📧  Email Viewer")

        # Tab 6: Bookmarks
        self.bookmark_tab = BookmarkTab()
        self.bookmark_tab.navigate_to.connect(self._navigate_to_artifact)
        self.tabs.addTab(self.bookmark_tab, "🔖  Bookmarks")

        # Wire results tab bookmark signal → bookmark tab
        self.results_tab.bookmark_requested.connect(self._on_bookmark)

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
        self._sync_evidence_cache()

    def _add_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Add Forensic Image", "",
            "Forensic Images (*.e01 *.dd *.img *.raw *.vmdk *.vhd *.iso *.001);;"
            "All (*)")
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
        self._sync_evidence_cache()

    def _sync_evidence_cache(self):
        """Rebuild the evidence items cache from the tree for ArtifactTab."""
        items = []
        # Images
        ir = self.browser.img_root
        for i in range(ir.childCount()):
            child = ir.child(i)
            d = child.data(0, Qt.ItemDataRole.UserRole) or {}
            if d.get("path"):
                items.append({"label": child.text(0).strip(),
                               "type":  d.get("type","image"),
                               "path":  d["path"]})
        # Local filesystem roots
        lr = self.browser.ev_tree.topLevelItem(0)  # "File System"
        if lr:
            for i in range(lr.childCount()):
                child = lr.child(i)
                d = child.data(0, Qt.ItemDataRole.UserRole) or {}
                if d.get("path"):
                    items.append({"label": child.text(0).strip(),
                                   "type":  d.get("type","dir"),
                                   "path":  d["path"]})
        # Remote targets
        rr = self.browser.remote_root
        for i in range(rr.childCount()):
            child = rr.child(i)
            d = child.data(0, Qt.ItemDataRole.UserRole) or {}
            items.append({"label": child.text(0).strip(),
                           "type":  "remote",
                           "path":  d.get("label","")})
        self._evidence_items_cache = items
        self.art_tab.refresh_evidence_list(items)

    def _on_remote_target_added(self, cfg):
        """Add a remote target (from the Remote Triage tab) to the evidence tree."""
        try:
            self.browser.add_remote_target(cfg.get("host", ""))
            self._sync_evidence_cache()
            self.set_status("Remote target ready: %s" % cfg.get("host", ""))
        except Exception:
            pass

    def _refresh_view(self):
        self.browser._load_dir(self.browser.current_dir)

    # ── Artifact collection ───────────────────
    def _process_artifacts(self):
        self.tabs.setCurrentIndex(1)
        self.art_tab._emit_process()

    def _run_collection(self, names: list, target_path: str = "", target_type: str = "local"):
        self.tabs.setCurrentIndex(2)
        self.results_tab.clear_all()
        self.progress_bar.setValue(0)
        tp = target_path or ""
        tt = target_type or "local"
        label = tp if tp else "Local System"
        self.set_status(f"Collecting {len(names)} artifact(s) from: {label}")

        self._worker = ArtifactWorker(names,
                                      target_path=tp or None,
                                      target_type=tt)
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
        # Feed any email results to the email viewer
        email_keys = [k for k in self.artifact_results
                      if any(x in k for x in ("PST","MSG","MBOX","Email","Thunderbird"))]
        for k in email_keys:
            self.email_tab.load_results(k, self.artifact_results[k])

    def _on_tab_changed(self, idx):
        """Refresh evidence list in ArtifactTab when switching to it."""
        if idx == 1:  # Artifact Selection tab
            items = getattr(self, '_evidence_items_cache', [])
            self.art_tab.refresh_evidence_list(items)

    def _on_bookmark(self, artifact_name: str, row_data: dict, tag: str):
        """Receive bookmark signal from ResultsTab and add to BookmarkTab."""
        try:
            self.bookmark_tab.add_bookmark(artifact_name, row_data, tag)
            # Brief flash on the bookmark tab label
            self.tabs.setTabText(6, "🔖  Bookmarks ✦")
            QTimer.singleShot(1500, lambda: self.tabs.setTabText(6, "🔖  Bookmarks"))
            self.set_status(f"  Bookmarked: {tag}  ←  {artifact_name}")
        except Exception as e:
            import traceback
            print(f"[_on_bookmark] {e}\n{traceback.format_exc()}")

    def _navigate_to_artifact(self, artifact_name: str):
        """Jump to Results tab and highlight the given artifact."""
        self.tabs.setCurrentIndex(2)   # Results tab
        art_list = self.results_tab.art_list
        for i in range(art_list.count()):
            if art_list.item(i).text().strip() == artifact_name:
                art_list.setCurrentRow(i)
                break
        self.set_status(f"  Navigated to: {artifact_name}")

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
        """Open the Hash Database / Calculator dialog."""
        self._open_hash_db()

    def _open_hash_db(self):
        """Hash Database — compute and store MD5/SHA-256 for files in the browser list."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Hash Database & Calculator")
        dlg.resize(900, 600)
        dlg.setStyleSheet(STYLESHEET)
        lay = QVBoxLayout(dlg)

        # ── Top bar ─────────────────────────────────────────────
        tb = QWidget()
        tbl = QHBoxLayout(tb)
        tbl.setContentsMargins(6,4,6,4); tbl.setSpacing(6)

        calc_btn   = QPushButton("⚡ Calculate Hashes for Listed Files")
        calc_btn.setObjectName("accent")
        import_btn = QPushButton("📂 Import Hash DB (CSV/JSON)…")
        export_btn = QPushButton("💾 Export Hash DB…")
        clear_btn  = QPushButton("🗑 Clear DB")
        verify_btn = QPushButton("✓ Verify Selected File…")

        for btn in (calc_btn, import_btn, export_btn, clear_btn, verify_btn):
            btn.setFixedHeight(28)
            tbl.addWidget(btn)
        tbl.addStretch()

        self._hash_progress = QProgressBar()
        self._hash_progress.setFixedWidth(200)
        self._hash_progress.setFixedHeight(18)
        self._hash_progress.setTextVisible(True)
        self._hash_progress.setValue(0)
        tbl.addWidget(self._hash_progress)
        lay.addWidget(tb)

        # ── Search bar ───────────────────────────────────────────
        sb = QWidget()
        sbl = QHBoxLayout(sb)
        sbl.setContentsMargins(6,2,6,2)
        sbl.addWidget(QLabel("Filter:"))
        hash_filter = QLineEdit()
        hash_filter.setPlaceholderText("Filter by filename, MD5, SHA-256…")
        sbl.addWidget(hash_filter)
        lay.addWidget(sb)

        # ── Hash table — Filename | MD5 | SHA-256 only ──────────────
        hash_cols = ["Filename", "MD5", "SHA-256"]
        hash_tbl  = QTableWidget(0, len(hash_cols))
        hash_tbl.setHorizontalHeaderLabels(hash_cols)
        hash_tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hash_tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hash_tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hash_tbl.verticalHeader().setVisible(False)
        hash_tbl.setAlternatingRowColors(True)
        hash_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        hash_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        hash_tbl.setSortingEnabled(True)
        lay.addWidget(hash_tbl)

        # In-memory hash database {path: {md5, sha256, size}}
        if not hasattr(self, '_hash_db'):
            self._hash_db = {}

        def _refresh_table(filter_text=""):
            ft = filter_text.lower()
            hash_tbl.setSortingEnabled(False)
            hash_tbl.setRowCount(0)
            for path, info in self._hash_db.items():
                fn = os.path.basename(path)
                m5 = info.get("md5","")
                sh = info.get("sha256","")
                if ft and not any(ft in x.lower() for x in (fn, m5, sh)):
                    continue
                r = hash_tbl.rowCount()
                hash_tbl.insertRow(r)
                for ci, (val, color) in enumerate([
                    (fn, C['fg']),
                    (m5, C['accent']),
                    (sh, C['green']),
                ]):
                    cell = QTableWidgetItem(str(val))
                    cell.setForeground(QBrush(QColor(color)))
                    cell.setData(Qt.ItemDataRole.UserRole, path)  # store full path
                    hash_tbl.setItem(r, ci, cell)
            hash_tbl.setSortingEnabled(True)

        hash_filter.textChanged.connect(_refresh_table)
        _refresh_table()

        def _calc_hashes():
            # Collect files from the browser's current directory directly.
            # This is more reliable than reading the Path column, which may
            # be empty if the directory was loaded before the column was added.
            files = []
            cur_dir = self.browser.current_dir
            try:
                for entry in cur_dir.iterdir():
                    if entry.is_file():
                        files.append(str(entry))
            except Exception:
                pass
            # Also try reading Path column (col 6) as fallback
            if not files:
                fb = self.browser.file_table
                for r in range(fb.rowCount()):
                    pi = fb.item(r, 6)
                    if pi and pi.text() and os.path.isfile(pi.text()):
                        files.append(pi.text())
            if not files:
                QMessageBox.information(dlg, "No Files",
                    f"No files found in:\n{self.browser.current_dir}\n\n"
                    "Navigate to a directory in the Evidence Browser first.")
                return
            calc_btn.setEnabled(False)
            self._hash_progress.setMaximum(len(files))
            self._hash_progress.setValue(0)

            def run():
                for i, path in enumerate(files):
                    try:
                        m5 = md5_path(path)
                        sh = sha256_path(path)
                        self._hash_db[path] = {"md5": m5, "sha256": sh}
                        # ── Update file browser columns (Path=col6, MD5=col8, SHA256=col9)
                        fb = self.browser.file_table
                        # Reveal hash columns on first successful hash
                        fb.setColumnHidden(8, False)
                        fb.setColumnHidden(9, False)
                        for r in range(fb.rowCount()):
                            # Match by Path column (6) or Name column (0)
                            pi6 = fb.item(r, 6)
                            pi0 = fb.item(r, 0)
                            row_path = (pi6.text() if pi6 else "") or ""
                            row_name = (pi0.text() if pi0 else "").strip()
                            row_name = row_name.lstrip("📁📄📝🎵🎬📕📦⚙🐍📜🔖🗄🖴📋🔑🔗⚡").strip()
                            if row_path == path or row_name == os.path.basename(path):
                                i8 = fb.item(r, 8)
                                i9 = fb.item(r, 9)
                                if i8: i8.setText(m5)
                                else:
                                    c = QTableWidgetItem(m5)
                                    c.setForeground(QBrush(QColor(C['accent'])))
                                    fb.setItem(r, 8, c)
                                if i9: i9.setText(sh)
                                else:
                                    c = QTableWidgetItem(sh)
                                    c.setForeground(QBrush(QColor(C['green'])))
                                    fb.setItem(r, 9, c)
                                break
                    except Exception as e:
                        self._hash_db[path] = {"md5":"", "sha256":""}
                    self._hash_progress.setValue(i+1)
                _refresh_table()
                calc_btn.setEnabled(True)
                self.set_status(f"  Hashed {len(files)} files.")

            threading.Thread(target=run, daemon=True).start()

        def _import_db():
            path, _ = QFileDialog.getOpenFileName(
                dlg,"Import Hash DB","","CSV (*.csv);;JSON (*.json);;All (*)")
            if not path: return
            try:
                if path.endswith(".json"):
                    with open(path) as f: data = json.load(f)
                    self._hash_db.update(data)
                else:
                    import csv as _csv
                    with open(path,newline="") as f:
                        for row in _csv.DictReader(f):
                            p = row.get("Path","")
                            if p:
                                self._hash_db[p] = {
                                    "md5":    row.get("MD5",""),
                                    "sha256": row.get("SHA-256",""),
                                    "size":   int(row.get("Size",0) or 0),
                                    "status": row.get("Status",""),
                                }
                _refresh_table()
                QMessageBox.information(dlg,"Imported",
                    f"Imported {len(self._hash_db)} hash records.")
            except Exception as e:
                QMessageBox.critical(dlg,"Import Error",str(e))

        def _export_db():
            path, _ = QFileDialog.getSaveFileName(
                dlg,"Export Hash DB","hash_db",
                "CSV (*.csv);;JSON (*.json)")
            if not path: return
            try:
                if path.endswith(".json"):
                    with open(path,"w") as f:
                        json.dump(self._hash_db, f, indent=2, default=str)
                else:
                    import csv as _csv
                    with open(path,"w",newline="") as f:
                        w = _csv.writer(f)
                        w.writerow(["File","Path","MD5","SHA-256","Size","Status"])
                        for p, info in self._hash_db.items():
                            w.writerow([os.path.basename(p), p,
                                        info.get("md5",""), info.get("sha256",""),
                                        info.get("size",""), info.get("status","")])
                QMessageBox.information(dlg,"Exported",f"Saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(dlg,"Export Error",str(e))

        def _clear_db():
            if QMessageBox.question(dlg,"Clear Hash DB",
                    f"Clear all {len(self._hash_db)} hash records?",
                    QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No
            ) == QMessageBox.StandardButton.Yes:
                self._hash_db.clear()
                _refresh_table()

        def _verify_file():
            path, _ = QFileDialog.getOpenFileName(dlg,"Select File to Verify","","All (*)")
            if not path: return
            self.set_status(f"  Computing hashes for {os.path.basename(path)}…")
            m5  = md5_path(path)
            sh  = sha256_path(path)
            sz  = os.path.getsize(path)
            stored = self._hash_db.get(path)
            if stored:
                md5_match = stored.get("md5","") == m5
                sha_match = stored.get("sha256","") == sh
                status    = "MATCH ✓" if (md5_match and sha_match) else "MISMATCH ✗"
                QMessageBox.information(dlg, "Verify Result",
                    f"File: {os.path.basename(path)}\n\n"
                    f"Computed MD5:    {m5}\n"
                    f"Stored MD5:      {stored.get('md5','')}\n"
                    f"MD5:             {'Match ✓' if md5_match else 'MISMATCH ✗'}\n\n"
                    f"Computed SHA-256:\n{sh}\n"
                    f"Stored SHA-256:\n{stored.get('sha256','')}\n"
                    f"SHA-256:         {'Match ✓' if sha_match else 'MISMATCH ✗'}\n\n"
                    f"Result: {status}")
            else:
                self._hash_db[path] = {"md5": m5, "sha256": sh}
                QMessageBox.information(dlg, "Hash Computed",
                    f"File: {os.path.basename(path)}\n\n"
                    f"MD5:\n{m5}\n\n"
                    f"SHA-256:\n{sh}\n\n"
                    f"Added to hash database.")
            _refresh_table()
            self.set_status("  Hash verification complete.")

        calc_btn.clicked.connect(_calc_hashes)
        import_btn.clicked.connect(_import_db)
        export_btn.clicked.connect(_export_db)
        clear_btn.clicked.connect(_clear_db)
        verify_btn.clicked.connect(_verify_file)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        lay.addWidget(close_btn)

        dlg.exec()

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
        """Add a remote Windows target for native (agentless) triage."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Add Remote Windows Target  (Native Triage)")
        dlg.setFixedSize(440, 300)
        dlg.setStyleSheet(STYLESHEET)
        lay = QFormLayout(dlg)
        f_host = QLineEdit()
        f_host.setPlaceholderText("hostname or IP (admin share over SMB)")
        f_user = QLineEdit()
        f_user.setPlaceholderText("DOMAIN\\user  or  user")
        f_pass = QLineEdit(); f_pass.setEchoMode(QLineEdit.EchoMode.Password)
        f_case = QLineEdit()
        f_case.setPlaceholderText("Case folder for collected evidence (optional)")
        lay.addRow("Host:",        f_host)
        lay.addRow("Username:",    f_user)
        lay.addRow("Password:",    f_pass)
        lay.addRow("Case Folder:", f_case)
        note = QLabel("Uses only native signed Windows tools (net/reg/wevtutil/\n"
                      "schtasks/tasklist/sc/PowerShell). No SSH or impacket.")
        note.setStyleSheet(f"color:{C['fg2']};font-size:8pt;")
        lay.addRow(note)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept); btns.rejected.connect(dlg.reject)
        lay.addRow(btns)
        if not dlg.exec():
            return
        host = f_host.text().strip()
        if not host:
            QMessageBox.warning(self, "Remote Target", "Enter a host name or IP.")
            return
        user = f_user.text().strip()
        domain = ""
        if "\\" in user:
            domain, user = user.split("\\", 1)
        cfg = register_remote_target(host, user=user, password=f_pass.text(),
                                     domain=domain, case_dir=f_case.text().strip())
        self.browser.add_remote_target(host)
        self._sync_evidence_cache()
        # Mirror into the Remote Triage tab for one-click collection.
        try:
            self.agent_tab.load_target(cfg)
        except Exception:
            pass
        self.tabs.setCurrentIndex(1)   # jump to Artifact Selection
        self.set_status(f"Remote target ready: {host}  (case folder: {cfg['case_dir']})")

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
            "<li>Native agentless remote triage (no SSH / impacket)</li>"
            "<li>Timeline analysis & keyword search</li>"
            "<li>HTML / JSON / CSV export</li>"
            "</ul>"
            f"<p style='color:#8b949e'>Python {sys.version.split()[0]} | PyQt6 | psutil | native Windows tools</p>"
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
