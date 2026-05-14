"""
ForensicPro Enterprise - Digital Forensic Analysis Platform
Mimics EnCase Enterprise with full forensic workflow support.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os, sys, threading, hashlib, datetime, json, struct, time, platform
import subprocess, socket, shutil, stat, base64, zipfile, tempfile
import psutil
from pathlib import Path

# ─────────────────────────────────────────────
#  THEME & STYLE CONSTANTS
# ─────────────────────────────────────────────
BG_DARK      = "#0d1117"
BG_PANEL     = "#161b22"
BG_SIDEBAR   = "#010409"
BG_ROW_ALT  = "#1a2030"
FG_PRIMARY   = "#e6edf3"
FG_SECONDARY = "#8b949e"
FG_ACCENT    = "#58a6ff"
FG_GREEN     = "#3fb950"
FG_RED       = "#f85149"
FG_ORANGE    = "#d29922"
FG_PURPLE    = "#bc8cff"
BORDER       = "#30363d"
SEL_BG       = "#1f3354"
HEADER_BG    = "#21262d"
BTN_BG       = "#21262d"
BTN_HOVER    = "#30363d"

FONT_MONO    = ("Courier New", 9)
FONT_UI      = ("Segoe UI", 9) if platform.system() == "Windows" else ("DejaVu Sans", 9)
FONT_BOLD    = ("Segoe UI", 9, "bold") if platform.system() == "Windows" else ("DejaVu Sans", 9, "bold")
FONT_TITLE   = ("Segoe UI", 11, "bold") if platform.system() == "Windows" else ("DejaVu Sans", 11, "bold")
FONT_SMALL   = ("Segoe UI", 8) if platform.system() == "Windows" else ("DejaVu Sans", 8)

APP_VERSION  = "3.2.1"
APP_NAME     = "ForensicPro Enterprise"

# ─────────────────────────────────────────────
#  HELPER UTILITIES
# ─────────────────────────────────────────────

def format_size(n):
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def format_ts(ts):
    try: return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except: return "N/A"

def md5_file(path, chunk=65536):
    h = hashlib.md5()
    try:
        with open(path,"rb") as f:
            while True:
                buf = f.read(chunk)
                if not buf: break
                h.update(buf)
        return h.hexdigest()
    except: return "N/A"

def sha256_file(path, chunk=65536):
    h = hashlib.sha256()
    try:
        with open(path,"rb") as f:
            while True:
                buf = f.read(chunk)
                if not buf: break
                h.update(buf)
        return h.hexdigest()
    except: return "N/A"

def detect_file_type(path):
    sigs = {
        b"\x4D\x5A": "PE Executable",
        b"\x7FELF": "ELF Binary",
        b"\xFF\xD8\xFF": "JPEG Image",
        b"\x89PNG": "PNG Image",
        b"\x25PDF": "PDF Document",
        b"PK\x03\x04": "ZIP Archive",
        b"\x52\x61\x72": "RAR Archive",
        b"\x1F\x8B": "GZIP Archive",
        b"OggS": "OGG Audio",
        b"ID3": "MP3 Audio",
        b"\x00\x00\x00\x18ftyp": "MP4 Video",
        b"fLaC": "FLAC Audio",
        b"SIMPLE  =": "FITS Image",
        b"\xD0\xCF\x11\xE0": "OLE2 Document (Office)",
        b"PK": "Office Open XML",
        b"ENCASE": "EnCase Evidence File",
        b"EVF": "Expert Witness Format",
    }
    try:
        with open(path,"rb") as f:
            header = f.read(16)
        for sig, name in sigs.items():
            if header.startswith(sig): return name
        ext = Path(path).suffix.lower()
        return {".e01":"EnCase E01 Image",".dd":"DD/RAW Image",".img":"Disk Image",
                ".vmdk":"VMware Disk",".vhd":"VHD Disk",".iso":"ISO Image",
                ".log":"Log File",".txt":"Text File",".xml":"XML File",
                ".json":"JSON File",".csv":"CSV File",".db":"SQLite Database",
                ".sqlite":"SQLite Database",".evtx":"Windows Event Log",
                ".reg":"Registry File",".lnk":"Windows LNK",".pf":"Prefetch File",
                ".pcap":"Network Capture",".pcapng":"Network Capture NG"}.get(ext,"Unknown")
    except: return "Unknown"

# ─────────────────────────────────────────────
#  FORENSIC IMAGE PARSER (E01 / DD stubs)
# ─────────────────────────────────────────────

class ForensicImage:
    """Represents an imported forensic image (E01/DD/RAW)."""
    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)
        self.ext  = Path(path).suffix.lower()
        self.size = os.path.getsize(path)
        self.md5  = None
        self.sha256 = None
        self.metadata = {}
        self._parse_header()

    def _parse_header(self):
        try:
            with open(self.path,"rb") as f:
                header = f.read(256)
            if self.ext == ".e01" or header[:3] == b"EVF":
                self.metadata = {
                    "Format": "Expert Witness Format (EWF/E01)",
                    "Segment": self.name,
                    "Compression": "Detected",
                    "Sectors": "Parsing...",
                }
            elif self.ext in (".dd",".img",".raw"):
                self.metadata = {
                    "Format": "RAW/DD Disk Image",
                    "Segment": self.name,
                    "Sectors": str(self.size // 512),
                    "Sector Size": "512 bytes",
                }
            else:
                self.metadata = {"Format": detect_file_type(self.path)}
        except Exception as e:
            self.metadata = {"Error": str(e)}

    def compute_hashes(self, callback=None):
        self.md5    = md5_file(self.path)
        self.sha256 = sha256_file(self.path)
        if callback: callback(self.md5, self.sha256)

# ─────────────────────────────────────────────
#  ARTIFACT DEFINITIONS
# ─────────────────────────────────────────────

ARTIFACT_CATEGORIES = {
    "System Information": [
        "OS Version & Build",
        "Hostname & Domain",
        "Installed Software",
        "Running Processes",
        "Loaded Drivers/Modules",
        "Scheduled Tasks",
        "System Uptime",
        "BIOS/UEFI Info",
        "Hardware Profile",
    ],
    "User & Account Activity": [
        "Local User Accounts",
        "Last Login Times",
        "Recent Files (MRU)",
        "Shellbags",
        "UserAssist Keys",
        "Jump Lists",
        "Windows Search History",
        "Typed URLs",
    ],
    "Network Artifacts": [
        "Active Connections",
        "ARP Cache",
        "DNS Cache",
        "Network Interfaces",
        "Firewall Rules",
        "Browser Cookies",
        "Browser History",
        "Cached Credentials",
        "WiFi Profiles",
    ],
    "Persistence Mechanisms": [
        "Registry Run Keys",
        "Startup Folder Items",
        "Services (Auto-Start)",
        "COM Hijacking Keys",
        "Browser Extensions",
        "Task Scheduler Jobs",
        "WMI Subscriptions",
        "AppInit DLLs",
    ],
    "File System Artifacts": [
        "Recently Accessed Files",
        "Prefetch Files",
        "LNK / Shortcut Files",
        "Temp Directory Contents",
        "Recycle Bin Contents",
        "Volume Shadow Copies",
        "Alternate Data Streams",
        "$MFT Entries",
    ],
    "Event Logs": [
        "Security Event Log",
        "System Event Log",
        "Application Event Log",
        "PowerShell Operational Log",
        "RDP Session Log",
        "Account Logon Events",
        "Process Creation Events (4688)",
    ],
    "Memory Artifacts": [
        "Process Memory Strings",
        "Injected DLLs",
        "Hollowed Processes",
        "Heap Allocations",
        "Kernel Objects",
    ],
    "Credentials & Secrets": [
        "SAM Database Hash Dump",
        "LSA Secrets",
        "DPAPI Master Keys",
        "Browser Saved Passwords",
        "Certificate Store",
    ],
}

# ─────────────────────────────────────────────
#  LIVE ARTIFACT COLLECTION
# ─────────────────────────────────────────────

def collect_artifact_local(artifact_name):
    """Simulate or actually collect artifacts from the local system."""
    results = []
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    try:
        if artifact_name == "Running Processes":
            for p in psutil.process_iter(['pid','name','username','status','create_time','exe','memory_info']):
                try:
                    info = p.info
                    mem = format_size(info['memory_info'].rss) if info['memory_info'] else "N/A"
                    results.append({
                        "PID": str(info['pid']),
                        "Name": info['name'] or "N/A",
                        "User": info['username'] or "N/A",
                        "Status": info['status'],
                        "Memory": mem,
                        "Started": format_ts(info['create_time']) if info['create_time'] else "N/A",
                        "Path": info['exe'] or "N/A",
                    })
                except: pass

        elif artifact_name == "Network Interfaces":
            for iface, addrs in psutil.net_if_addrs().items():
                stats = psutil.net_if_stats().get(iface)
                for addr in addrs:
                    results.append({
                        "Interface": iface,
                        "Family": str(addr.family),
                        "Address": addr.address,
                        "Netmask": addr.netmask or "N/A",
                        "Speed": f"{stats.speed}Mbps" if stats else "N/A",
                        "Status": "UP" if (stats and stats.isup) else "DOWN",
                    })

        elif artifact_name == "Active Connections":
            for conn in psutil.net_connections(kind='inet'):
                try:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    try: pname = psutil.Process(conn.pid).name() if conn.pid else "N/A"
                    except: pname = "N/A"
                    results.append({
                        "PID": str(conn.pid) if conn.pid else "N/A",
                        "Process": pname,
                        "Protocol": conn.type.name if hasattr(conn.type,"name") else str(conn.type),
                        "Local": laddr,
                        "Remote": raddr,
                        "Status": conn.status,
                    })
                except: pass

        elif artifact_name == "OS Version & Build":
            u = platform.uname()
            results.append({
                "System": u.system,
                "Node": u.node,
                "Release": u.release,
                "Version": u.version,
                "Machine": u.machine,
                "Processor": u.processor,
                "Python": sys.version.split()[0],
            })

        elif artifact_name == "Hostname & Domain":
            results.append({
                "Hostname": socket.gethostname(),
                "FQDN": socket.getfqdn(),
                "IP Address": socket.gethostbyname(socket.gethostname()),
            })

        elif artifact_name == "System Uptime":
            boot = datetime.datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.datetime.now() - boot
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            results.append({
                "Boot Time": boot.strftime("%Y-%m-%d %H:%M:%S"),
                "Uptime": str(uptime).split('.')[0],
                "Total RAM": format_size(mem.total),
                "Used RAM": format_size(mem.used),
                "RAM %": f"{mem.percent}%",
                "Disk Total": format_size(disk.total),
                "Disk Used": format_size(disk.used),
                "Disk %": f"{disk.percent}%",
            })

        elif artifact_name == "Hardware Profile":
            cpu = psutil.cpu_freq()
            results.append({
                "CPU Cores (Physical)": str(psutil.cpu_count(logical=False)),
                "CPU Cores (Logical)": str(psutil.cpu_count(logical=True)),
                "CPU Freq (MHz)": f"{cpu.current:.0f}" if cpu else "N/A",
                "CPU Usage": f"{psutil.cpu_percent(interval=0.5)}%",
                "RAM Total": format_size(psutil.virtual_memory().total),
                "Swap Total": format_size(psutil.swap_memory().total),
            })
            for i, disk in enumerate(psutil.disk_partitions()):
                try:
                    usage = psutil.disk_usage(disk.mountpoint)
                    results.append({
                        "Disk": f"Disk #{i+1}",
                        "Device": disk.device,
                        "Mountpoint": disk.mountpoint,
                        "FSType": disk.fstype,
                        "Total": format_size(usage.total),
                        "Used": format_size(usage.used),
                    })
                except: pass

        elif artifact_name == "Prefetch Files":
            pf_dir = "C:\\Windows\\Prefetch" if platform.system() == "Windows" else "/proc"
            if platform.system() == "Windows" and os.path.isdir(pf_dir):
                for f in os.listdir(pf_dir)[:50]:
                    fp = os.path.join(pf_dir, f)
                    st = os.stat(fp)
                    results.append({
                        "File": f,
                        "Size": format_size(st.st_size),
                        "Modified": format_ts(st.st_mtime),
                        "Accessed": format_ts(st.st_atime),
                    })
            else:
                # Linux demo: /proc entries
                for pid_dir in list(Path("/proc").iterdir())[:30]:
                    if pid_dir.name.isdigit():
                        try:
                            comm = (pid_dir/"comm").read_text().strip()
                            st = pid_dir.stat()
                            results.append({
                                "Process": comm,
                                "PID": pid_dir.name,
                                "Created": format_ts(st.st_mtime),
                            })
                        except: pass

        elif artifact_name == "Recently Accessed Files":
            home = Path.home()
            recent_dirs = [home, home/"Documents", home/"Downloads", home/"Desktop"]
            found = []
            for d in recent_dirs:
                if d.exists():
                    for f in d.iterdir():
                        if f.is_file():
                            try:
                                st = f.stat()
                                found.append((st.st_atime, f, st))
                            except: pass
            found.sort(reverse=True)
            for atime, f, st in found[:40]:
                results.append({
                    "File": f.name,
                    "Path": str(f.parent),
                    "Size": format_size(st.st_size),
                    "Accessed": format_ts(st.st_atime),
                    "Modified": format_ts(st.st_mtime),
                    "Type": detect_file_type(str(f)),
                })

        elif artifact_name == "Temp Directory Contents":
            tmp = tempfile.gettempdir()
            for f in os.listdir(tmp)[:60]:
                fp = os.path.join(tmp, f)
                try:
                    st = os.stat(fp)
                    results.append({
                        "Name": f,
                        "Type": "Directory" if os.path.isdir(fp) else detect_file_type(fp),
                        "Size": format_size(st.st_size) if os.path.isfile(fp) else "-",
                        "Created": format_ts(st.st_ctime),
                        "Modified": format_ts(st.st_mtime),
                    })
                except: pass

        elif artifact_name == "Installed Software":
            if platform.system() == "Linux":
                try:
                    out = subprocess.check_output(["dpkg","-l"], text=True, timeout=10)
                    for line in out.splitlines()[5:55]:
                        parts = line.split()
                        if len(parts) >= 3 and parts[0] == "ii":
                            results.append({"Package": parts[1], "Version": parts[2], "Status": "Installed"})
                except Exception as e:
                    results.append({"Error": str(e)})
            else:
                results.append({"Note": "Installed software listing available on Windows/Linux with appropriate permissions"})

        elif artifact_name == "Scheduled Tasks":
            if platform.system() == "Linux":
                for cron_path in ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"]:
                    if os.path.isdir(cron_path):
                        for f in os.listdir(cron_path)[:20]:
                            fp = os.path.join(cron_path, f)
                            try:
                                st = os.stat(fp)
                                results.append({"Path": fp, "Modified": format_ts(st.st_mtime), "Type": "cron job"})
                            except: pass
                    elif os.path.isfile(cron_path):
                        try:
                            st = os.stat(cron_path)
                            results.append({"Path": cron_path, "Modified": format_ts(st.st_mtime), "Type": "crontab"})
                        except: pass
            else:
                results.append({"Note": "Full task enumeration requires admin/Windows integration"})

        else:
            # Generic: return a representative placeholder
            results.append({
                "Artifact": artifact_name,
                "Status": "Collected",
                "Timestamp": ts,
                "Note": f"Full collection of '{artifact_name}' requires target OS integration. Deploy agent for live collection.",
            })

    except Exception as e:
        results.append({"Error": str(e), "Artifact": artifact_name})

    return results

# ─────────────────────────────────────────────
#  AGENT GENERATOR
# ─────────────────────────────────────────────

AGENT_TEMPLATE = '''#!/usr/bin/env python3
"""
ForensicPro Remote Collection Agent v{version}
Generated: {timestamp}
Case: {case_name}
Examiner: {examiner}
Target Artifacts: {artifacts}
---
Deploy this script on the remote target with administrator/root privileges.
Run: python3 forensic_agent.py [--output /path/to/output] [--server HOST:PORT]
"""
import os, sys, json, socket, hashlib, datetime, platform, subprocess
import psutil, zipfile, tempfile, base64
try: import paramiko
except: paramiko = None

ARTIFACTS = {artifacts_list}
OUTPUT_DIR = "{output_dir}"
SERVER = "{server}"
CASE_ID = "{case_id}"

def collect_sysinfo():
    u = platform.uname()
    mem = psutil.virtual_memory()
    return {{"hostname": u.node, "os": u.system, "release": u.release,
             "version": u.version, "ram_gb": round(mem.total/1073741824,2),
             "cpu_count": psutil.cpu_count(), "boot_time": psutil.boot_time()}}

def collect_processes():
    procs = []
    for p in psutil.process_iter(['pid','name','username','status','exe','cmdline']):
        try: procs.append(p.info)
        except: pass
    return procs

def collect_connections():
    conns = []
    for c in psutil.net_connections(kind='inet'):
        try:
            conns.append({{"pid": c.pid, "status": c.status,
                "local": f"{{c.laddr.ip}}:{{c.laddr.port}}" if c.laddr else "",
                "remote": f"{{c.raddr.ip}}:{{c.raddr.port}}" if c.raddr else ""}})
        except: pass
    return conns

def collect_users():
    users = []
    try:
        for u in psutil.users():
            users.append({{"name": u.name, "terminal": u.terminal,
                           "host": u.host, "started": u.started}})
    except: pass
    return users

def collect_disks():
    disks = []
    for p in psutil.disk_partitions():
        try:
            u = psutil.disk_usage(p.mountpoint)
            disks.append({{"device": p.device, "mountpoint": p.mountpoint,
                "fstype": p.fstype, "total": u.total, "used": u.used}})
        except: pass
    return disks

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report = {{"case_id": CASE_ID, "collected_at": datetime.datetime.now().isoformat(),
               "agent_version": "{version}", "artifacts": {{}}}}

    for artifact in ARTIFACTS:
        print(f"[*] Collecting: {{artifact}}")
        try:
            if artifact == "Running Processes": report["artifacts"][artifact] = collect_processes()
            elif artifact == "Active Connections": report["artifacts"][artifact] = collect_connections()
            elif artifact == "OS Version & Build": report["artifacts"][artifact] = collect_sysinfo()
            elif artifact == "Local User Accounts": report["artifacts"][artifact] = collect_users()
            elif artifact == "Hardware Profile": report["artifacts"][artifact] = collect_disks()
            else: report["artifacts"][artifact] = {{"status": "collected", "note": f"{{artifact}} - see full agent output"}}
            print(f"[+] Done: {{artifact}}")
        except Exception as e:
            report["artifacts"][artifact] = {{"error": str(e)}}
            print(f"[-] Error: {{artifact}}: {{e}}")

    out_path = os.path.join(OUTPUT_DIR, f"forensic_{{CASE_ID}}_{{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}}.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Create ZIP bundle
    zip_path = out_path.replace(".json", ".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(out_path, os.path.basename(out_path))

    print(f"[+] Report saved: {{out_path}}")
    print(f"[+] Archive: {{zip_path}}")

    if SERVER:
        try:
            host, port = SERVER.split(":")
            s = socket.socket()
            s.connect((host, int(port)))
            with open(zip_path, "rb") as f:
                data = f.read()
            s.sendall(len(data).to_bytes(8,"big") + data)
            s.close()
            print(f"[+] Report sent to {{SERVER}}")
        except Exception as e:
            print(f"[-] Send failed: {{e}}")

if __name__ == "__main__":
    main()
'''

def generate_agent(case_name, examiner, artifacts, output_dir, server, case_id):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    arts_str = json.dumps(artifacts)
    code = AGENT_TEMPLATE.format(
        version=APP_VERSION, timestamp=ts, case_name=case_name,
        examiner=examiner, artifacts=", ".join(artifacts),
        artifacts_list=arts_str, output_dir=output_dir or "./forensic_output",
        server=server or "", case_id=case_id or "CASE_001",
    )
    return code

# ─────────────────────────────────────────────
#  MAIN APPLICATION WINDOW
# ─────────────────────────────────────────────

class ForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  v{APP_VERSION}")
        self.geometry("1400x900")
        self.minsize(1100, 700)
        self.configure(bg=BG_DARK)

        # State
        self.evidence_items   = []   # list of (label, type, path/info)
        self.selected_artifacts = {}  # checkbox vars
        self.artifact_results   = {}  # name -> list[dict]
        self.case_info = {
            "name": "New Case", "number": "FC-2025-001",
            "examiner": "Examiner", "notes": ""
        }
        self.status_var  = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar(value=0)

        self._style()
        self._build_menu()
        self._build_toolbar()
        self._build_main()
        self._build_statusbar()

        self.after(100, self._welcome_message)

    # ── Styling ──────────────────────────────
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG_DARK, foreground=FG_PRIMARY,
                    fieldbackground=BG_PANEL, bordercolor=BORDER, troughcolor=BG_PANEL)
        s.configure("TFrame", background=BG_DARK)
        s.configure("TLabel", background=BG_DARK, foreground=FG_PRIMARY, font=FONT_UI)
        s.configure("TButton", background=BTN_BG, foreground=FG_PRIMARY, font=FONT_UI,
                    borderwidth=1, relief="flat", padding=(8,4))
        s.map("TButton", background=[("active",BTN_HOVER),("pressed",BORDER)])
        s.configure("Accent.TButton", background=FG_ACCENT, foreground="#000000", font=FONT_BOLD)
        s.map("Accent.TButton", background=[("active","#79c0ff")])
        s.configure("Danger.TButton", background=FG_RED, foreground="#ffffff", font=FONT_BOLD)
        s.configure("Success.TButton", background=FG_GREEN, foreground="#000000", font=FONT_BOLD)
        s.configure("TNotebook", background=BG_DARK, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_SECONDARY,
                    padding=(14,6), font=FONT_UI)
        s.map("TNotebook.Tab", background=[("selected",BG_DARK)],
              foreground=[("selected",FG_ACCENT)])
        s.configure("Treeview", background=BG_PANEL, foreground=FG_PRIMARY,
                    fieldbackground=BG_PANEL, rowheight=22, font=FONT_UI,
                    borderwidth=0)
        s.configure("Treeview.Heading", background=HEADER_BG, foreground=FG_SECONDARY,
                    font=FONT_BOLD, relief="flat", padding=(4,4))
        s.map("Treeview", background=[("selected",SEL_BG)], foreground=[("selected",FG_ACCENT)])
        s.configure("TScrollbar", background=BG_PANEL, troughcolor=BG_DARK,
                    arrowcolor=FG_SECONDARY, borderwidth=0)
        s.configure("TProgressbar", background=FG_ACCENT, troughcolor=BG_PANEL, borderwidth=0)
        s.configure("TCheckbutton", background=BG_DARK, foreground=FG_PRIMARY, font=FONT_UI)
        s.configure("TEntry", fieldbackground=BG_PANEL, foreground=FG_PRIMARY,
                    insertcolor=FG_PRIMARY, bordercolor=BORDER)
        s.configure("TCombobox", fieldbackground=BG_PANEL, foreground=FG_PRIMARY,
                    selectbackground=SEL_BG)
        s.configure("TSeparator", background=BORDER)
        s.configure("Panel.TFrame", background=BG_PANEL)
        s.configure("Sidebar.TFrame", background=BG_SIDEBAR)
        s.configure("Header.TFrame", background=HEADER_BG)
        s.configure("Header.TLabel", background=HEADER_BG, foreground=FG_SECONDARY, font=FONT_SMALL)
        s.configure("Title.TLabel", background=HEADER_BG, foreground=FG_PRIMARY, font=FONT_TITLE)

    # ── Menu ─────────────────────────────────
    def _build_menu(self):
        mb = tk.Menu(self, bg=BG_PANEL, fg=FG_PRIMARY, activebackground=SEL_BG,
                     activeforeground=FG_ACCENT, borderwidth=0, relief="flat")
        self.config(menu=mb)

        def menu(label, items):
            m = tk.Menu(mb, tearoff=0, bg=BG_PANEL, fg=FG_PRIMARY,
                        activebackground=SEL_BG, activeforeground=FG_ACCENT,
                        borderwidth=1, relief="flat")
            mb.add_cascade(label=label, menu=m)
            for item in items:
                if item[0] == "-": m.add_separator()
                else: m.add_command(label=item[0], command=item[1])
            return m

        menu("File", [
            ("New Case…",         self._new_case),
            ("Open Case…",        self._open_case),
            ("Save Case",         self._save_case),
            ("-",),
            ("Add Evidence File…",self._import_file),
            ("Add Disk Image…",   self._import_image),
            ("Add Local Disk…",   self._import_local_disk),
            ("-",),
            ("Export Report…",    self._export_report),
            ("Exit",              self.quit),
        ])
        menu("Evidence", [
            ("Verify Integrity (Hash All)",   self._verify_all),
            ("Mount Image…",                  self._stub("Mount Image")),
            ("Extract All Files…",            self._stub("Extract Files")),
            ("-",),
            ("Remove Selected Evidence",      self._remove_evidence),
        ])
        menu("Analysis", [
            ("Process Selected Artifacts",    self._process_artifacts),
            ("Keyword Search…",               self._keyword_search),
            ("Timeline Analysis",             self._stub("Timeline Analysis")),
            ("Hash Set Lookup",               self._stub("Hash Set Lookup")),
            ("-",),
            ("Registry Viewer",               self._stub("Registry Viewer")),
            ("Email Analyzer",                self._stub("Email Analyzer")),
        ])
        menu("Remote", [
            ("Generate Agent…",               self._open_agent_tab),
            ("Connect via SSH…",              self._ssh_connect),
            ("Live Response…",                self._stub("Live Response")),
        ])
        menu("View", [
            ("Tree View",         lambda: self._switch_view("tree")),
            ("List View",         lambda: self._switch_view("list")),
            ("Hex View",          self._hex_view),
            ("-",),
            ("Case Properties",   self._case_properties),
        ])
        menu("Help", [
            ("About ForensicPro", self._about),
            ("Documentation",     self._stub("Documentation")),
        ])

    # ── Toolbar ──────────────────────────────
    def _build_toolbar(self):
        bar = tk.Frame(self, bg=HEADER_BG, height=40, bd=0)
        bar.pack(fill="x", side="top")

        def tbtn(text, cmd, accent=False):
            fg_col = "#000000" if accent else FG_PRIMARY
            bg_col = FG_ACCENT if accent else BTN_BG
            b = tk.Button(bar, text=text, command=cmd, bg=bg_col, fg=fg_col,
                          font=FONT_SMALL, relief="flat", bd=0, padx=10, pady=6,
                          activebackground=BTN_HOVER, cursor="hand2")
            b.pack(side="left", padx=2, pady=4)
            return b

        def sep():
            tk.Frame(bar, bg=BORDER, width=1).pack(side="left", fill="y", pady=6, padx=3)

        tbtn("＋ Add Evidence",  self._import_file, accent=True)
        tbtn("🖴 Add Disk Image", self._import_image)
        tbtn("💾 Local Disk",     self._import_local_disk)
        sep()
        tbtn("▶ Process",        self._process_artifacts)
        tbtn("🔍 Search",         self._keyword_search)
        tbtn("📊 Report",         self._export_report)
        sep()
        tbtn("⚡ Remote Agent",   self._open_agent_tab)
        sep()
        tbtn("🔐 Verify Hashes",  self._verify_all)

        # Case info on right
        self.case_label = tk.Label(bar, text="Case: New Case  |  FC-2025-001",
                                   bg=HEADER_BG, fg=FG_SECONDARY, font=FONT_SMALL)
        self.case_label.pack(side="right", padx=12)

    # ── Main Layout ──────────────────────────
    def _build_main(self):
        pane = tk.PanedWindow(self, orient="horizontal", bg=BG_DARK,
                              sashwidth=4, sashrelief="flat", bd=0)
        pane.pack(fill="both", expand=True, padx=0, pady=0)

        # LEFT sidebar
        left = tk.Frame(pane, bg=BG_SIDEBAR, width=260)
        pane.add(left, minsize=180)
        self._build_sidebar(left)

        # RIGHT notebook
        right = tk.Frame(pane, bg=BG_DARK)
        pane.add(right, minsize=600)
        self._build_notebook(right)

    # ── Sidebar ──────────────────────────────
    def _build_sidebar(self, parent):
        # Header
        hdr = tk.Frame(parent, bg=HEADER_BG, pady=6)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  EVIDENCE TREE", bg=HEADER_BG,
                 fg=FG_SECONDARY, font=FONT_SMALL).pack(side="left")

        # Tree
        tf = tk.Frame(parent, bg=BG_SIDEBAR)
        tf.pack(fill="both", expand=True)
        self.ev_tree = ttk.Treeview(tf, show="tree", selectmode="browse")
        self.ev_tree.column("#0", width=240)
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.ev_tree.yview)
        self.ev_tree.configure(yscrollcommand=vsb.set)
        self.ev_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Root nodes
        self.ev_root_local  = self.ev_tree.insert("","end","local_root",
            text="📁  Local Evidence", open=True)
        self.ev_root_images = self.ev_tree.insert("","end","image_root",
            text="🖴  Forensic Images", open=True)
        self.ev_root_remote = self.ev_tree.insert("","end","remote_root",
            text="🌐  Remote Targets", open=True)
        self.ev_tree.tag_configure("evidence", foreground=FG_PRIMARY)
        self.ev_tree.tag_configure("image", foreground=FG_ORANGE)
        self.ev_tree.tag_configure("remote", foreground=FG_PURPLE)
        self.ev_tree.bind("<<TreeviewSelect>>", self._on_evidence_select)
        self.ev_tree.bind("<Button-3>", self._evidence_context_menu)

        # Case info
        ci = tk.Frame(parent, bg=BG_PANEL, pady=6, padx=8)
        ci.pack(fill="x", side="bottom")
        tk.Label(ci, text="CASE INFORMATION", bg=BG_PANEL,
                 fg=FG_SECONDARY, font=FONT_SMALL).pack(anchor="w")
        self.case_detail_text = tk.Text(ci, height=6, bg=BG_PANEL, fg=FG_PRIMARY,
                                        font=FONT_SMALL, relief="flat", wrap="word",
                                        state="disabled", insertbackground=FG_PRIMARY)
        self.case_detail_text.pack(fill="x")
        self._refresh_case_info_panel()

    # ── Notebook Tabs ────────────────────────
    def _build_notebook(self, parent):
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True, padx=4, pady=4)

        self.tab_evidence  = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_artifacts = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_results   = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_hex       = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_timeline  = tk.Frame(self.nb, bg=BG_DARK)
        self.tab_agent     = tk.Frame(self.nb, bg=BG_DARK)

        self.nb.add(self.tab_evidence,  text="📂  Evidence Browser")
        self.nb.add(self.tab_artifacts, text="🔎  Artifact Selection")
        self.nb.add(self.tab_results,   text="📋  Analysis Results")
        self.nb.add(self.tab_hex,       text="🔢  Hex Viewer")
        self.nb.add(self.tab_timeline,  text="📅  Timeline")
        self.nb.add(self.tab_agent,     text="⚡  Remote Agent")

        self._build_tab_evidence()
        self._build_tab_artifacts()
        self._build_tab_results()
        self._build_tab_hex()
        self._build_tab_timeline()
        self._build_tab_agent()

    # ── Tab: Evidence Browser ────────────────
    def _build_tab_evidence(self):
        p = self.tab_evidence

        # Top split: file list | detail/content
        pane = tk.PanedWindow(p, orient="horizontal", bg=BG_DARK,
                              sashwidth=4, sashrelief="flat")
        pane.pack(fill="both", expand=True)

        # File list
        left = tk.Frame(pane, bg=BG_DARK)
        pane.add(left, minsize=400)

        # Toolbar
        ft = tk.Frame(left, bg=HEADER_BG, pady=3)
        ft.pack(fill="x")
        for label, cmd in [("📂 Open Folder", self._browse_folder),
                            ("🖴 Add Image",  self._import_image),
                            ("⟳ Refresh",    self._refresh_file_list)]:
            tk.Button(ft, text=label, command=cmd, bg=BTN_BG, fg=FG_PRIMARY,
                      font=FONT_SMALL, relief="flat", bd=0, padx=8, pady=3,
                      activebackground=BTN_HOVER, cursor="hand2").pack(side="left", padx=2)

        # Path bar
        pb = tk.Frame(left, bg=BG_PANEL, pady=2)
        pb.pack(fill="x")
        tk.Label(pb, text="Path:", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(side="left", padx=4)
        self.path_var = tk.StringVar(value=str(Path.home()))
        tk.Entry(pb, textvariable=self.path_var, bg=BG_PANEL, fg=FG_PRIMARY,
                 insertbackground=FG_PRIMARY, relief="flat", font=FONT_SMALL,
                 bd=0).pack(side="left", fill="x", expand=True, padx=2)
        tk.Button(pb, text="Go", command=self._go_to_path, bg=BTN_BG, fg=FG_PRIMARY,
                  font=FONT_SMALL, relief="flat", bd=0, padx=6,
                  activebackground=BTN_HOVER, cursor="hand2").pack(side="right", padx=2)

        # File list tree (columns)
        cols = ("Name","Size","Type","Modified","MD5")
        self.file_list = ttk.Treeview(left, columns=cols, show="headings",
                                      selectmode="extended")
        widths = [280,80,160,150,260]
        for col,w in zip(cols,widths):
            self.file_list.heading(col, text=col,
                command=lambda c=col: self._sort_file_list(c))
            self.file_list.column(col, width=w, anchor="w")
        sb_v = ttk.Scrollbar(left, orient="vertical",   command=self.file_list.yview)
        sb_h = ttk.Scrollbar(left, orient="horizontal", command=self.file_list.xview)
        self.file_list.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        self.file_list.pack(fill="both", expand=True)
        sb_v.pack(side="right", fill="y")
        self.file_list.bind("<<TreeviewSelect>>", self._on_file_select)
        self.file_list.bind("<Double-1>", self._on_file_double_click)

        # Right: file detail + preview
        right = tk.Frame(pane, bg=BG_DARK)
        pane.add(right, minsize=280)

        tk.Label(right, text="FILE DETAILS", bg=HEADER_BG, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(fill="x", padx=0, pady=0, ipady=4)

        self.file_detail = tk.Text(right, bg=BG_PANEL, fg=FG_PRIMARY, font=FONT_MONO,
                                   relief="flat", wrap="none", state="disabled",
                                   insertbackground=FG_PRIMARY, height=12)
        self.file_detail.pack(fill="x", padx=4, pady=4)

        tk.Label(right, text="CONTENT PREVIEW", bg=HEADER_BG, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(fill="x", padx=0, ipady=4)
        self.content_view = tk.Text(right, bg=BG_PANEL, fg=FG_GREEN, font=FONT_MONO,
                                    relief="flat", state="disabled",
                                    insertbackground=FG_PRIMARY)
        sb2 = ttk.Scrollbar(right, orient="vertical", command=self.content_view.yview)
        self.content_view.configure(yscrollcommand=sb2.set)
        self.content_view.pack(fill="both", expand=True, padx=4, pady=4, side="left")
        sb2.pack(side="right", fill="y", pady=4)

        # Load default directory
        self.current_dir = Path.home()
        self._load_directory(self.current_dir)

    # ── Tab: Artifact Selection ───────────────
    def _build_tab_artifacts(self):
        p = self.tab_artifacts

        # Header
        hdr = tk.Frame(p, bg=HEADER_BG, pady=6)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  SELECT ARTIFACTS TO COLLECT", bg=HEADER_BG,
                 fg=FG_PRIMARY, font=FONT_TITLE).pack(side="left", padx=8)

        # Buttons bar
        bb = tk.Frame(p, bg=BG_DARK, pady=4)
        bb.pack(fill="x", padx=8)
        for label, cmd in [("✓ Select All",   self._select_all_artifacts),
                            ("✗ Clear All",    self._clear_all_artifacts),
                            ("▶ Process Now",  self._process_artifacts)]:
            accent = "Process" in label
            ttk.Button(bb, text=label, command=cmd,
                       style="Accent.TButton" if accent else "TButton"
                       ).pack(side="left", padx=4)

        # Scrollable checkbox area
        outer = tk.Frame(p, bg=BG_DARK)
        outer.pack(fill="both", expand=True, padx=8, pady=4)
        canvas = tk.Canvas(outer, bg=BG_DARK, bd=0, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        self.art_frame = tk.Frame(canvas, bg=BG_DARK)
        self.art_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=self.art_frame, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        canvas.bind("<MouseWheel>",
            lambda e: canvas.yview_scroll(-1*(e.delta//120),"units"))

        # Populate checkboxes
        row = 0
        for cat, arts in ARTIFACT_CATEGORIES.items():
            # Category header
            cat_frame = tk.Frame(self.art_frame, bg=HEADER_BG, bd=0)
            cat_frame.grid(row=row, column=0, columnspan=3, sticky="ew",
                           padx=4, pady=(10,2), ipady=3)
            tk.Label(cat_frame, text=f"  {cat}", bg=HEADER_BG, fg=FG_ACCENT,
                     font=FONT_BOLD).pack(side="left", padx=4)
            row += 1
            col = 0
            for art in arts:
                var = tk.BooleanVar(value=True)
                self.selected_artifacts[art] = var
                cb = tk.Checkbutton(self.art_frame, text=art, variable=var,
                                    bg=BG_DARK, fg=FG_PRIMARY, font=FONT_UI,
                                    selectcolor=BG_PANEL, activebackground=BG_DARK,
                                    activeforeground=FG_ACCENT, cursor="hand2")
                cb.grid(row=row, column=col, sticky="w", padx=16, pady=1)
                col += 1
                if col >= 3:
                    col = 0
                    row += 1
            if col != 0:
                row += 1

    # ── Tab: Analysis Results ─────────────────
    def _build_tab_results(self):
        p = self.tab_results

        # Split: artifact list | result table
        pane = tk.PanedWindow(p, orient="horizontal", bg=BG_DARK,
                              sashwidth=4, sashrelief="flat")
        pane.pack(fill="both", expand=True)

        # Left: collected artifact list
        left = tk.Frame(pane, bg=BG_SIDEBAR)
        pane.add(left, minsize=200)
        tk.Label(left, text="COLLECTED ARTIFACTS", bg=HEADER_BG,
                 fg=FG_SECONDARY, font=FONT_SMALL).pack(fill="x", ipady=4)
        self.result_list = tk.Listbox(left, bg=BG_SIDEBAR, fg=FG_PRIMARY,
                                      font=FONT_UI, selectbackground=SEL_BG,
                                      selectforeground=FG_ACCENT, relief="flat",
                                      activestyle="none", bd=0)
        sb = ttk.Scrollbar(left, orient="vertical", command=self.result_list.yview)
        self.result_list.configure(yscrollcommand=sb.set)
        self.result_list.pack(fill="both", expand=True, side="left")
        sb.pack(side="right", fill="y")
        self.result_list.bind("<<ListboxSelect>>", self._on_result_select)

        # Right: result table
        right = tk.Frame(pane, bg=BG_DARK)
        pane.add(right, minsize=600)

        self.result_header = tk.Label(right, text="Select an artifact from the list",
                                      bg=HEADER_BG, fg=FG_PRIMARY, font=FONT_TITLE,
                                      anchor="w")
        self.result_header.pack(fill="x", ipady=6, padx=8)

        # Export bar
        eb = tk.Frame(right, bg=BG_DARK, pady=2)
        eb.pack(fill="x", padx=4)
        ttk.Button(eb, text="Export CSV",  command=self._export_csv).pack(side="left",padx=2)
        ttk.Button(eb, text="Export JSON", command=self._export_json).pack(side="left",padx=2)
        ttk.Button(eb, text="Export TXT",  command=self._export_txt).pack(side="left",padx=2)
        self.result_count = tk.Label(eb, text="", bg=BG_DARK, fg=FG_SECONDARY, font=FONT_SMALL)
        self.result_count.pack(side="right", padx=8)

        # Dynamic result tree
        self.result_tree_frame = tk.Frame(right, bg=BG_DARK)
        self.result_tree_frame.pack(fill="both", expand=True, padx=4, pady=4)
        self.result_tree   = None
        self.current_result_name = None

        # Progress
        prog_frame = tk.Frame(right, bg=BG_DARK)
        prog_frame.pack(fill="x", padx=4, pady=2)
        self.result_progress = ttk.Progressbar(prog_frame, variable=self.progress_var,
                                               maximum=100, mode="determinate",
                                               style="TProgressbar")
        self.result_progress.pack(fill="x")

    # ── Tab: Hex Viewer ───────────────────────
    def _build_tab_hex(self):
        p = self.tab_hex
        hdr = tk.Frame(p, bg=HEADER_BG, pady=4)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  HEX VIEWER", bg=HEADER_BG, fg=FG_PRIMARY,
                 font=FONT_TITLE).pack(side="left", padx=8)
        ttk.Button(hdr, text="Open File…", command=self._open_hex_file).pack(side="right", padx=8)

        # Offset bar
        ob = tk.Frame(p, bg=BG_PANEL, pady=2)
        ob.pack(fill="x")
        tk.Label(ob, text="Offset:", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(side="left", padx=4)
        self.hex_offset_var = tk.StringVar(value="0")
        tk.Entry(ob, textvariable=self.hex_offset_var, bg=BG_PANEL, fg=FG_PRIMARY,
                 width=12, font=FONT_MONO, insertbackground=FG_PRIMARY,
                 relief="flat").pack(side="left", padx=2)
        tk.Button(ob, text="Jump", command=self._hex_jump, bg=BTN_BG, fg=FG_PRIMARY,
                  font=FONT_SMALL, relief="flat", bd=0, padx=6,
                  activebackground=BTN_HOVER, cursor="hand2").pack(side="left")

        pane2 = tk.PanedWindow(p, orient="horizontal", bg=BG_DARK, sashwidth=4)
        pane2.pack(fill="both", expand=True, padx=4, pady=4)

        # Hex panel
        hex_f = tk.Frame(pane2, bg=BG_DARK)
        pane2.add(hex_f, minsize=500)
        tk.Label(hex_f, text="OFFSET        00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F",
                 bg=BG_PANEL, fg=FG_SECONDARY, font=FONT_MONO).pack(fill="x")
        self.hex_text = tk.Text(hex_f, bg=BG_DARK, fg=FG_GREEN, font=FONT_MONO,
                                relief="flat", state="disabled", wrap="none",
                                insertbackground=FG_PRIMARY)
        hsb = ttk.Scrollbar(hex_f, orient="vertical", command=self.hex_text.yview)
        self.hex_text.configure(yscrollcommand=hsb.set)
        self.hex_text.pack(fill="both", expand=True, side="left")
        hsb.pack(side="right", fill="y")

        # ASCII panel
        asc_f = tk.Frame(pane2, bg=BG_DARK)
        pane2.add(asc_f, minsize=220)
        tk.Label(asc_f, text="ASCII", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_MONO).pack(fill="x")
        self.ascii_text = tk.Text(asc_f, bg=BG_DARK, fg=FG_ORANGE, font=FONT_MONO,
                                  relief="flat", state="disabled", wrap="none",
                                  width=20)
        self.ascii_text.pack(fill="both", expand=True)
        self.hex_file_path = None

    # ── Tab: Timeline ────────────────────────
    def _build_tab_timeline(self):
        p = self.tab_timeline
        hdr = tk.Frame(p, bg=HEADER_BG, pady=6)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  TIMELINE ANALYSIS", bg=HEADER_BG, fg=FG_PRIMARY,
                 font=FONT_TITLE).pack(side="left", padx=8)
        ttk.Button(hdr, text="Build Timeline from Results",
                   command=self._build_timeline).pack(side="right", padx=8)

        # Filter bar
        fb = tk.Frame(p, bg=BG_PANEL, pady=4)
        fb.pack(fill="x", padx=4)
        tk.Label(fb, text="Filter:", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(side="left", padx=4)
        self.tl_filter = tk.Entry(fb, bg=BG_PANEL, fg=FG_PRIMARY, font=FONT_SMALL,
                                  insertbackground=FG_PRIMARY, relief="flat", width=30)
        self.tl_filter.pack(side="left", padx=4)
        self.tl_filter.bind("<KeyRelease>", self._filter_timeline)
        tk.Label(fb, text="From:", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(side="left", padx=4)
        self.tl_from = tk.Entry(fb, bg=BG_PANEL, fg=FG_PRIMARY, font=FONT_SMALL,
                                insertbackground=FG_PRIMARY, relief="flat", width=16)
        self.tl_from.pack(side="left", padx=2)

        cols = ("Timestamp","Event Type","Source","Description")
        self.tl_tree = ttk.Treeview(p, columns=cols, show="headings")
        widths = [160,140,180,500]
        for col,w in zip(cols,widths):
            self.tl_tree.heading(col, text=col)
            self.tl_tree.column(col, width=w, anchor="w")
        self.tl_tree.tag_configure("process", foreground=FG_GREEN)
        self.tl_tree.tag_configure("network", foreground=FG_ORANGE)
        self.tl_tree.tag_configure("file",    foreground=FG_ACCENT)
        self.tl_tree.tag_configure("user",    foreground=FG_PURPLE)
        sb = ttk.Scrollbar(p, orient="vertical", command=self.tl_tree.yview)
        self.tl_tree.configure(yscrollcommand=sb.set)
        self.tl_tree.pack(fill="both", expand=True, padx=4, pady=4, side="left")
        sb.pack(side="right", fill="y", pady=4)
        self.tl_all_items = []

    # ── Tab: Remote Agent ────────────────────
    def _build_tab_agent(self):
        p = self.tab_agent
        tk.Label(p, text="  REMOTE COLLECTION AGENT GENERATOR", bg=HEADER_BG,
                 fg=FG_PRIMARY, font=FONT_TITLE).pack(fill="x", ipady=6)

        pane = tk.PanedWindow(p, orient="horizontal", bg=BG_DARK, sashwidth=4)
        pane.pack(fill="both", expand=True, padx=4, pady=4)

        # Left: config
        cfg = tk.Frame(pane, bg=BG_PANEL, padx=12, pady=12)
        pane.add(cfg, minsize=340)

        def row(parent, label, var_name, default=""):
            tk.Label(parent, text=label, bg=BG_PANEL, fg=FG_SECONDARY,
                     font=FONT_SMALL).pack(anchor="w", pady=(6,0))
            var = tk.StringVar(value=default)
            setattr(self, var_name, var)
            e = tk.Entry(parent, textvariable=var, bg=BG_DARK, fg=FG_PRIMARY,
                         insertbackground=FG_PRIMARY, relief="flat", font=FONT_UI,
                         bd=1, highlightbackground=BORDER, highlightthickness=1)
            e.pack(fill="x", pady=2)
            return var

        tk.Label(cfg, text="CASE & DEPLOYMENT SETTINGS", bg=BG_PANEL,
                 fg=FG_ACCENT, font=FONT_BOLD).pack(anchor="w", pady=(0,8))
        row(cfg, "Case Name",    "ag_case_name",   "Investigation-001")
        row(cfg, "Case ID",      "ag_case_id",     "FC-2025-001")
        row(cfg, "Examiner",     "ag_examiner",    "Forensic Examiner")
        row(cfg, "Output Dir (remote)", "ag_output_dir", "/tmp/forensic_out")
        row(cfg, "C2 Server (host:port, optional)", "ag_server", "")
        row(cfg, "SSH Target (user@host)",  "ag_ssh_target", "")
        row(cfg, "SSH Password / Key Path", "ag_ssh_pass",   "")

        tk.Label(cfg, text="AGENT TYPE", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(anchor="w", pady=(10,2))
        self.ag_type = ttk.Combobox(cfg, values=["Python Script (.py)",
                                                   "Standalone EXE (PyInstaller)",
                                                   "Shell Script (.sh, Linux)"],
                                     state="readonly", font=FONT_UI)
        self.ag_type.current(0)
        self.ag_type.pack(fill="x")

        tk.Label(cfg, text="ARTIFACT PRESET", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_SMALL).pack(anchor="w", pady=(10,2))
        self.ag_preset = ttk.Combobox(cfg, values=["Use Current Selection",
                                                     "Quick Triage (Minimal)",
                                                     "Full Collection",
                                                     "Incident Response",
                                                     "Malware Hunt"],
                                       state="readonly", font=FONT_UI)
        self.ag_preset.current(0)
        self.ag_preset.pack(fill="x")

        btn_f = tk.Frame(cfg, bg=BG_PANEL)
        btn_f.pack(fill="x", pady=12)
        ttk.Button(btn_f, text="⚙ Generate Agent Code",
                   command=self._generate_agent,
                   style="Accent.TButton").pack(fill="x", pady=2)
        ttk.Button(btn_f, text="💾 Save Agent File",
                   command=self._save_agent).pack(fill="x", pady=2)
        ttk.Button(btn_f, text="🚀 Deploy via SSH",
                   command=self._deploy_agent_ssh).pack(fill="x", pady=2)
        ttk.Button(btn_f, text="📥 Import Agent Results",
                   command=self._import_agent_results).pack(fill="x", pady=2)

        # Right: agent code preview
        right = tk.Frame(pane, bg=BG_DARK)
        pane.add(right, minsize=500)
        tk.Label(right, text="GENERATED AGENT CODE", bg=HEADER_BG,
                 fg=FG_SECONDARY, font=FONT_SMALL).pack(fill="x", ipady=4)
        self.agent_code = scrolledtext.ScrolledText(right, bg=BG_DARK, fg=FG_GREEN,
                                                     font=FONT_MONO, relief="flat",
                                                     insertbackground=FG_PRIMARY)
        self.agent_code.pack(fill="both", expand=True, padx=4, pady=4)
        self.agent_code.insert("end",
            "# Agent code will appear here after clicking 'Generate Agent Code'\n"
            "# Configure case settings on the left, then click Generate.\n")

    # ── Status bar ───────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self, bg=HEADER_BG, height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.progress_bar = ttk.Progressbar(bar, variable=self.progress_var,
                                             maximum=100, length=160,
                                             mode="determinate")
        self.progress_bar.pack(side="right", padx=8, pady=3)

        tk.Label(bar, textvariable=self.status_var, bg=HEADER_BG, fg=FG_SECONDARY,
                 font=FONT_SMALL, anchor="w").pack(side="left", padx=8)

        self.time_label = tk.Label(bar, text="", bg=HEADER_BG, fg=FG_SECONDARY,
                                   font=FONT_SMALL)
        self.time_label.pack(side="right", padx=8)
        self._update_clock()

    def _update_clock(self):
        self.time_label.config(
            text=datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._update_clock)

    # ── Evidence Tree Helpers ─────────────────
    def _add_evidence_node(self, label, etype, path_or_info):
        icons = {"file":"📄","directory":"📁","image":"🖴","remote":"🌐","disk":"💾"}
        icon = icons.get(etype, "📄")
        parent = {"file": self.ev_root_local,
                  "directory": self.ev_root_local,
                  "image": self.ev_root_images,
                  "disk": self.ev_root_images,
                  "remote": self.ev_root_remote}.get(etype, self.ev_root_local)
        node_id = self.ev_tree.insert(parent, "end",
                                      text=f"{icon}  {label}",
                                      tags=(etype,))
        self.evidence_items.append({
            "id": node_id, "label": label, "type": etype,
            "path": path_or_info
        })
        self.ev_tree.see(node_id)
        return node_id

    def _import_file(self):
        paths = filedialog.askopenfilenames(
            title="Add Evidence Files",
            filetypes=[("All Forensic Files","*.e01 *.dd *.img *.raw *.vmdk *.vhd *.iso *.evtx *.reg *.db *.pcap *"),
                       ("EnCase E01","*.e01"), ("DD/Raw","*.dd *.img *.raw"),
                       ("All Files","*")])
        for p in paths:
            ext = Path(p).suffix.lower()
            etype = "image" if ext in (".e01",".dd",".img",".raw",".vmdk",".vhd",".iso") else "file"
            self._add_evidence_node(os.path.basename(p), etype, p)
            self.set_status(f"Added: {os.path.basename(p)}")
        if paths:
            self._load_directory(Path(paths[0]).parent)

    def _import_image(self):
        path = filedialog.askopenfilename(
            title="Add Forensic Disk Image",
            filetypes=[("Forensic Images","*.e01 *.dd *.img *.raw *.vmdk *.vhd *.iso *.001"),
                       ("EnCase E01","*.e01"),("DD/RAW","*.dd *.img *.raw"),
                       ("All","*")])
        if path:
            img = ForensicImage(path)
            node = self._add_evidence_node(img.name, "image", path)
            # Add metadata child nodes
            for k,v in img.metadata.items():
                self.ev_tree.insert(node,"end", text=f"  {k}: {v}",
                                    tags=("evidence",))
            self.set_status(f"Image loaded: {img.name}  ({format_size(img.size)})")

    def _import_local_disk(self):
        parts = psutil.disk_partitions()
        if not parts:
            messagebox.showinfo("Disks", "No disk partitions found.")
            return
        win = tk.Toplevel(self)
        win.title("Select Local Disk"); win.geometry("500x360")
        win.configure(bg=BG_DARK); win.grab_set()
        tk.Label(win, text="Available Disk Partitions", bg=BG_DARK,
                 fg=FG_PRIMARY, font=FONT_TITLE).pack(pady=8)
        lb = tk.Listbox(win, bg=BG_PANEL, fg=FG_PRIMARY, font=FONT_UI,
                        selectbackground=SEL_BG, selectforeground=FG_ACCENT,
                        relief="flat", activestyle="none")
        lb.pack(fill="both", expand=True, padx=12, pady=4)
        for p in parts:
            try:
                u = psutil.disk_usage(p.mountpoint)
                label = f"{p.device}  [{p.fstype}]  {format_size(u.total)} total  {format_size(u.free)} free"
            except:
                label = f"{p.device}  [{p.fstype}]"
            lb.insert("end", label)
        def add_sel():
            sel = lb.curselection()
            if sel:
                part = parts[sel[0]]
                self._add_evidence_node(part.device, "disk", part.mountpoint)
                self._load_directory(Path(part.mountpoint))
                self.set_status(f"Disk added: {part.device}")
            win.destroy()
        ttk.Button(win, text="Add Selected Disk", command=add_sel,
                   style="Accent.TButton").pack(pady=8)

    def _remove_evidence(self):
        sel = self.ev_tree.selection()
        for s in sel:
            self.ev_tree.delete(s)
            self.evidence_items = [e for e in self.evidence_items if e["id"] != s]
        self.set_status("Evidence removed.")

    def _on_evidence_select(self, event):
        sel = self.ev_tree.selection()
        if not sel: return
        item = sel[0]
        ev = next((e for e in self.evidence_items if e["id"] == item), None)
        if ev:
            path = ev["path"]
            if os.path.isdir(path):
                self._load_directory(Path(path))
                self.nb.select(0)
            elif os.path.isfile(path):
                self._load_directory(Path(path).parent)
                self.nb.select(0)

    def _evidence_context_menu(self, event):
        item = self.ev_tree.identify_row(event.y)
        if not item: return
        self.ev_tree.selection_set(item)
        m = tk.Menu(self, tearoff=0, bg=BG_PANEL, fg=FG_PRIMARY,
                    activebackground=SEL_BG, activeforeground=FG_ACCENT)
        m.add_command(label="Open in Browser",   command=lambda: self._open_evidence(item))
        m.add_command(label="Verify Hash",        command=lambda: self._hash_evidence(item))
        m.add_command(label="Remove",             command=self._remove_evidence)
        m.add_separator()
        m.add_command(label="Properties",         command=lambda: self._evidence_properties(item))
        m.post(event.x_root, event.y_root)

    def _open_evidence(self, item_id):
        ev = next((e for e in self.evidence_items if e["id"] == item_id), None)
        if ev and os.path.exists(ev["path"]):
            if os.path.isdir(ev["path"]):
                self._load_directory(Path(ev["path"]))
            else:
                self._load_directory(Path(ev["path"]).parent)
            self.nb.select(0)

    def _hash_evidence(self, item_id):
        ev = next((e for e in self.evidence_items if e["id"] == item_id), None)
        if ev and os.path.isfile(ev["path"]):
            self.set_status(f"Computing hashes for {ev['label']}…")
            def run():
                m = md5_file(ev["path"])
                s = sha256_file(ev["path"])
                self.after(0, lambda: messagebox.showinfo(
                    "Hash Verification",
                    f"File: {ev['label']}\n\nMD5:\n{m}\n\nSHA-256:\n{s}"))
                self.set_status(f"Hash complete: {ev['label']}")
            threading.Thread(target=run, daemon=True).start()

    def _evidence_properties(self, item_id):
        ev = next((e for e in self.evidence_items if e["id"] == item_id), None)
        if not ev: return
        info = f"Label: {ev['label']}\nType: {ev['type']}\nPath: {ev['path']}\n"
        if os.path.isfile(ev["path"]):
            st = os.stat(ev["path"])
            info += f"Size: {format_size(st.st_size)}\nModified: {format_ts(st.st_mtime)}\nCreated: {format_ts(st.st_ctime)}"
        messagebox.showinfo("Evidence Properties", info)

    # ── File Browser ─────────────────────────
    def _load_directory(self, path):
        self.current_dir = path
        self.path_var.set(str(path))
        self.file_list.delete(*self.file_list.get_children())
        try:
            entries = sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
        except PermissionError:
            entries = []
        # Add parent
        self.file_list.insert("","end", values=("..","","Directory","",""),
                              tags=("dir",))
        for entry in entries:
            try:
                st = entry.stat()
                size = format_size(st.st_size) if entry.is_file() else ""
                ftype = "Directory" if entry.is_dir() else detect_file_type(str(entry))
                mtime = format_ts(st.st_mtime)
                md5 = ""  # Lazy compute
                tag = "dir" if entry.is_dir() else "file"
                self.file_list.insert("","end",
                    values=(entry.name, size, ftype, mtime, md5),
                    tags=(tag,))
            except: pass
        self.file_list.tag_configure("dir", foreground=FG_ORANGE)
        self.file_list.tag_configure("file", foreground=FG_PRIMARY)

    def _browse_folder(self):
        d = filedialog.askdirectory(title="Select Directory to Browse")
        if d: self._load_directory(Path(d))

    def _go_to_path(self):
        p = Path(self.path_var.get())
        if p.exists() and p.is_dir():
            self._load_directory(p)
        else:
            messagebox.showerror("Error", f"Path not found:\n{p}")

    def _refresh_file_list(self):
        self._load_directory(self.current_dir)

    def _on_file_double_click(self, event):
        sel = self.file_list.selection()
        if not sel: return
        vals = self.file_list.item(sel[0], "values")
        name = vals[0]
        if name == "..":
            self._load_directory(self.current_dir.parent)
        else:
            new = self.current_dir / name
            if new.is_dir(): self._load_directory(new)
            else: self._on_file_select(event)

    def _on_file_select(self, event):
        sel = self.file_list.selection()
        if not sel: return
        vals = self.file_list.item(sel[0], "values")
        name = vals[0]
        if name == "..": return
        fp = self.current_dir / name
        self._show_file_detail(fp)
        self._show_content_preview(fp)

    def _show_file_detail(self, fp):
        self.file_detail.config(state="normal")
        self.file_detail.delete("1.0","end")
        try:
            st = fp.stat()
            info = (
                f"Name        : {fp.name}\n"
                f"Path        : {str(fp.parent)}\n"
                f"Type        : {detect_file_type(str(fp))}\n"
                f"Size        : {format_size(st.st_size)} ({st.st_size:,} bytes)\n"
                f"Created     : {format_ts(st.st_ctime)}\n"
                f"Modified    : {format_ts(st.st_mtime)}\n"
                f"Accessed    : {format_ts(st.st_atime)}\n"
                f"Permissions : {oct(stat.S_IMODE(st.st_mode))}\n"
            )
            if fp.is_file() and st.st_size < 10*1024*1024:
                info += f"MD5         : {md5_file(str(fp))}\n"
                info += f"SHA-256     : {sha256_file(str(fp))}\n"
        except Exception as e:
            info = f"Error: {e}"
        self.file_detail.insert("end", info)
        self.file_detail.config(state="disabled")

    def _show_content_preview(self, fp):
        self.content_view.config(state="normal")
        self.content_view.delete("1.0","end")
        if not fp.is_file():
            self.content_view.insert("end","[Directory — double-click to open]")
            self.content_view.config(state="disabled")
            return
        try:
            with open(fp,"rb") as f:
                data = f.read(8192)
            # Try text
            try:
                text = data.decode("utf-8","replace")
                self.content_view.insert("end", text)
            except:
                # Hex fallback
                lines = []
                for i in range(0, min(len(data),512), 16):
                    chunk = data[i:i+16]
                    hex_part = " ".join(f"{b:02X}" for b in chunk)
                    asc_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
                    lines.append(f"{i:08X}  {hex_part:<48}  {asc_part}")
                self.content_view.insert("end","\n".join(lines))
        except Exception as e:
            self.content_view.insert("end", f"[Cannot read: {e}]")
        self.content_view.config(state="disabled")

    def _sort_file_list(self, col):
        pass  # Sort by column - stub

    # ── Artifact Processing ───────────────────
    def _select_all_artifacts(self):
        for v in self.selected_artifacts.values(): v.set(True)

    def _clear_all_artifacts(self):
        for v in self.selected_artifacts.values(): v.set(False)

    def _process_artifacts(self):
        selected = [name for name, var in self.selected_artifacts.items() if var.get()]
        if not selected:
            messagebox.showwarning("No Artifacts", "Please select at least one artifact.")
            return
        self.nb.select(2)  # Switch to results tab
        self.result_list.delete(0,"end")
        self.artifact_results.clear()
        self.progress_var.set(0)
        self.set_status(f"Processing {len(selected)} artifact(s)…")

        def run():
            for i, art in enumerate(selected):
                self.set_status(f"Collecting: {art}")
                results = collect_artifact_local(art)
                self.artifact_results[art] = results
                pct = (i+1)/len(selected)*100
                self.after(0, lambda a=art, p=pct: (
                    self.result_list.insert("end", f"  {a}"),
                    self.progress_var.set(p),
                ))
                time.sleep(0.05)
            self.after(0, lambda: (
                self.result_list.selection_set(0),
                self._on_result_select(None),
                self.set_status(f"✓ Collection complete — {len(selected)} artifact(s)"),
                self.progress_var.set(100),
            ))
        threading.Thread(target=run, daemon=True).start()

    def _on_result_select(self, event):
        sel = self.result_list.curselection()
        if not sel: return
        art_name = self.result_list.get(sel[0]).strip()
        results  = self.artifact_results.get(art_name, [])
        self.current_result_name = art_name
        self.result_header.config(text=f"  {art_name}  ({len(results)} records)")
        self.result_count.config(text=f"{len(results)} records")
        self._show_result_table(results)

    def _show_result_table(self, results):
        # Destroy old tree
        for w in self.result_tree_frame.winfo_children():
            w.destroy()

        if not results:
            tk.Label(self.result_tree_frame, text="No results", bg=BG_DARK,
                     fg=FG_SECONDARY, font=FONT_UI).pack(pady=20)
            return

        # Get columns from first result
        cols = list(results[0].keys())
        tree = ttk.Treeview(self.result_tree_frame, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            # Auto-width
            max_w = len(col)*10
            for r in results[:20]:
                max_w = max(max_w, len(str(r.get(col,""))) * 7)
            tree.column(col, width=min(max_w, 400), anchor="w")

        for i, row in enumerate(results):
            vals = [str(row.get(c,"")) for c in cols]
            tag = "alt" if i%2 else "norm"
            tree.insert("","end", values=vals, tags=(tag,))

        tree.tag_configure("alt",  background=BG_ROW_ALT)
        tree.tag_configure("norm", background=BG_PANEL)
        vsb = ttk.Scrollbar(self.result_tree_frame, orient="vertical",   command=tree.yview)
        hsb = ttk.Scrollbar(self.result_tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.pack(fill="both", expand=True, side="left")
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.result_tree = tree

    # ── Hex Viewer ───────────────────────────
    def _open_hex_file(self):
        path = filedialog.askopenfilename(title="Open File for Hex View")
        if path:
            self.hex_file_path = path
            self._load_hex(0)

    def _hex_view(self):
        self.nb.select(3)
        if not self.hex_file_path:
            self._open_hex_file()

    def _hex_jump(self):
        try:
            offset = int(self.hex_offset_var.get(), 0)
            self._load_hex(offset)
        except:
            messagebox.showerror("Error","Invalid offset")

    def _load_hex(self, offset=0, length=4096):
        if not self.hex_file_path: return
        self.hex_text.config(state="normal")
        self.ascii_text.config(state="normal")
        self.hex_text.delete("1.0","end")
        self.ascii_text.delete("1.0","end")
        try:
            with open(self.hex_file_path,"rb") as f:
                f.seek(offset)
                data = f.read(length)
            hex_lines = []; asc_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                addr = offset + i
                h1 = " ".join(f"{b:02X}" for b in chunk[:8])
                h2 = " ".join(f"{b:02X}" for b in chunk[8:])
                hex_lines.append(f"{addr:08X}  {h1:<23}  {h2:<23}")
                asc_lines.append("".join(chr(b) if 32<=b<127 else "." for b in chunk))
            self.hex_text.insert("end","\n".join(hex_lines))
            self.ascii_text.insert("end","\n".join(asc_lines))
        except Exception as e:
            self.hex_text.insert("end", f"Error: {e}")
        self.hex_text.config(state="disabled")
        self.ascii_text.config(state="disabled")

    # ── Timeline ─────────────────────────────
    def _build_timeline(self):
        self.tl_tree.delete(*self.tl_tree.get_children())
        self.tl_all_items = []
        events = []
        ts = datetime.datetime.now()

        for art_name, results in self.artifact_results.items():
            for r in results:
                ts_val = None
                for k,v in r.items():
                    if "time" in k.lower() or "date" in k.lower() or "stamp" in k.lower():
                        ts_val = str(v); break
                if not ts_val:
                    ts_val = ts.strftime("%Y-%m-%d %H:%M:%S")
                desc = " | ".join(f"{k}={v}" for k,v in list(r.items())[:4])
                tag = "process" if "Process" in art_name else \
                      "network" if "Connection" in art_name or "DNS" in art_name else \
                      "file"    if "File" in art_name or "Prefetch" in art_name else "user"
                events.append((ts_val, art_name, art_name, desc, tag))

        events.sort(key=lambda x: x[0])
        for ev in events:
            iid = self.tl_tree.insert("","end", values=ev[:4], tags=(ev[4],))
            self.tl_all_items.append((iid, ev))
        self.set_status(f"Timeline built: {len(events)} events")

    def _filter_timeline(self, event=None):
        query = self.tl_filter.get().lower()
        self.tl_tree.delete(*self.tl_tree.get_children())
        for iid, ev in self.tl_all_items:
            if not query or any(query in str(v).lower() for v in ev[:4]):
                self.tl_tree.insert("","end", values=ev[:4], tags=(ev[4],))

    # ── Agent Generation ─────────────────────
    def _generate_agent(self):
        preset = self.ag_preset.get()
        if preset == "Quick Triage (Minimal)":
            arts = ["OS Version & Build","Running Processes","Active Connections","Local User Accounts"]
        elif preset == "Full Collection":
            arts = list(self.selected_artifacts.keys())
        elif preset == "Incident Response":
            arts = ["Running Processes","Active Connections","Network Interfaces",
                    "Recently Accessed Files","Temp Directory Contents",
                    "OS Version & Build","Hostname & Domain","System Uptime"]
        elif preset == "Malware Hunt":
            arts = ["Running Processes","Active Connections","Registry Run Keys",
                    "Scheduled Tasks","Loaded Drivers/Modules","Services (Auto-Start)",
                    "Recently Accessed Files","Prefetch Files"]
        else:
            arts = [n for n,v in self.selected_artifacts.items() if v.get()]
            if not arts:
                arts = ["OS Version & Build","Running Processes","Active Connections"]

        code = generate_agent(
            case_name  = self.ag_case_name.get(),
            examiner   = self.ag_examiner.get(),
            artifacts  = arts,
            output_dir = self.ag_output_dir.get(),
            server     = self.ag_server.get(),
            case_id    = self.ag_case_id.get(),
        )
        self.agent_code.config(state="normal")
        self.agent_code.delete("1.0","end")
        self.agent_code.insert("end", code)
        self.set_status(f"Agent generated with {len(arts)} artifact(s)")
        self._generated_agent_code = code

    def _save_agent(self):
        if not hasattr(self, "_generated_agent_code"):
            messagebox.showwarning("Generate First","Please generate the agent code first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Agent Script",
            defaultextension=".py",
            filetypes=[("Python Script","*.py"),("Shell Script","*.sh"),("All","*")])
        if path:
            with open(path,"w") as f:
                f.write(self._generated_agent_code)
            # Copy to outputs
            out = f"/mnt/user-data/outputs/{os.path.basename(path)}"
            shutil.copy(path, out)
            self.set_status(f"Agent saved: {path}")
            messagebox.showinfo("Saved", f"Agent script saved:\n{path}")

    def _deploy_agent_ssh(self):
        target = self.ag_ssh_target.get()
        if not target:
            messagebox.showwarning("SSH Target", "Please enter SSH target (user@host).")
            return
        if not hasattr(self, "_generated_agent_code"):
            messagebox.showwarning("Generate First","Generate the agent code first.")
            return
        try:
            import paramiko
        except ImportError:
            messagebox.showerror("Missing", "paramiko not installed: pip install paramiko")
            return

        def run():
            self.set_status(f"Connecting to {target}…")
            try:
                user, host = target.split("@") if "@" in target else ("root", target)
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                passwd = self.ag_ssh_pass.get() or None
                client.connect(host, username=user, password=passwd, timeout=15)
                sftp = client.open_sftp()
                remote_path = f"/tmp/forensic_agent_{self.ag_case_id.get()}.py"
                with sftp.open(remote_path, "w") as rf:
                    rf.write(self._generated_agent_code)
                sftp.chmod(remote_path, 0o755)
                stdin, stdout, stderr = client.exec_command(
                    f"python3 {remote_path} &")
                out = stdout.read().decode()
                err = stderr.read().decode()
                client.close()
                self.after(0, lambda: (
                    self.set_status(f"✓ Agent deployed to {target}"),
                    messagebox.showinfo("Deployed",
                        f"Agent deployed to {target}\nPath: {remote_path}\n\nOutput:\n{out[:500]}")
                ))
            except Exception as e:
                self.after(0, lambda: (
                    self.set_status(f"SSH failed: {e}"),
                    messagebox.showerror("SSH Error", str(e))
                ))
        threading.Thread(target=run, daemon=True).start()

    def _import_agent_results(self):
        path = filedialog.askopenfilename(
            title="Import Agent Results",
            filetypes=[("JSON Results","*.json"),("ZIP Archive","*.zip"),("All","*")])
        if not path: return
        try:
            if path.endswith(".zip"):
                with zipfile.ZipFile(path) as z:
                    names = [n for n in z.namelist() if n.endswith(".json")]
                    if not names:
                        messagebox.showerror("Error","No JSON file in archive."); return
                    data = json.loads(z.read(names[0]))
            else:
                with open(path) as f:
                    data = json.load(f)

            arts = data.get("artifacts", {})
            for art_name, results in arts.items():
                if isinstance(results, list):
                    self.artifact_results[art_name] = results
                elif isinstance(results, dict):
                    self.artifact_results[art_name] = [results]
                else:
                    self.artifact_results[art_name] = [{"value": str(results)}]
                self.result_list.insert("end", f"  {art_name}")

            self._add_evidence_node(
                f"Remote: {data.get('hostname', path)}", "remote", path)
            self.nb.select(2)
            self.set_status(f"Imported {len(arts)} artifact(s) from {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Import Error", str(e))

    # ── Export ───────────────────────────────
    def _export_csv(self):
        if not self.current_result_name: return
        results = self.artifact_results.get(self.current_result_name, [])
        if not results: return
        path = filedialog.asksaveasfilename(
            title="Export CSV", defaultextension=".csv",
            filetypes=[("CSV","*.csv")])
        if path:
            import csv
            with open(path,"w",newline="") as f:
                w = csv.DictWriter(f, fieldnames=results[0].keys())
                w.writeheader(); w.writerows(results)
            self.set_status(f"Exported CSV: {path}")

    def _export_json(self):
        path = filedialog.asksaveasfilename(
            title="Export JSON", defaultextension=".json",
            filetypes=[("JSON","*.json")])
        if path:
            with open(path,"w") as f:
                json.dump(self.artifact_results, f, indent=2, default=str)
            self.set_status(f"Exported JSON: {path}")

    def _export_txt(self):
        if not self.current_result_name: return
        results = self.artifact_results.get(self.current_result_name, [])
        path = filedialog.asksaveasfilename(
            title="Export Text", defaultextension=".txt",
            filetypes=[("Text","*.txt")])
        if path:
            with open(path,"w") as f:
                f.write(f"ForensicPro Export — {self.current_result_name}\n")
                f.write(f"Generated: {datetime.datetime.now()}\n")
                f.write("="*60+"\n")
                for r in results:
                    for k,v in r.items():
                        f.write(f"  {k}: {v}\n")
                    f.write("-"*40+"\n")
            self.set_status(f"Exported TXT: {path}")

    def _export_report(self):
        path = filedialog.asksaveasfilename(
            title="Export Full Forensic Report",
            defaultextension=".html",
            filetypes=[("HTML Report","*.html"),("JSON","*.json"),("Text","*.txt")])
        if not path: return
        case = self.case_info
        now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if path.endswith(".html"):
            html = f"""<!DOCTYPE html><html><head>
<title>ForensicPro Report — {case['name']}</title>
<style>
body{{background:#0d1117;color:#e6edf3;font-family:monospace;margin:40px}}
h1{{color:#58a6ff}} h2{{color:#3fb950;border-bottom:1px solid #30363d;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%;margin-bottom:20px}}
th{{background:#21262d;color:#8b949e;padding:6px 10px;text-align:left}}
td{{padding:5px 10px;border-bottom:1px solid #21262d;color:#e6edf3}}
tr:hover td{{background:#1f3354}} .badge{{background:#1f3354;color:#58a6ff;padding:2px 8px;border-radius:4px}}
</style></head><body>
<h1>🔍 ForensicPro Enterprise — Digital Forensic Report</h1>
<p>Case: <b>{case['name']}</b> ({case['number']}) | Examiner: {case['examiner']} | Generated: {now}</p>
<hr style="border-color:#30363d">
"""
            for art_name, results in self.artifact_results.items():
                html += f"<h2>📋 {art_name} <span class='badge'>{len(results)} records</span></h2>"
                if results:
                    cols = list(results[0].keys())
                    html += "<table><tr>" + "".join(f"<th>{c}</th>" for c in cols) + "</tr>"
                    for row in results:
                        html += "<tr>" + "".join(f"<td>{row.get(c,'')}</td>" for c in cols) + "</tr>"
                    html += "</table>"
            html += "</body></html>"
            with open(path,"w") as f:
                f.write(html)
        elif path.endswith(".json"):
            with open(path,"w") as f:
                json.dump({"case": case, "generated": now,
                           "artifacts": self.artifact_results}, f, indent=2, default=str)
        else:
            with open(path,"w") as f:
                f.write(f"ForensicPro Enterprise Report\nCase: {case['name']}\n{now}\n\n")
                for art, results in self.artifact_results.items():
                    f.write(f"\n{'='*60}\n{art}\n{'='*60}\n")
                    for r in results:
                        for k,v in r.items(): f.write(f"  {k}: {v}\n")
                        f.write("\n")

        # Copy to outputs
        try: shutil.copy(path, f"/mnt/user-data/outputs/{os.path.basename(path)}")
        except: pass
        self.set_status(f"Report exported: {path}")
        messagebox.showinfo("Exported", f"Report saved:\n{path}")

    # ── Case Management ───────────────────────
    def _new_case(self):
        win = tk.Toplevel(self)
        win.title("New Case"); win.geometry("420x300")
        win.configure(bg=BG_DARK); win.grab_set()
        tk.Label(win, text="CREATE NEW CASE", bg=HEADER_BG, fg=FG_PRIMARY,
                 font=FONT_TITLE).pack(fill="x", ipady=8)
        fields = {}
        for label, default in [("Case Name","New Investigation"),
                                ("Case Number","FC-2025-001"),
                                ("Examiner",""),("Notes","")]:
            tk.Label(win, text=label, bg=BG_DARK, fg=FG_SECONDARY,
                     font=FONT_SMALL).pack(anchor="w", padx=12, pady=(6,0))
            var = tk.StringVar(value=default)
            tk.Entry(win, textvariable=var, bg=BG_PANEL, fg=FG_PRIMARY,
                     insertbackground=FG_PRIMARY, relief="flat",
                     font=FONT_UI).pack(fill="x", padx=12)
            fields[label] = var

        def create():
            self.case_info = {
                "name":     fields["Case Name"].get(),
                "number":   fields["Case Number"].get(),
                "examiner": fields["Examiner"].get(),
                "notes":    fields["Notes"].get(),
            }
            self._refresh_case_info_panel()
            self.case_label.config(
                text=f"Case: {self.case_info['name']}  |  {self.case_info['number']}")
            win.destroy()
            self.set_status(f"New case: {self.case_info['name']}")

        ttk.Button(win, text="Create Case", command=create,
                   style="Accent.TButton").pack(pady=16)

    def _case_properties(self):
        self._new_case()

    def _refresh_case_info_panel(self):
        c = self.case_info
        self.case_detail_text.config(state="normal")
        self.case_detail_text.delete("1.0","end")
        self.case_detail_text.insert("end",
            f"Name:     {c['name']}\n"
            f"Number:   {c['number']}\n"
            f"Examiner: {c['examiner']}\n"
            f"Items:    {len(self.evidence_items)}\n"
            f"Results:  {len(self.artifact_results)}\n"
        )
        self.case_detail_text.config(state="disabled")

    def _open_case(self):
        path = filedialog.askopenfilename(
            title="Open Case File",
            filetypes=[("ForensicPro Case","*.fpcase"),("JSON","*.json"),("All","*")])
        if not path: return
        try:
            with open(path) as f:
                data = json.load(f)
            self.case_info = data.get("case", self.case_info)
            saved_results = data.get("artifact_results", {})
            self.artifact_results.update(saved_results)
            for art in saved_results:
                self.result_list.insert("end", f"  {art}")
            self._refresh_case_info_panel()
            self.case_label.config(
                text=f"Case: {self.case_info['name']}  |  {self.case_info['number']}")
            self.set_status(f"Case opened: {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open case:\n{e}")

    def _save_case(self):
        path = filedialog.asksaveasfilename(
            title="Save Case", defaultextension=".fpcase",
            filetypes=[("ForensicPro Case","*.fpcase"),("JSON","*.json")])
        if not path: return
        data = {"case": self.case_info,
                "artifact_results": self.artifact_results,
                "evidence_items": [{"label":e["label"],"type":e["type"],"path":e["path"]}
                                   for e in self.evidence_items],
                "saved_at": datetime.datetime.now().isoformat()}
        with open(path,"w") as f:
            json.dump(data, f, indent=2, default=str)
        self.set_status(f"Case saved: {path}")

    # ── SSH Connect ───────────────────────────
    def _ssh_connect(self):
        win = tk.Toplevel(self)
        win.title("SSH Live Response"); win.geometry("400x240")
        win.configure(bg=BG_DARK); win.grab_set()
        tk.Label(win, text="SSH LIVE RESPONSE", bg=HEADER_BG, fg=FG_PRIMARY,
                 font=FONT_TITLE).pack(fill="x", ipady=8)
        fields = {}
        for label, default in [("Host",""),("Username","root"),("Password","")]:
            tk.Label(win, text=label, bg=BG_DARK, fg=FG_SECONDARY,
                     font=FONT_SMALL).pack(anchor="w",padx=12,pady=(6,0))
            var = tk.StringVar(value=default)
            show = "*" if label=="Password" else ""
            tk.Entry(win, textvariable=var, bg=BG_PANEL, fg=FG_PRIMARY,
                     insertbackground=FG_PRIMARY, relief="flat", font=FONT_UI,
                     show=show).pack(fill="x", padx=12)
            fields[label] = var

        def connect():
            host  = fields["Host"].get()
            user  = fields["Username"].get()
            passwd= fields["Password"].get()
            win.destroy()
            self._add_evidence_node(f"SSH: {user}@{host}", "remote", f"{user}@{host}")
            self.ag_ssh_target.set(f"{user}@{host}")
            self.ag_ssh_pass.set(passwd)
            self.nb.select(5)
            self.set_status(f"Remote target added: {user}@{host}")

        ttk.Button(win, text="Add Remote Target", command=connect,
                   style="Accent.TButton").pack(pady=14)

    # ── Keyword Search ────────────────────────
    def _keyword_search(self):
        win = tk.Toplevel(self)
        win.title("Keyword Search"); win.geometry("700x500")
        win.configure(bg=BG_DARK)

        hdr = tk.Frame(win, bg=HEADER_BG, pady=6)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  KEYWORD SEARCH", bg=HEADER_BG, fg=FG_PRIMARY,
                 font=FONT_TITLE).pack(side="left",padx=8)

        sf = tk.Frame(win, bg=BG_PANEL, pady=4)
        sf.pack(fill="x", padx=8, pady=4)
        tk.Label(sf, text="Search:", bg=BG_PANEL, fg=FG_SECONDARY,
                 font=FONT_UI).pack(side="left", padx=4)
        q_var = tk.StringVar()
        q_entry = tk.Entry(sf, textvariable=q_var, bg=BG_DARK, fg=FG_PRIMARY,
                           insertbackground=FG_PRIMARY, relief="flat", font=FONT_UI,
                           width=40)
        q_entry.pack(side="left", padx=4, fill="x", expand=True)

        cols = ("Source","Field","Match","Context")
        results_tree = ttk.Treeview(win, columns=cols, show="headings")
        for col in cols:
            results_tree.heading(col, text=col)
        results_tree.column("Source", width=140)
        results_tree.column("Field",  width=100)
        results_tree.column("Match",  width=180)
        results_tree.column("Context",width=260)
        results_tree.pack(fill="both", expand=True, padx=8, pady=4)

        count_label = tk.Label(win, text="", bg=BG_DARK, fg=FG_SECONDARY, font=FONT_SMALL)
        count_label.pack()

        def do_search(*args):
            q = q_var.get().lower()
            results_tree.delete(*results_tree.get_children())
            if not q: return
            hits = 0
            for art_name, records in self.artifact_results.items():
                for record in records:
                    for k, v in record.items():
                        if q in str(v).lower():
                            context = str(v)[:80]
                            results_tree.insert("","end", values=(art_name,k,str(v)[:50],context))
                            hits += 1
            # Also search current directory files
            for entry in self.current_dir.iterdir():
                if q in entry.name.lower():
                    results_tree.insert("","end",
                        values=(str(self.current_dir),"Filename",entry.name,"File system match"))
                    hits += 1
            count_label.config(text=f"{hits} match(es) found")

        q_entry.bind("<KeyRelease>", do_search)
        ttk.Button(win, text="Search", command=do_search,
                   style="Accent.TButton").pack(pady=4)
        q_entry.focus()

    # ── Open Agent Tab ────────────────────────
    def _open_agent_tab(self):
        self.nb.select(5)

    # ── Verify all ───────────────────────────
    def _verify_all(self):
        files = [e for e in self.evidence_items if os.path.isfile(e["path"])]
        if not files:
            messagebox.showinfo("Verify","No file evidence items to hash."); return
        self.set_status(f"Hashing {len(files)} evidence item(s)…")
        lines = []
        def run():
            for e in files:
                m = md5_file(e["path"])
                s = sha256_file(e["path"])
                lines.append(f"{e['label']}\n  MD5:    {m}\n  SHA256: {s}\n")
                self.set_status(f"Hashed: {e['label']}")
            self.after(0, lambda: (
                messagebox.showinfo("Hash Verification Complete","\n".join(lines[:10])),
                self.set_status("Hash verification complete"),
            ))
        threading.Thread(target=run, daemon=True).start()

    # ── Misc ─────────────────────────────────
    def _browse_folder(self):
        d = filedialog.askdirectory(title="Browse Folder")
        if d: self._load_directory(Path(d))

    def _stub(self, feature):
        return lambda: messagebox.showinfo(feature,
            f"'{feature}' module is available in ForensicPro Enterprise edition.\n"
            f"Connect to a licensed server to activate full functionality.")

    def _about(self):
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME}  v{APP_VERSION}\n\n"
            "Enterprise Digital Forensic Analysis Platform\n"
            "Inspired by EnCase Enterprise\n\n"
            "Features:\n"
            "• Multi-format forensic image support (E01, DD, RAW)\n"
            "• Tree/list/hex/content views\n"
            "• 60+ artifact collection categories\n"
            "• Remote agent generation & SSH deployment\n"
            "• Timeline analysis & keyword search\n"
            "• HTML/JSON/CSV report export\n\n"
            f"Python {sys.version.split()[0]} | tkinter | psutil | paramiko\n"
            f"Platform: {platform.system()} {platform.release()}")

    def _welcome_message(self):
        self.set_status(f"Welcome to {APP_NAME} v{APP_VERSION} — Ready")

    def set_status(self, msg):
        self.status_var.set(f"  {msg}")
        self._refresh_case_info_panel()

    def _switch_view(self, view):
        if view == "tree": self.nb.select(0)
        elif view == "list": self.nb.select(0)

# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()
