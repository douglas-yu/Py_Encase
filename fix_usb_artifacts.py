
#!/usr/bin/env python3
"""
fix_usb_artifacts.py
====================
Standalone patcher for the USB artifact collection in forensic_qt.py.

Run AFTER fix_tree_thumb_usb.py (or instead of its Patch 9).

Adds four USB artifacts to ARTIFACT_CATEGORIES and implements their
collection logic inside collect_artifact().  All registry paths are
built at runtime using chr(92) so the patcher source is backslash-free.

Usage
-----
    python fix_usb_artifacts.py  path/to/forensic_qt.py
"""

import sys, os, shutil

# ── runtime helpers ───────────────────────────────────────────────────────────
_B  = chr(92)          # backslash
_N  = _B + "n"         # \n   (for regex / split patterns)
_S  = _B + "s"         # \s
_D  = _B + "d"         # \d
_BB = _B + _B          # \\  (escaped backslash in regex raw strings)

# Registry key strings exactly as they must appear in the injected code
_K_USBSTOR = 'r"SYSTEM{b}CurrentControlSet{b}Enum{b}USBSTOR"'.format(b=_B)
_K_WINDIR  = 'r"C:{b}Windows"'.format(b=_B)
_K_MP2     = ('(r"SOFTWARE{b}Microsoft{b}Windows{b}CurrentVersion"'
              ' r"{b}Explorer{b}MountPoints2")').format(b=_B)
_K_MDEV    = 'r"SYSTEM{b}MountedDevices"'.format(b=_B)

# Regex patterns (raw strings in injected code)
_RE_SETUPAPI = ('r">>>.*?USBSTOR.*?<<<.*?start.*?{n}.*?time.*?{n}"'
                ).format(n=_N)
_RE_TS       = ('r"start{s}+({d}{{4}}/{d}{{2}}/{d}{{2}}[^{n}]+)"'
                ).format(s=_S, d=_D, n=_N)
_RE_DEV      = ('r"USBSTOR{bb}[^{bb}]+{bb}([^{s}{b}]{bb}]+)"'
                ).format(bb=_BB, s=_S, b=_B)

# String used to split udevadm output on blank lines
_SPLIT_NN = '"{n}{n}"'.format(n=_N)


# ── ARTIFACT_CATEGORIES patch ─────────────────────────────────────────────────

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


# ── collect_artifact() USB logic ──────────────────────────────────────────────

P9_OLD = """\
        # ── GENERIC FALLBACK for any uncaught names ───────────────────
        else:
            results.append({
                "Artifact":  name,
                "Status":    "Not Implemented","""


def _build_p9():
    """Build P9_NEW without any literal backslash characters."""

    usb_hist = "\n".join([
        "",
        "        elif name == \"USB Device History\":",
        "            if OS == \"Windows\":",
        "                try:",
        "                    import winreg as _wr",
        "                    usbstor = " + _K_USBSTOR,
        "                    with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, usbstor) as root:",
        "                        i = 0",
        "                        while True:",
        "                            try:",
        "                                dev_class = _wr.EnumKey(root, i); i += 1",
        "                                with _wr.OpenKey(root, dev_class) as ckey:",
        "                                    j = 0",
        "                                    while True:",
        "                                        try:",
        "                                            serial = _wr.EnumKey(ckey, j)",
        "                                            j += 1",
        "                                            with _wr.OpenKey(",
        "                                                    ckey, serial) as skey:",
        "                                                def _qv(k):",
        "                                                    try:",
        "                                                        return _wr.QueryValueEx(",
        "                                                            skey, k)[0]",
        "                                                    except Exception:",
        "                                                        return \"\"",
        "                                                results.append({",
        "                                                    \"DeviceClass\":  dev_class,",
        "                                                    \"SerialNumber\": serial,",
        "                                                    \"FriendlyName\": _qv(\"FriendlyName\"),",
        "                                                    \"Manufacturer\": _qv(\"Mfg\"),",
        "                                                    \"Service\":      _qv(\"Service\"),",
        "                                                    \"Driver\":       _qv(\"Driver\"),",
        "                                                })",
        "                                        except OSError:",
        "                                            break",
        "                            except OSError:",
        "                                break",
        "                except PermissionError:",
        "                    results.append({",
        "                        \"Note\": \"Access denied - run as Administrator for USB registry.\"})",
        "                except Exception as e:",
        "                    results.append({\"Error\": str(e), \"Source\": \"USBSTOR Registry\"})",
        "            else:",
        "                try:",
        "                    import subprocess as _sp",
        "                    r = _sp.run(",
        "                        [\"udevadm\", \"info\", \"--export-db\"],",
        "                        capture_output=True, text=True, timeout=20)",
        "                    for block in r.stdout.split(" + _SPLIT_NN + "):",
        "                        if \"ID_BUS=usb\" in block and \"ID_TYPE=disk\" in block:",
        "                            info = {}",
        "                            for line in block.splitlines():",
        "                                if \"E: \" in line and \"=\" in line:",
        "                                    rest = line.partition(\"E: \")[2]",
        "                                    k, _, v = rest.partition(\"=\")",
        "                                    info[k.strip()] = v.strip()",
        "                            if info:",
        "                                results.append({",
        "                                    \"Device\":     info.get(\"DEVNAME\", \"\"),",
        "                                    \"Vendor\":     info.get(\"ID_VENDOR\", \"\"),",
        "                                    \"Model\":      info.get(\"ID_MODEL\", \"\"),",
        "                                    \"Serial\":     info.get(\"ID_SERIAL_SHORT\", \"\"),",
        "                                    \"Filesystem\": info.get(\"ID_FS_TYPE\", \"\"),",
        "                                    \"Label\":      info.get(\"ID_FS_LABEL\", \"\"),",
        "                                })",
        "                except Exception:",
        "                    pass",
        "                try:",
        "                    import subprocess as _sp",
        "                    dm = _sp.run(",
        "                        [\"dmesg\"], capture_output=True, text=True, timeout=10)",
        "                    for line in dm.stdout.splitlines():",
        "                        ll = line.lower()",
        "                        if \"usb\" in ll and any(",
        "                                x in ll for x in",
        "                                (\"new usb\", \"attached\", \"disconnect\",",
        "                                 \"product:\", \"manufacturer:\")):",
        "                            results.append({\"dmesg\": line.strip()})",
        "                except Exception:",
        "                    pass",
        "            if not results:",
        "                results.append({",
        "                    \"Note\": \"No USB records found. Run as Administrator/root.\"})",
    ])

    usb_times = "\n".join([
        "",
        "        elif name == \"USB First/Last Connection Times\":",
        "            if OS == \"Windows\":",
        "                import re as _re",
        "                setupapi = os.path.join(",
        "                    os.environ.get(\"SystemRoot\", " + _K_WINDIR + "),",
        "                    \"INF\", \"setupapi.dev.log\")",
        "                if os.path.isfile(setupapi):",
        "                    try:",
        "                        with open(setupapi, \"r\",",
        "                                  encoding=\"utf-8\", errors=\"ignore\") as f:",
        "                            content = f.read()",
        "                        for m in list(_re.finditer(",
        "                                " + _RE_SETUPAPI + ",",
        "                                content,",
        "                                _re.DOTALL | _re.IGNORECASE))[:60]:",
        "                            blk   = m.group(0)",
        "                            ts_m  = _re.search(",
        "                                " + _RE_TS + ", blk)",
        "                            dev_m = _re.search(",
        "                                " + _RE_DEV + ", blk)",
        "                            results.append({",
        "                                \"FirstConnected\": ts_m.group(1).strip()",
        "                                                  if ts_m else \"\",",
        "                                \"DeviceID\":       dev_m.group(1).strip()",
        "                                                  if dev_m else \"\",",
        "                                \"Source\":         \"SetupAPI.dev.log\",",
        "                            })",
        "                    except Exception as e:",
        "                        results.append({\"Source\": \"SetupAPI\", \"Error\": str(e)})",
        "                try:",
        "                    import subprocess as _sp",
        "                    out = _sp.run(",
        "                        [\"wevtutil\", \"qe\",",
        "                         \"Microsoft-Windows-DriverFrameworks-UserMode/Operational\",",
        "                         \"/q:*[System[(EventID=2003 or EventID=2100)]]\",",
        "                         \"/f:text\", \"/c:200\"],",
        "                        capture_output=True, text=True, timeout=25)",
        "                    for line in out.stdout.splitlines():",
        "                        ls = line.strip()",
        "                        if ls:",
        "                            results.append({\"EventLog\": ls})",
        "                except Exception:",
        "                    pass",
        "            else:",
        "                results.append({",
        "                    \"Note\": \"USB connection-time keys are Windows-only.\"})",
        "            if not results:",
        "                results.append({\"Note\": \"No USB connection-time records found.\"})",
    ])

    drive_letters = "\n".join([
        "",
        "        elif name == \"Drive Letter Assignments\":",
        "            try:",
        "                for p in psutil.disk_partitions(all=True):",
        "                    try:",
        "                        u = psutil.disk_usage(p.mountpoint)",
        "                        results.append({",
        "                            \"Device\":     p.device,",
        "                            \"Mountpoint\": p.mountpoint,",
        "                            \"Filesystem\": p.fstype,",
        "                            \"Options\":    p.opts,",
        "                            \"Total\":      fmt_size(u.total),",
        "                            \"Used\":       fmt_size(u.used),",
        "                            \"Free\":       fmt_size(u.free),",
        "                            \"UsedPct\":    f\"{u.percent:.1f}%\",",
        "                        })",
        "                    except Exception:",
        "                        results.append({",
        "                            \"Device\":     p.device,",
        "                            \"Mountpoint\": p.mountpoint,",
        "                            \"Filesystem\": p.fstype,",
        "                        })",
        "            except Exception as e:",
        "                results.append({\"Error\": str(e)})",
        "            if OS == \"Windows\":",
        "                try:",
        "                    import winreg as _wr",
        "                    mp2 = " + _K_MP2,
        "                    with _wr.OpenKey(_wr.HKEY_CURRENT_USER, mp2) as key:",
        "                        i = 0",
        "                        while True:",
        "                            try:",
        "                                guid = _wr.EnumKey(key, i); i += 1",
        "                                results.append(",
        "                                    {\"MountPoints2_GUID\": guid,",
        "                                     \"Source\": \"HKCU MountPoints2\"})",
        "                            except OSError:",
        "                                break",
        "                except Exception:",
        "                    pass",
        "            if not results:",
        "                results.append({\"Note\": \"No drive assignment records found.\"})",
    ])

    vol_serials = "\n".join([
        "",
        "        elif name == \"Volume Serial Numbers\":",
        "            if OS == \"Windows\":",
        "                try:",
        "                    import winreg as _wr, struct as _st",
        "                    with _wr.OpenKey(",
        "                            _wr.HKEY_LOCAL_MACHINE,",
        "                            " + _K_MDEV + ") as key:",
        "                        i = 0",
        "                        while True:",
        "                            try:",
        "                                vname, data, _ = _wr.EnumValue(key, i)",
        "                                i += 1",
        "                                if (data and len(data) >= 12",
        "                                        and (\"DosDevices\" in vname",
        "                                             or \"#\" in vname)):",
        "                                    try:",
        "                                        vsn = _st.unpack_from(",
        "                                            \"<I\", data, 8)[0]",
        "                                        results.append({",
        "                                            \"MountPoint\":   vname,",
        "                                            \"VolumeSerial\": \"%08X\" % vsn,",
        "                                            \"RawBytes\":     len(data),",
        "                                        })",
        "                                    except Exception:",
        "                                        results.append({",
        "                                            \"MountPoint\": vname,",
        "                                            \"RawBytes\":   len(data),",
        "                                        })",
        "                            except OSError:",
        "                                break",
        "                except PermissionError:",
        "                    results.append(",
        "                        {\"Note\": \"Access denied - run as Administrator.\"})",
        "                except Exception as e:",
        "                    results.append({\"Error\": str(e)})",
        "            else:",
        "                import subprocess as _sp",
        "                done = False",
        "                for cmd in (",
        "                    [\"lsblk\", \"-o\",",
        "                     \"NAME,UUID,FSTYPE,LABEL,SIZE,MOUNTPOINT\"],",
        "                    [\"blkid\"],",
        "                ):",
        "                    try:",
        "                        r = _sp.run(",
        "                            cmd, capture_output=True,",
        "                            text=True, timeout=10)",
        "                        if r.returncode == 0:",
        "                            for line in r.stdout.splitlines():",
        "                                if line.strip():",
        "                                    results.append(",
        "                                        {\"Output\": line.strip(),",
        "                                         \"Source\": cmd[0]})",
        "                            done = True",
        "                            break",
        "                    except Exception:",
        "                        pass",
        "                if not done:",
        "                    results.append(",
        "                        {\"Note\": \"lsblk/blkid not available on this system.\"})",
        "            if not results:",
        "                results.append(",
        "                    {\"Note\": \"No volume serial number records found.\"})",
        "",
        "        # -- GENERIC FALLBACK for any uncaught names --",
        "        else:",
        "            results.append({",
        "                \"Artifact\":  name,",
        "                \"Status\":    \"Not Implemented\",",
    ])

    return (
        "        # -- REMOVABLE MEDIA & USB --\n"
        + usb_hist
        + usb_times
        + drive_letters
        + vol_serials
    )


P9_NEW = _build_p9()


# ── patch helper ──────────────────────────────────────────────────────────────

def patch(code, old, new, tag):
    if old not in code:
        print(f"  [SKIP] not found - {tag}")
        return code
    result = code.replace(old, new, 1)
    print(f"  [OK]   {tag}")
    return result


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_usb_artifacts.py <forensic_qt.py>")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.isfile(src):
        print(f"Error: not found - {src}")
        sys.exit(1)

    bak = src + ".bak_usb"
    shutil.copy2(src, bak)
    print(f"Backup : {bak}\n")

    with open(src, "r", encoding="utf-8") as fh:
        code = fh.read()

    print("Applying USB artifact patches...")
    code = patch(code, P8_OLD, P8_NEW,
                 "Add 'Removable Media & USB' to ARTIFACT_CATEGORIES")
    code = patch(code, P9_OLD, P9_NEW,
                 "USB collection logic in collect_artifact()")

    with open(src, "w", encoding="utf-8") as fh:
        fh.write(code)

    print(f"\nDone - patched: {src}")
    print(f"Restore with:   {bak}\n")
    print("USB artifacts added:")
    print("  - USB Device History           (USBSTOR registry / udevadm / dmesg)")
    print("  - USB First/Last Connection Times (SetupAPI log / Event Log IDs 2003/2100)")
    print("  - Drive Letter Assignments     (psutil + MountPoints2 registry)")
    print("  - Volume Serial Numbers        (MountedDevices registry / lsblk / blkid)")


if __name__ == "__main__":
    main()
