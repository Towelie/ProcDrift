#!/usr/bin/env python3
"""
procdrift - baseline + drift detection for Linux execution/persistence surfaces

Usage:
  python3 procdrift.py init
  python3 procdrift.py run

Core model:
- init overwrites baseline (baselines/baseline.json)
- run prints ONLY diffs
- file surfaces show unified diffs (git-like)
- new process identities are annotated (not judged) with high-signal context:
  - parent/uid/cwd/start time
  - suspicious path / deleted exe / world-writable / hidden
  - risky env vars (LD_PRELOAD, etc.) presence
  - interpreter staging markers (-c / -e / curl|sh / base64 decode pipelines)
  - basic socket ownership correlation (listening + outbound endpoints)
  - odd-hour drift vs baseline start-hour set (approximation)

Linux-only (/proc). Root recommended for completeness.

No AI. No signatures. No enforcement.
"""

import os
import re
import sys
import json
import time
import glob
import pwd
import stat
import hashlib
import difflib
from typing import Dict, Any, List, Tuple, Optional

BASELINE_DIR = "baselines"
BASELINE_PATH = os.path.join(BASELINE_DIR, "baseline.json")

WS_RE = re.compile(r"\s+")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
SOCKET_INODE_RE = re.compile(r"socket:\[(\d+)\]")

MAX_TEXT_BYTES = 512_000     # cap for baseline/diff text files
MAX_HASH_BYTES = 50_000_000  # cap for hashing binaries (avoid huge files)
MAX_ENV_BYTES  = 256_000     # cap for /proc/<pid>/environ reads

SUSPECT_PATH_PARTS = (
    "/tmp", "/var/tmp", "/dev/shm", "/run",
    "/.cache/", "/.config/", "/.local/",
)

INTERPRETERS = {
    "python", "python2", "python3", "bash", "sh", "dash",
    "perl", "ruby", "php", "node", "lua"
}

RISK_ENV_KEYS = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "PERL5OPT",
    "RUBYOPT",
}

# ---------------- Utility ----------------

def info(msg: str):
    print(f"[*] {msg}", flush=True)

def die(msg: str, code: int = 1):
    print(f"[!] {msg}")
    sys.exit(code)

def normalize_cmd(cmd: str) -> str:
    return WS_RE.sub(" ", cmd).strip()

def safe_listdir(path: str) -> List[str]:
    try:
        return os.listdir(path)
    except Exception:
        return []

def is_file(path: str) -> bool:
    try:
        return os.path.isfile(path)
    except Exception:
        return False

def is_dir(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except Exception:
        return False

def read_text_lines(path: str, max_bytes: int = MAX_TEXT_BYTES) -> List[str]:
    try:
        st = os.stat(path)
        if st.st_size > max_bytes:
            return [f"<<FILE TOO LARGE: {st.st_size} bytes>>"]
        with open(path, "r", errors="replace") as f:
            return f.read().splitlines()
    except Exception:
        return []

def sha256_file(path: str, max_bytes: int = MAX_HASH_BYTES) -> str:
    try:
        st = os.stat(path)
        if st.st_size > max_bytes:
            return f"<<SKIPPED HASH: {st.st_size} bytes>>"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def print_unified_diff(path: str, base_lines: List[str], curr_lines: List[str]):
    diff = difflib.unified_diff(
        base_lines,
        curr_lines,
        fromfile=f"{path} (baseline)",
        tofile=f"{path} (current)",
        lineterm=""
    )
    for line in diff:
        print(line)

# ---------------- Self hiding (PID ancestry) ----------------

def get_ppid(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            parts = f.read().split()
        return int(parts[3])  # PPID
    except Exception:
        return -1

def get_self_and_parents() -> set:
    pids = set()
    pid = os.getpid()
    while True:
        pids.add(pid)
        ppid = get_ppid(pid)
        if ppid <= 1 or ppid == pid:
            break
        pid = ppid
    return pids

SELF_PIDS = get_self_and_parents()

# ---------------- /proc helpers ----------------

def read_cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
        return normalize_cmd(raw.replace(b"\x00", b" ").decode(errors="ignore").strip())
    except Exception:
        return ""

def read_exe(pid: str) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""

def read_uid(pid: str) -> int:
    try:
        return os.stat(f"/proc/{pid}").st_uid
    except Exception:
        return -1

def read_cwd(pid: str) -> str:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except Exception:
        return ""

def read_status_ppid(pid: str) -> int:
    try:
        with open(f"/proc/{pid}/status", "r", errors="replace") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return -1

def read_start_time_ticks(pid: str) -> int:
    """
    /proc/<pid>/stat field 22 = starttime in clock ticks since boot.
    """
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            parts = f.read().split()
        return int(parts[21])
    except Exception:
        return -1

def boot_time_epoch() -> int:
    """
    From /proc/stat btime (seconds since epoch).
    """
    try:
        with open("/proc/stat", "r") as f:
            for line in f:
                if line.startswith("btime "):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0

def clk_tck() -> int:
    try:
        return os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    except Exception:
        return 100

BOOT_EPOCH = boot_time_epoch()
CLK_TCK = clk_tck()

def start_time_epoch(pid: str) -> int:
    ticks = read_start_time_ticks(pid)
    if ticks < 0 or BOOT_EPOCH <= 0:
        return 0
    return BOOT_EPOCH + int(ticks / max(1, CLK_TCK))

# ---------------- Containers ----------------

def container_hint(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cgroup", "r", errors="replace") as f:
            data = f.read().lower()
    except Exception:
        return ""

    for rx in (HEX64, HEX32):
        m = rx.search(data)
        if m:
            return m.group(0)[:12]
    if "kubepods" in data:
        return "k8s"
    return ""

# ---------------- Risk annotations ----------------

def suspicious_exec_path(exe: str) -> bool:
    if not exe:
        return False
    if "(deleted)" in exe:
        return True
    return any(part in exe for part in SUSPECT_PATH_PARTS)

def is_hidden_path(exe: str) -> bool:
    try:
        return os.path.basename(exe).startswith(".")
    except Exception:
        return False

def is_world_writable_path(exe: str) -> bool:
    """
    Checks if the executable itself OR its containing directory is world-writable.
    """
    try:
        st = os.stat(exe)
        if st.st_mode & 0o002:
            return True
        parent = os.path.dirname(exe) or "/"
        stp = os.stat(parent)
        if stp.st_mode & 0o002:
            return True
    except Exception:
        pass
    return False

def parse_environ(pid: str) -> Dict[str, str]:
    """
    Parse /proc/<pid>/environ (NUL separated) for new processes only.
    Returns dict of env key->value (best effort). Size capped.
    """
    try:
        st = os.stat(f"/proc/{pid}/environ")
        if st.st_size > MAX_ENV_BYTES:
            return {"__TRUNCATED__": f"{st.st_size} bytes"}
        with open(f"/proc/{pid}/environ", "rb") as f:
            raw = f.read()
        out = {}
        for entry in raw.split(b"\x00"):
            if b"=" in entry:
                k, v = entry.split(b"=", 1)
                out[k.decode(errors="ignore")] = v.decode(errors="ignore")
        return out
    except Exception:
        return {}

def env_risk_flags(env: Dict[str, str]) -> List[str]:
    flags = []
    for k in sorted(RISK_ENV_KEYS):
        if k in env and env.get(k, "") != "":
            flags.append(f"ENV:{k}")
    path = env.get("PATH", "")
    if path:
        # simple PATH risk checks
        parts = path.split(":")
        if "." in parts:
            flags.append("ENV:PATH_HAS_DOT")
        for p in parts[:3]:  # only check leading segments (highest risk)
            if p.startswith(("/tmp", "/var/tmp", "/dev/shm")):
                flags.append("ENV:PATH_LEADS_TMP")
                break
    return flags

def interpreter_staging_flags(exe: str, cmd: str) -> List[str]:
    flags = []
    base = os.path.basename(exe).lower() if exe else ""
    low = cmd.lower()

    if base in INTERPRETERS:
        # inline code execution
        if " -c " in f" {cmd} " or low.startswith("python -c") or low.startswith("python3 -c") or low.startswith("bash -c") or low.startswith("sh -c"):
            flags.append("INTERP:INLINE_CODE")
        if " -e " in f" {cmd} ":
            flags.append("INTERP:INLINE_CODE")

    # common staging patterns (cheap string checks)
    if "curl " in low and ("| sh" in low or "|bash" in low or "| bash" in low):
        flags.append("STAGE:CURL_PIPE_SHELL")
    if "wget " in low and ("| sh" in low or "|bash" in low or "| bash" in low):
        flags.append("STAGE:WGET_PIPE_SHELL")
    if "base64" in low and ("-d" in low or "--decode" in low) and ("| sh" in low or "|bash" in low or "| bash" in low):
        flags.append("STAGE:BASE64_DECODE_PIPE_SHELL")
    if "openssl" in low and "enc" in low and ("-d" in low or "-decrypt" in low):
        flags.append("STAGE:OPENSSL_DECRYPT")
    return flags

def user_context_flags(uid: int, ppid_uid: int, cwd: str) -> List[str]:
    flags = []
    if uid == 0 and ppid_uid not in (-1, 0) and ppid_uid != 0:
        flags.append("CTX:ROOT_CHILD_OF_USER")
    # root working in a user's home is often weird
    if uid == 0 and cwd.startswith("/home/"):
        flags.append("CTX:ROOT_CWD_HOME")
    return flags

def odd_hour_flag(start_epoch: int, baseline_hours: List[int]) -> Optional[str]:
    if start_epoch <= 0 or not baseline_hours:
        return None
    hour = time.localtime(start_epoch).tm_hour
    if hour not in baseline_hours:
        return f"TIME:ODD_HOUR({hour})"
    return None

# ---------------- Network correlation (diff-only) ----------------

def parse_proc_net_table(path: str) -> Dict[str, Dict[str, Any]]:
    """
    Parse /proc/net/tcp, tcp6, udp, udp6.
    Returns inode(str) -> conn dict.
    """
    out: Dict[str, Dict[str, Any]] = {}
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception:
        return out

    # header then rows
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        inode = parts[9]
        out[inode] = {
            "local": local,
            "remote": remote,
            "state": state,
            "inode": inode,
            "table": os.path.basename(path),
        }
    return out

def ipport_from_hex(addr_port: str) -> str:
    # best-effort humanization; supports v4 in /proc/net/tcp (little endian hex)
    try:
        addr_hex, port_hex = addr_port.split(":")
        port = int(port_hex, 16)
        if len(addr_hex) == 8:  # IPv4
            b = bytes.fromhex(addr_hex)
            ip = ".".join(str(x) for x in b[::-1])
            return f"{ip}:{port}"
        # fallback: raw
        return f"{addr_hex}:{port}"
    except Exception:
        return addr_port

def build_inode_conn_map() -> Dict[str, Dict[str, Any]]:
    m: Dict[str, Dict[str, Any]] = {}
    for p in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
        m.update(parse_proc_net_table(p))
    return m

def pid_socket_inodes(pid: str) -> List[str]:
    inodes = []
    fd_dir = f"/proc/{pid}/fd"
    if not is_dir(fd_dir):
        return inodes
    for fd in safe_listdir(fd_dir):
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except Exception:
            continue
        m = SOCKET_INODE_RE.search(target)
        if m:
            inodes.append(m.group(1))
    return inodes

def network_summary_for_pid(pid: str, inode_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Returns:
      {
        "listening": [ "ip:port", ... ],
        "outbound": [ "ip:port", ... ],
        "count": int
      }
    """
    listening = set()
    outbound = set()
    inodes = pid_socket_inodes(pid)

    for inode in inodes:
        c = inode_map.get(inode)
        if not c:
            continue
        local = ipport_from_hex(c["local"])
        remote = ipport_from_hex(c["remote"])
        state = c["state"]
        table = c["table"]

        # TCP LISTEN state is 0A; for UDP, state field exists but semantics differ.
        if table.startswith("tcp") and state == "0A":
            listening.add(local)
        else:
            # heuristically treat remote != 0.0.0.0:0 as outbound/connected
            if not remote.endswith(":0") and not remote.startswith("00000000"):
                outbound.add(remote)

    return {"listening": sorted(list(listening)), "outbound": sorted(list(outbound)), "count": len(inodes)}

# ---------------- Snapshot: processes (baseline) ----------------

def snapshot_processes_baseline() -> Dict[str, Any]:
    """
    Baseline stores process identities only (deduped):
      (exe, cmd, uid, container)
    and also a baseline set of observed start-hours (approx).
    """
    procs: Dict[Tuple[str, str, int, str], Dict[str, Any]] = {}
    skipped = 0
    captured = 0
    hours = set()

    for pid in safe_listdir("/proc"):
        if not pid.isdigit():
            continue
        if int(pid) in SELF_PIDS:
            continue

        try:
            exe = read_exe(pid)
            cmd = read_cmdline(pid)
            uid = read_uid(pid)
            cont = container_hint(pid)
        except Exception:
            skipped += 1
            continue

        if not exe or not cmd or uid < 0:
            skipped += 1
            continue

        key = (exe, cmd, uid, cont)
        if key not in procs:
            procs[key] = {"exe": exe, "cmd": cmd, "user": uid, "container": cont}
            captured += 1

        st = start_time_epoch(pid)
        if st > 0:
            hours.add(time.localtime(st).tm_hour)

    return {
        "items": list(procs.values()),
        "stats": {"captured": captured, "skipped": skipped},
        "start_hours": sorted(list(hours)),
    }

# ---------------- Snapshot: generic file collectors ----------------

def collect_text_files(paths: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in paths:
        if is_file(p):
            out.append({"path": p, "content": read_text_lines(p)})
        elif is_dir(p):
            for name in sorted(safe_listdir(p)):
                fp = os.path.join(p, name)
                if is_file(fp):
                    out.append({"path": fp, "content": read_text_lines(fp)})
    return out

def collect_glob_text(patterns: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for pat in patterns:
        for fp in sorted(glob.glob(pat)):
            if is_file(fp):
                out.append({"path": fp, "content": read_text_lines(fp)})
    return out

# ---------------- Snapshot: cron ----------------

def snapshot_cron() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    entries.extend(collect_text_files([
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]))

    for user in pwd.getpwall():
        candidates = [
            f"/var/spool/cron/crontabs/{user.pw_name}",
            f"/var/spool/cron/{user.pw_name}",
        ]
        for crontab in candidates:
            if is_file(crontab):
                entries.append({"path": crontab, "user": user.pw_name, "content": read_text_lines(crontab)})
                break
    return entries

# ---------------- Snapshot: shell init ----------------

def snapshot_shell_rc() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    entries.extend(collect_text_files([
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshrc",
    ]))
    entries.extend(collect_glob_text(["/etc/profile.d/*"]))

    for user in pwd.getpwall():
        home = user.pw_dir
        for fname in (".bashrc", ".profile", ".zshrc"):
            fp = os.path.join(home, fname)
            if is_file(fp):
                entries.append({"path": fp, "user": user.pw_name, "content": read_text_lines(fp)})
    return entries

# ---------------- Snapshot: authorized_keys ----------------

def snapshot_authorized_keys() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for user in pwd.getpwall():
        ak = os.path.join(user.pw_dir, ".ssh", "authorized_keys")
        if is_file(ak):
            entries.append({"path": ak, "user": user.pw_name, "content": read_text_lines(ak)})
    return entries

# ---------------- Snapshot: systemd persistence ----------------

def snapshot_systemd_units() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    entries.extend(collect_glob_text([
        "/etc/systemd/system/*.service",
        "/etc/systemd/system/*.timer",
        "/etc/systemd/system/*.socket",
        "/etc/systemd/system/*.path",
        "/etc/systemd/system/*.mount",
        "/etc/systemd/system/*.target",
        "/etc/systemd/system/*/*.conf",
        "/etc/systemd/system/*.d/*.conf",
    ]))

    entries.extend(collect_glob_text([
        "/lib/systemd/system/*.service",
        "/lib/systemd/system/*.timer",
        "/lib/systemd/system/*.socket",
        "/lib/systemd/system/*.path",
        "/lib/systemd/system/*.mount",
        "/lib/systemd/system/*.target",
    ]))

    for user in pwd.getpwall():
        base = os.path.join(user.pw_dir, ".config", "systemd", "user")
        if is_dir(base):
            pats = [
                os.path.join(base, "*.service"),
                os.path.join(base, "*.timer"),
                os.path.join(base, "*.socket"),
                os.path.join(base, "*.path"),
                os.path.join(base, "*.target"),
                os.path.join(base, "*.mount"),
                os.path.join(base, "*.d", "*.conf"),
            ]
            for fp in sorted(sum([glob.glob(p) for p in pats], [])):
                if is_file(fp):
                    entries.append({"path": fp, "user": user.pw_name, "content": read_text_lines(fp)})

    return entries

def snapshot_systemd_enablement() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []

    def collect_wants(root: str, user: Optional[str] = None):
        for wants_dir in sorted(glob.glob(os.path.join(root, "*.wants"))):
            if not is_dir(wants_dir):
                continue
            for item in sorted(glob.glob(os.path.join(wants_dir, "*"))):
                try:
                    if os.path.islink(item):
                        target = os.readlink(item)
                        entry = {"path": item, "target": target}
                        if user:
                            entry["user"] = user
                        entries.append(entry)
                    elif is_file(item):
                        entry = {"path": item, "target": "<<not a symlink>>"}
                        if user:
                            entry["user"] = user
                        entries.append(entry)
                except Exception:
                    continue

    collect_wants("/etc/systemd/system", None)

    for user in pwd.getpwall():
        root = os.path.join(user.pw_dir, ".config", "systemd", "user")
        if is_dir(root):
            collect_wants(root, user.pw_name)

    return entries

# ---------------- Snapshot: dynamic linker ----------------

def snapshot_linker() -> List[Dict[str, Any]]:
    return collect_text_files([
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
    ])

# ---------------- Snapshot: identity & privilege ----------------

def snapshot_identity_privilege() -> Dict[str, Any]:
    text_entries = collect_text_files([
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
        "/etc/sudoers.d",
    ])
    shadow_hash = sha256_file("/etc/shadow") if is_file("/etc/shadow") else ""
    return {"text": text_entries, "shadow": {"path": "/etc/shadow", "sha256": shadow_hash}}

# ---------------- Snapshot: SSH daemon config ----------------

def snapshot_ssh() -> List[Dict[str, Any]]:
    return collect_text_files([
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
    ])

# ---------------- Snapshot: kernel modules & autoload ----------------

def snapshot_kernel() -> Dict[str, Any]:
    mods: List[str] = []
    try:
        with open("/proc/modules", "r", errors="replace") as f:
            for line in f.read().splitlines():
                name = line.split()[0] if line.strip() else ""
                if name:
                    mods.append(name)
    except Exception:
        pass

    autoload = collect_text_files([
        "/etc/modules",
        "/etc/modules-load.d",
    ])

    return {"loaded_modules": sorted(set(mods)), "autoload": autoload}

# ---------------- Snapshot: SUID/SGID inventory ----------------

SUID_SCAN_DIRS = [
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"
]

def snapshot_suid_sgid() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for base in SUID_SCAN_DIRS:
        if not is_dir(base):
            continue
        for fp in sorted(glob.glob(os.path.join(base, "*"))):
            try:
                st = os.stat(fp, follow_symlinks=False)
            except Exception:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if (st.st_mode & stat.S_ISUID) or (st.st_mode & stat.S_ISGID):
                items.append({
                    "path": fp,
                    "mode": oct(st.st_mode & 0o7777),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "sha256": sha256_file(fp),
                })
    return items

# ---------------- Snapshot: log metadata ----------------

LOG_CANDIDATES = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
]

def snapshot_log_metadata() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in LOG_CANDIDATES:
        if not is_file(p):
            continue
        try:
            st = os.stat(p)
            out.append({"path": p, "inode": st.st_ino, "size": st.st_size, "mtime": int(st.st_mtime)})
        except Exception:
            continue
    return out

# ---------------- Snapshot orchestration ----------------

def take_snapshot() -> Dict[str, Any]:
    return {
        "timestamp": int(time.time()),
        "processes": snapshot_processes_baseline(),
        "cron": snapshot_cron(),
        "shell_rc": snapshot_shell_rc(),
        "authorized_keys": snapshot_authorized_keys(),
        "systemd_units": snapshot_systemd_units(),
        "systemd_enablement": snapshot_systemd_enablement(),
        "linker": snapshot_linker(),
        "identity_privilege": snapshot_identity_privilege(),
        "ssh": snapshot_ssh(),
        "kernel": snapshot_kernel(),
        "suid_sgid": snapshot_suid_sgid(),
        "log_metadata": snapshot_log_metadata(),
    }

# ---------------- Diff helpers ----------------

def index_by_path(items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    idx: Dict[str, Dict[str, Any]] = {}
    for it in items:
        p = it.get("path", "")
        if p:
            idx[p] = it
    return idx

def diff_processes(base_items: List[Dict[str, Any]], curr_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    base_set = {(p.get("exe",""), p.get("cmd",""), p.get("user",-1), p.get("container","")) for p in base_items}
    return [p for p in curr_items if (p.get("exe",""), p.get("cmd",""), p.get("user",-1), p.get("container","")) not in base_set]

def diff_text_files(base_items: List[Dict[str, Any]], curr_items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    base_idx = index_by_path(base_items)
    curr_idx = index_by_path(curr_items)
    changed: Dict[str, Dict[str, Any]] = {}

    for path in sorted(set(base_idx.keys()) | set(curr_idx.keys())):
        b = base_idx.get(path)
        c = curr_idx.get(path)

        if b is None and c is not None:
            changed[path] = {"base": None, "curr": c}
            continue
        if c is None and b is not None:
            changed[path] = {"base": b, "curr": None}
            continue
        if b.get("content", []) != c.get("content", []):
            changed[path] = {"base": b, "curr": c}

    return changed

def diff_simple_sets(base_list: List[Any], curr_list: List[Any]) -> Dict[str, List[Any]]:
    b = set(base_list)
    c = set(curr_list)
    return {"added": sorted(list(c - b)), "removed": sorted(list(b - c))}

def diff_systemd_enablement(base: List[Dict[str, Any]], curr: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    b = {x.get("path",""): x for x in base if x.get("path")}
    c = {x.get("path",""): x for x in curr if x.get("path")}
    changes: Dict[str, Dict[str, Any]] = {}

    for p in sorted(set(b.keys()) | set(c.keys())):
        if p not in b:
            changes[p] = {"type": "added", "curr": c[p]}
        elif p not in c:
            changes[p] = {"type": "removed", "base": b[p]}
        else:
            if b[p].get("target") != c[p].get("target"):
                changes[p] = {"type": "modified", "base": b[p], "curr": c[p]}
    return changes

def diff_suid(base: List[Dict[str, Any]], curr: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    b = {x.get("path",""): x for x in base if x.get("path")}
    c = {x.get("path",""): x for x in curr if x.get("path")}
    added, removed, modified = [], [], []

    for p in sorted(set(b.keys()) | set(c.keys())):
        if p not in b:
            added.append(c[p])
        elif p not in c:
            removed.append(b[p])
        else:
            if (b[p].get("mode"), b[p].get("uid"), b[p].get("gid"), b[p].get("sha256")) != \
               (c[p].get("mode"), c[p].get("uid"), c[p].get("gid"), c[p].get("sha256")):
                modified.append({"path": p, "base": b[p], "curr": c[p]})
    return {"added": added, "removed": removed, "modified": modified}

def diff_log_meta(base: List[Dict[str, Any]], curr: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    b = {x.get("path",""): x for x in base if x.get("path")}
    c = {x.get("path",""): x for x in curr if x.get("path")}
    added, removed, changed = [], [], []

    for p in sorted(set(b.keys()) | set(c.keys())):
        if p not in b:
            added.append(c[p])
        elif p not in c:
            removed.append(b[p])
        else:
            if (b[p].get("inode"), b[p].get("size"), b[p].get("mtime")) != (c[p].get("inode"), c[p].get("size"), c[p].get("mtime")):
                changed.append({"path": p, "base": b[p], "curr": c[p]})
    return {"added": added, "removed": removed, "changed": changed}

# ---------------- Printing helpers ----------------

def show_unified_diff_group(title: str, changes: Dict[str, Dict[str, Any]]):
    if not changes:
        return
    print(f"\n[{title}: unified diffs]")
    for path, pair in changes.items():
        b = pair["base"]
        c = pair["curr"]
        print()
        if b is None and c is not None:
            print_unified_diff(path, [], c.get("content", []))
        elif c is None and b is not None:
            print_unified_diff(path, b.get("content", []), [])
        else:
            print_unified_diff(path, b.get("content", []), c.get("content", []))

# ---------------- Process annotation (run-time only for NEW procs) ----------------

def build_current_pid_index() -> Dict[Tuple[str, str, int, str], str]:
    """
    Map identity tuple -> one representative PID (current run).
    """
    idx: Dict[Tuple[str, str, int, str], str] = {}
    for pid in safe_listdir("/proc"):
        if not pid.isdigit():
            continue
        if int(pid) in SELF_PIDS:
            continue

        exe = read_exe(pid)
        cmd = read_cmdline(pid)
        uid = read_uid(pid)
        cont = container_hint(pid)

        if not exe or not cmd or uid < 0:
            continue

        key = (exe, cmd, uid, cont)
        if key not in idx:
            idx[key] = pid
    return idx

def annotate_new_process(p: Dict[str, Any], pid: str, baseline_hours: List[int], inode_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Adds:
      - pid, ppid, parent exe/cmd/uid
      - cwd
      - start time epoch + local string
      - risk flags (path/env/interpreter/user/time/network)
      - network summary (listening/outbound)
    """
    exe = p.get("exe","")
    cmd = p.get("cmd","")
    uid = int(p.get("user", -1))
    cont = p.get("container","")

    flags: List[str] = []
    extra: Dict[str, Any] = {}

    # parent context
    ppid = read_status_ppid(pid)
    pexe = read_exe(str(ppid)) if ppid > 0 else ""
    pcmd = read_cmdline(str(ppid)) if ppid > 0 else ""
    puid = read_uid(str(ppid)) if ppid > 0 else -1

    # cwd
    cwd = read_cwd(pid)

    # start time
    st_epoch = start_time_epoch(pid)
    st_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st_epoch)) if st_epoch > 0 else ""

    # risk: deleted exe
    if "(deleted)" in exe:
        flags.append("EXEC:DELETED")

    # risk: suspicious path
    if suspicious_exec_path(exe):
        flags.append("EXEC:SUSP_PATH")

    if is_hidden_path(exe):
        flags.append("EXEC:HIDDEN_NAME")

    if is_world_writable_path(exe):
        flags.append("EXEC:WORLD_WRITABLE")

    # env risks (new processes only)
    env = parse_environ(pid)
    flags.extend(env_risk_flags(env))

    # interpreter / staging patterns
    flags.extend(interpreter_staging_flags(exe, cmd))

    # user context anomalies
    flags.extend(user_context_flags(uid, puid, cwd))

    # odd hour vs baseline observed hours
    oh = odd_hour_flag(st_epoch, baseline_hours)
    if oh:
        flags.append(oh)

    # network correlation (diff-only)
    net = network_summary_for_pid(pid, inode_map)
    if net["listening"]:
        flags.append("NET:LISTENING")
    if net["outbound"]:
        flags.append("NET:OUTBOUND")

    extra.update({
        "pid": int(pid),
        "ppid": ppid,
        "parent_exe": pexe,
        "parent_cmd": pcmd,
        "parent_user": puid,
        "cwd": cwd,
        "start_time": st_str,
        "start_epoch": st_epoch,
        "network": net,
        "flags": flags,
    })
    return extra

# ---------------- Commands ----------------

def cmd_init():
    snap = take_snapshot()
    os.makedirs(BASELINE_DIR, exist_ok=True)
    with open(BASELINE_PATH, "w") as f:
        json.dump(snap, f, indent=2)

    pstats = snap["processes"]["stats"]
    hours = snap["processes"].get("start_hours", [])
    info("Baseline initialized (overwritten if existed)")
    info(f"Process snapshot: captured={pstats['captured']} skipped={pstats['skipped']} (permissions may affect this)")
    info(f"Baseline start-hours observed: {hours if hours else 'none'}")

def cmd_run():
    if not os.path.exists(BASELINE_PATH):
        die("Baseline not found. Run: python3 procdrift.py init")

    with open(BASELINE_PATH, "r") as f:
        base = json.load(f)

    curr = take_snapshot()

    # Process diffs (identities only)
    proc_diffs = diff_processes(base["processes"]["items"], curr["processes"]["items"])

    # File surfaces diffs
    cron_changes = diff_text_files(base["cron"], curr["cron"])
    shell_changes = diff_text_files(base["shell_rc"], curr["shell_rc"])
    ak_changes = diff_text_files(base["authorized_keys"], curr["authorized_keys"])
    systemd_unit_changes = diff_text_files(base["systemd_units"], curr["systemd_units"])
    systemd_en_changes = diff_systemd_enablement(base["systemd_enablement"], curr["systemd_enablement"])
    linker_changes = diff_text_files(base["linker"], curr["linker"])
    ident_text_changes = diff_text_files(base["identity_privilege"]["text"], curr["identity_privilege"]["text"])
    ssh_changes = diff_text_files(base["ssh"], curr["ssh"])
    kernel_mod_changes = diff_simple_sets(base["kernel"]["loaded_modules"], curr["kernel"]["loaded_modules"])
    kernel_autoload_changes = diff_text_files(base["kernel"]["autoload"], curr["kernel"]["autoload"])
    suid_changes = diff_suid(base["suid_sgid"], curr["suid_sgid"])
    log_meta_changes = diff_log_meta(base["log_metadata"], curr["log_metadata"])

    shadow_base = base["identity_privilege"].get("shadow", {}).get("sha256", "")
    shadow_curr = curr["identity_privilege"].get("shadow", {}).get("sha256", "")
    shadow_changed = (shadow_base != shadow_curr)

    any_drift = any([
        proc_diffs,
        cron_changes, shell_changes, ak_changes,
        systemd_unit_changes, systemd_en_changes,
        linker_changes,
        ident_text_changes, shadow_changed,
        ssh_changes,
        kernel_mod_changes["added"] or kernel_mod_changes["removed"],
        kernel_autoload_changes,
        suid_changes["added"] or suid_changes["removed"] or suid_changes["modified"],
        log_meta_changes["added"] or log_meta_changes["removed"] or log_meta_changes["changed"],
    ])

    if not any_drift:
        info("No drift detected")
        return

    info("Drift detected")

    # Enrich new process diffs ONLY
    if proc_diffs:
        baseline_hours = base["processes"].get("start_hours", [])
        pid_index = build_current_pid_index()
        inode_map = build_inode_conn_map()

        print("\n[Processes: new identities + annotations]")
        for p in proc_diffs:
            key = (p.get("exe",""), p.get("cmd",""), p.get("user",-1), p.get("container",""))
            pid = pid_index.get(key, "")

            # base identity print
            cont = p.get("container","")
            cont_str = f" container={cont}" if cont else ""
            print(f"- exe={p.get('exe','')}")
            print(f"  cmd={p.get('cmd','')}")
            print(f"  user={p.get('user','')}{cont_str}")

            if pid:
                ann = annotate_new_process(p, pid, baseline_hours, inode_map)
                flags = ann.get("flags", [])
                if flags:
                    print(f"  flags={','.join(flags)}")
                if ann.get("start_time"):
                    print(f"  start={ann['start_time']} pid={ann['pid']} ppid={ann['ppid']}")
                if ann.get("cwd"):
                    print(f"  cwd={ann['cwd']}")
                if ann.get("parent_exe") or ann.get("parent_cmd"):
                    print(f"  parent_exe={ann.get('parent_exe','')}")
                    if ann.get("parent_cmd"):
                        print(f"  parent_cmd={ann['parent_cmd']}")
                    print(f"  parent_user={ann.get('parent_user')}")
                net = ann.get("network", {})
                if net:
                    if net.get("listening"):
                        print(f"  listening={net['listening']}")
                    if net.get("outbound"):
                        # limit spam
                        out = net["outbound"]
                        shown = out[:8]
                        more = f" (+{len(out)-len(shown)} more)" if len(out) > len(shown) else ""
                        print(f"  outbound={shown}{more}")
            else:
                print("  (note: no PID match to enrich; likely permissions or process ended)")

            print()

    # File drift diffs
    show_unified_diff_group("Cron", cron_changes)
    show_unified_diff_group("Shell RC", shell_changes)
    show_unified_diff_group("authorized_keys", ak_changes)
    show_unified_diff_group("systemd units", systemd_unit_changes)

    if systemd_en_changes:
        print("\n[systemd enablement: wants symlinks]")
        for pth, change in systemd_en_changes.items():
            t = change["type"]
            if t == "added":
                cur = change["curr"]
                print(f"+ {pth} -> {cur.get('target')}")
            elif t == "removed":
                b = change["base"]
                print(f"- {pth} -> {b.get('target')}")
            else:
                b = change["base"]
                c = change["curr"]
                print(f"~ {pth}")
                print(f"  - {b.get('target')}")
                print(f"  + {c.get('target')}")

    show_unified_diff_group("Dynamic linker", linker_changes)
    show_unified_diff_group("Identity/privilege", ident_text_changes)

    if shadow_changed:
        print("\n[/etc/shadow: hash changed]")
        print(f"- baseline sha256: {shadow_base}")
        print(f"+ current  sha256: {shadow_curr}")
        print("  (hash-only; content not stored)")

    show_unified_diff_group("SSHD config", ssh_changes)

    if kernel_mod_changes["added"] or kernel_mod_changes["removed"]:
        print("\n[Kernel modules]")
        for m in kernel_mod_changes["added"]:
            print(f"+ {m}")
        for m in kernel_mod_changes["removed"]:
            print(f"- {m}")

    show_unified_diff_group("Kernel autoload configs", kernel_autoload_changes)

    if suid_changes["added"] or suid_changes["removed"] or suid_changes["modified"]:
        print("\n[SUID/SGID inventory]")
        for it in suid_changes["added"]:
            print(f"+ {it['path']} mode={it['mode']} uid={it['uid']} gid={it['gid']} sha256={it['sha256']}")
        for it in suid_changes["removed"]:
            print(f"- {it['path']} mode={it['mode']} uid={it['uid']} gid={it['gid']} sha256={it['sha256']}")
        for ch in suid_changes["modified"]:
            b = ch["base"]
            c = ch["curr"]
            print(f"~ {ch['path']}")
            print(f"  - mode={b.get('mode')} uid={b.get('uid')} gid={b.get('gid')} sha256={b.get('sha256')}")
            print(f"  + mode={c.get('mode')} uid={c.get('uid')} gid={c.get('gid')} sha256={c.get('sha256')}")

    if log_meta_changes["added"] or log_meta_changes["removed"] or log_meta_changes["changed"]:
        print("\n[Log metadata]")
        for it in log_meta_changes["added"]:
            print(f"+ {it['path']} inode={it['inode']} size={it['size']} mtime={it['mtime']}")
        for it in log_meta_changes["removed"]:
            print(f"- {it['path']} inode={it['inode']} size={it['size']} mtime={it['mtime']}")
        for ch in log_meta_changes["changed"]:
            b = ch["base"]
            c = ch["curr"]
            print(f"~ {ch['path']}")
            print(f"  - inode={b.get('inode')} size={b.get('size')} mtime={b.get('mtime')}")
            print(f"  + inode={c.get('inode')} size={c.get('size')} mtime={c.get('mtime')}")

# ---------------- Entry ----------------

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("init", "run"):
        print("Usage:")
        print("  python3 procdrift.py init")
        print("  python3 procdrift.py run")
        sys.exit(1)

    if sys.argv[1] == "init":
        cmd_init()
    else:
        cmd_run()

if __name__ == "__main__":
    main()
