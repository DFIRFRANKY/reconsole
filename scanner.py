"""
scanner.py
----------
The backend engine for reconsole. Targets Kali Linux and its standard tools:
nmap, smbmap, gobuster.

It is designed to run as ROOT. Running as root means every tool reconsole
spawns is already root, so the privileged nmap scans (SYN / -A / -p-) need no
`sudo` prefix, and reconsole can also stop those scans cleanly (a process can
only signal another process it owns). Start it with `sudo python app.py`.

Input variables (substituted into the preset and custom commands)
    $IPs / $IPS   one or more targets (single / comma list / range / CIDR).
                  Expanded to a concrete IP list; written to IP.txt.
    $ports        one or more ports (single / comma list / range a-b).
    $hostname     a single hostname.

How each tool consumes those variables
    nmap      one run for everything. $IPs -> "ip1 ip2 ..."; $ports -> the raw
              spec ("80,443" or "1-1024"), which nmap accepts directly in a
              single command.
    smbmap    one run per host ($IPs -> a single ip, via -H).
    gobuster  -u takes ONE url, so a run is created per host AND/OR per port:
                $IPS:$ports      -> one run per (host, port)
                $hostname:$ports -> one run per port (single host)
              http:// is prepended to the -u value when no scheme is present.

Timeouts
    There is NO timeout: a scan runs for as long as it needs (a full nmap -p- /
    -A scan can take hours). Runs are never killed by a watchdog — they can
    still be stopped manually or on shutdown.

Each run streams its combined stdout/stderr to its own .txt file as it happens,
so output can be watched live. Running tasks can be stopped individually or all
at once, and every child is killed when the app exits.

Safety
    * Commands never go through a shell (shell=False, argv list); the validated
      IPv4/port/hostname values cannot inject anything.
    * Targets/ports/hostnames are validated before use; expansion is capped.
"""

import ipaddress
import os
import re
import shlex
import shutil
import signal
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

import database as db

RUNS_DIR = "runs"
MAX_HOSTS = 2048           # safety cap on IP range/CIDR expansion
MAX_GOBUSTER_PORTS = 64    # gobuster runs once per port; refuse to fan out past this
MAX_CONCURRENCY = 4        # tasks run in parallel (nmap/smbmap/gobuster at once)
SIGKILL_GRACE = 3.0        # seconds between SIGTERM and SIGKILL when stopping

# ---- live-process control --------------------------------------------------
# RUNNING_PROCS maps an in-flight run_id to its Popen so it can be stopped on
# demand and so every child can be killed when the app shuts down. STOP_REQUESTED
# marks runs the user explicitly stopped (vs. timed out / failed). CANCELLED_SCANS
# tells the worker to stop launching the remaining runs of a scan.
_procs_lock = threading.Lock()
RUNNING_PROCS = {}         # run_id -> subprocess.Popen
STOP_REQUESTED = set()     # run_id
CANCELLED_SCANS = set()    # scan_id


class RunStopped(Exception):
    """Raised inside _execute when a run was killed by the user."""


def _terminate_group(proc, sig):
    """Send a signal to the process's whole group (so e.g. an nmap helper child
    dies too). Falls back to signalling just the process if the group call fails."""
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, OSError):
        try:
            proc.send_signal(sig)
        except Exception:
            pass


def stop_run(run_id: int) -> bool:
    """Stop one running task. SIGTERM now, SIGKILL shortly after if it lingers.
    Returns True if a live process was found."""
    with _procs_lock:
        STOP_REQUESTED.add(run_id)
        proc = RUNNING_PROCS.get(run_id)
    if not proc:
        return False
    _terminate_group(proc, signal.SIGTERM)
    threading.Timer(SIGKILL_GRACE, lambda: _terminate_group(proc, signal.SIGKILL)).start()
    return True


def kill_all_procs() -> list:
    """Stop every running task (used by 'Stop all' and on shutdown).
    Returns the run_ids that were stopped."""
    with _procs_lock:
        items = list(RUNNING_PROCS.items())
        for rid, _ in items:
            STOP_REQUESTED.add(rid)
    for _, proc in items:
        _terminate_group(proc, signal.SIGTERM)
    for _, proc in items:
        threading.Timer(SIGKILL_GRACE, lambda p=proc: _terminate_group(p, signal.SIGKILL)).start()
    return [rid for rid, _ in items]


def cancel_scan(scan_id: int) -> None:
    CANCELLED_SCANS.add(scan_id)


_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_GOBUSTER_LINE = re.compile(
    r"(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)(?:\s+\[Size:\s*(?P<size>\d+)\])?"
)


# ==========================================================================
# Preset catalogue  ── THIS IS WHERE YOU ADD OR CHANGE THE SCAN COMMANDS ──
# ==========================================================================
# This list is the single source of truth for the checkboxes in the GUI. The
# web UI fetches it (via /api/presets), renders one checkbox per entry grouped
# by `tool`, and sends back the chosen `id`s. The backend then looks each id up
# here and runs its `template`. Add, remove, or edit entries below and the GUI
# updates automatically — no other file needs to change.
#
# Each entry is a dict with these keys:
#
#   id        Unique, stable string. Sent from the browser to identify the
#             preset. Must be unique across the whole list. (If you rename an
#             id, anyone who had it selected just needs to re-tick it.)
#
#   tool      The external binary, e.g. "nmap" / "smbmap" / "gobuster". Used to
#             group the checkbox in the UI, to check the tool is installed, and
#             to name the output file. The command must still name the tool in
#             `template` too (the tool name here is metadata, not the command).
#
#   loop      A tuple saying how this command FANS OUT into separate tasks,
#             because some tools take many targets at once and some take one:
#                ()             -> ONE task for everything. $IPs becomes the
#                                  whole space-joined list, $ports the raw spec.
#                                  Use for nmap (it accepts many hosts/ports in
#                                  a single command).
#                ("ip",)        -> one task PER host. $IPs becomes a single IP.
#                                  Use for smbmap (-H takes one host).
#                ("ip","port")  -> one task per (host, port) pair.
#                ("port",)      -> one task per port, single host.
#                                  Use the last two for gobuster, whose -u takes
#                                  exactly one URL (one host, one port).
#
#   parse     Which output parser populates the Dashboard from this command:
#                "nmap"      -> parses nmap XML into the Open Ports widget.
#                "smbmap"    -> parses SMB shares into the SMB widget.
#                "gobuster"  -> parses discovered paths into the Web widget.
#                None        -> run it, capture/stream output, but don't parse
#                               (still visible in the Runs panel + output file).
#             To feed a NEW tool into the dashboard, write a _parse_<tool>()
#             function in the "Output parsers" section and reference it from
#             run_job (see the dispatch in run_job's _do()).
#
#   template  The actual command line, with these variables substituted from
#             the GUI fields before running (see _substitute):
#                $IPs / $IPS  the target IP(s)
#                $ports       the port(s)            (one per task when looped)
#                $hostname    the single hostname
#             For gobuster, http:// is auto-prepended to the -u value if you
#             leave the scheme off (see _ensure_scheme).
#
# ── EXAMPLES ──────────────────────────────────────────────────────────────
#   Add a UDP nmap scan of given ports (one task, all hosts):
#       {"id": "nmap_udp", "tool": "nmap", "loop": (), "parse": "nmap",
#        "template": "nmap -sU -p $ports $IPs"},
#
#   Add a nikto web scan per host+port (needs a parser or use parse=None):
#       {"id": "nikto_ip", "tool": "nikto", "loop": ("ip","port"), "parse": None,
#        "template": "nikto -h $IPS:$ports"},
#
#   Add a different gobuster wordlist (per host+port):
#       {"id": "gobuster_ip_raft", "tool": "gobuster", "loop": ("ip","port"),
#        "parse": "gobuster",
#        "template": "gobuster dir -u $IPS:$ports -w /usr/share/wordlists/seclists/raft-large-directories.txt"},
#
# NOTE: reconsole is meant to run AS ROOT, so the privileged nmap presets
# (SYN scan -sS, -A, full range -p-) carry no `sudo` prefix.
# NOTE: gobuster fans out one task per port; that fan-out is capped at
# MAX_GOBUSTER_PORTS to avoid accidentally launching hundreds of tasks.
PRESETS = [
    {"id": "nmap_connect", "tool": "nmap", "loop": (), "parse": "nmap",
     "template": "nmap -sT $IPs"},
    {"id": "nmap_connect_ports", "tool": "nmap", "loop": (), "parse": "nmap",
     "template": "nmap -sT -p $ports $IPs"},
    {"id": "nmap_full", "tool": "nmap", "loop": (), "parse": "nmap",
     "template": "nmap -p- -Pn -v -sS -A -T4 $IPs"},
    {"id": "nmap_smb", "tool": "nmap", "loop": (), "parse": "nmap",
     "template": "nmap -p 139,445 --script=smb-os-discovery,smb-enum-shares,smb-enum-users $IPs"},

    {"id": "smbmap_null", "tool": "smbmap", "loop": ("ip",), "parse": "smbmap",
     "template": "smbmap -H $IPs -u null"},

    # gobuster against IP target(s) -- one run per (host, port)
    {"id": "gobuster_ip_common", "tool": "gobuster", "loop": ("ip", "port"), "parse": "gobuster",
     "template": "gobuster dir -u $IPS:$ports -w /usr/share/wordlists/dirb/common.txt"},
    {"id": "gobuster_ip_small", "tool": "gobuster", "loop": ("ip", "port"), "parse": "gobuster",
     "template": "gobuster dir -u $IPS:$ports -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"},
    {"id": "gobuster_ip_medium", "tool": "gobuster", "loop": ("ip", "port"), "parse": "gobuster",
     "template": "gobuster dir -u $IPS:$ports -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"},
    {"id": "gobuster_ip_medium_ext", "tool": "gobuster", "loop": ("ip", "port"), "parse": "gobuster",
     "template": "gobuster dir -u $IPS:$ports -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x pdf,txt"},
    {"id": "gobuster_ip_big", "tool": "gobuster", "loop": ("ip", "port"), "parse": "gobuster",
     "template": "gobuster dir -u $IPS:$ports -w /usr/share/wordlists/dirb/big.txt"},

    # gobuster against a single hostname -- one run per port
    {"id": "gobuster_host_common", "tool": "gobuster", "loop": ("port",), "parse": "gobuster",
     "template": "gobuster dir -u $hostname:$ports -w /usr/share/wordlists/dirb/common.txt"},
    {"id": "gobuster_host_medium", "tool": "gobuster", "loop": ("port",), "parse": "gobuster",
     "template": "gobuster dir -u $hostname:$ports -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"},
    {"id": "gobuster_host_medium_ext", "tool": "gobuster", "loop": ("port",), "parse": "gobuster",
     "template": "gobuster dir -u $hostname:$ports -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x pdf,txt"},
    {"id": "gobuster_host_big", "tool": "gobuster", "loop": ("port",), "parse": "gobuster",
     "template": "gobuster dir -u $hostname:$ports -w /usr/share/wordlists/dirb/big.txt"},
]
PRESET_BY_ID = {p["id"]: p for p in PRESETS}

# Human label for the GUI describing how a preset fans out into tasks.
LOOP_LABEL = {(): "", ("ip",): "per host", ("ip", "port"): "per host x port", ("port",): "per port"}


def template_vars(text: str) -> dict:
    """Which input variables a command string references."""
    return {
        "ips": ("$IPs" in text) or ("$IPS" in text),
        "ports": "$ports" in text,
        "hostname": "$hostname" in text,
    }


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def tools_status() -> dict:
    return {t: tool_available(t) for t in ("nmap", "smbmap", "gobuster")}


def is_root() -> bool:
    """True if running as root (so the privileged nmap presets will work)."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid() == 0 if geteuid else True


# ==========================================================================
# Input parsing / validation
# ==========================================================================
_META = set(";|&$`><\\\"'(){}[]!*?~")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$"
)


def parse_targets(raw: str) -> list:
    """
    Expand the target field into a de-duplicated, ordered list of IPv4 strings.

    Accepts comma-separated tokens, each of which may be:
        192.168.1.10                 single IP
        192.168.1.26-96              last-octet range
        192.168.1.10-192.168.1.40    full range
        192.168.1.0/24               CIDR
    """
    if any(ch in _META for ch in raw):
        raise ValueError("Target contains illegal characters")

    ips, seen = [], set()

    def push(ip_str):
        if ip_str not in seen:
            seen.add(ip_str)
            ips.append(ip_str)
            if len(ips) > MAX_HOSTS:
                raise ValueError(f"Target expands to more than {MAX_HOSTS} hosts")

    for token in (t.strip() for t in raw.split(",")):
        if not token:
            continue
        if "/" in token:                                   # CIDR
            for ip in ipaddress.ip_network(token, strict=False).hosts():
                push(str(ip))
        elif "-" in token:                                 # range
            left, right = (s.strip() for s in token.split("-", 1))
            start = ipaddress.ip_address(left)
            if right.isdigit():                            # last-octet form
                octets = left.split(".")
                octets[-1] = right
                end = ipaddress.ip_address(".".join(octets))
            else:                                          # full second IP
                end = ipaddress.ip_address(right)
            if int(end) < int(start):
                raise ValueError(f"Range end before start: {token}")
            for n in range(int(start), int(end) + 1):
                push(str(ipaddress.ip_address(n)))
        else:                                              # single IP
            push(str(ipaddress.ip_address(token)))

    if not ips:
        raise ValueError("No valid targets parsed")
    return ips


def parse_ports(raw: str):
    """
    Parse the port field. Accepts comma-separated single ports and a-b ranges,
    e.g. "80", "80,443", "8000-8005", "80,443,8000-8002".

    Returns (port_list, port_spec):
        port_list  expanded list of individual ints  -> gobuster fans out over these
        port_spec  cleaned original string           -> passed straight to nmap -p
                                                         (nmap accepts comma lists and
                                                          dash ranges in one command)
    """
    if any(ch in _META for ch in raw):
        raise ValueError("Ports contain illegal characters")

    ports, seen, tokens = [], set(), []

    def push(p):
        if not (1 <= p <= 65535):
            raise ValueError(f"Port out of range (1-65535): {p}")
        if p not in seen:
            seen.add(p)
            ports.append(p)

    for token in (t.strip() for t in raw.split(",")):
        if not token:
            continue
        tokens.append(token)
        if "-" in token:
            a_str, b_str = (s.strip() for s in token.split("-", 1))
            if not (a_str.isdigit() and b_str.isdigit()):
                raise ValueError(f"Invalid port range: {token}")
            a, b = int(a_str), int(b_str)
            if b < a:
                raise ValueError(f"Port range end before start: {token}")
            for p in range(a, b + 1):
                push(p)
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port: {token}")
            push(int(token))

    if not ports:
        raise ValueError("No valid ports parsed")
    return ports, ",".join(tokens)


def validate_hostname(raw: str) -> str:
    """Validate a SINGLE hostname for the $hostname variable. An optional
    http:// or https:// scheme is allowed and preserved (so it flows straight
    into gobuster's -u, e.g. https://target.local:$ports)."""
    h = raw.strip()
    if not h:
        raise ValueError("Empty hostname")
    if "," in h:
        raise ValueError("Only a single hostname is allowed")

    # Split off an optional scheme; validate only the host part.
    m = re.match(r"^(https?://)(.*)$", h, re.I)
    scheme, host = (m.group(1), m.group(2)) if m else ("", h)
    host = host.rstrip("/")

    if any(ch in _META for ch in host) or " " in host:
        raise ValueError("Hostname contains illegal characters")
    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"'{host}' is not a valid hostname")
    return scheme + host


def write_ip_file(scan_id: int, ips: list) -> str:
    """Write the expanded targets to IP.txt in the scan's working directory."""
    scan_dir = _run_dir(scan_id)
    path = os.path.join(scan_dir, "IP.txt")
    with open(path, "w") as f:
        f.write("\n".join(ips) + "\n")
    return path


# ==========================================================================
# Command building
# ==========================================================================
def _run_dir(scan_id: int) -> str:
    d = os.path.join(RUNS_DIR, f"scan_{scan_id}")
    os.makedirs(d, exist_ok=True)
    return d


def _substitute(template: str, ips, port_spec, hostname, ip_val=None, port_val=None,
                loop=()) -> str:
    """
    Fill the variables in a command template.

    For looped dimensions the single current value is used; otherwise the
    aggregate is used ($IPs -> the whole space-joined list, $ports -> the raw
    nmap-friendly spec).
    """
    ipsub = ip_val if ("ip" in loop and ip_val is not None) else " ".join(ips)
    portsub = str(port_val) if ("port" in loop and port_val is not None) else (port_spec or "")
    return (template.replace("$IPS", ipsub).replace("$IPs", ipsub)
                    .replace("$ports", portsub)
                    .replace("$hostname", hostname or ""))


def _ensure_scheme(cmd: str) -> str:
    """Prepend http:// to a gobuster -u value that lacks a scheme."""
    return re.sub(
        r"(-u\s+)(\S+)",
        lambda m: m.group(1) + (m.group(2) if "://" in m.group(2) else "http://" + m.group(2)),
        cmd,
    )


def _build_runs(preset, ips, ports, port_spec, hostname):
    """
    Yield (command_string, target_label, port_val) for a preset, fanning out
    over the preset's loop dimensions. target_label is the host the run is
    aimed at (ip or hostname), used to group results on the dashboard.
    """
    loop = preset["loop"]
    ip_space = ips if "ip" in loop else [None]
    port_space = ports if "port" in loop else [None]

    for ip_val in ip_space:
        for port_val in port_space:
            cmd = _substitute(preset["template"], ips, port_spec, hostname,
                              ip_val, port_val, loop)
            if preset["tool"] == "gobuster":
                cmd = _ensure_scheme(cmd)
            if "ip" in loop:
                target = ip_val
            elif "$hostname" in preset["template"]:
                target = hostname
            else:
                target = None
            yield cmd, target, port_val


# ==========================================================================
# Execution (live streaming + stoppable process group)
# ==========================================================================
def _execute(run_id: int, argv: list, output_path: str, timeout=None) -> str:
    """
    Run argv (no shell) and STREAM combined stdout+stderr into output_path,
    flushing after every line so the file can be opened and watched live while
    the scan is still running. stderr is merged into stdout so the file mirrors
    exactly what the tool prints in the terminal. stdin is closed so a prompt
    fails fast instead of hanging the worker.

    timeout=None (the default) disables the watchdog entirely: scans run for as
    long as they need. The process is started in its own session (process group)
    and registered in RUNNING_PROCS so it -- and any children it spawns -- can be
    stopped on demand or killed when the app shuts down.

    Returns the full captured text (used by the parsers). Raises RunStopped if
    the user stopped it, or TimeoutExpired if it exceeded a non-None timeout.
    """
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,     # mirror the CLI: one combined stream
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,                    # line-buffered
        start_new_session=True,       # own process group -> clean group kill
    )
    with _procs_lock:
        RUNNING_PROCS[run_id] = proc

    timed_out = {"flag": False}
    timer = None
    if timeout is not None:
        def _kill():
            timed_out["flag"] = True
            _terminate_group(proc, signal.SIGKILL)
        timer = threading.Timer(timeout, _kill)
        timer.start()

    captured = []
    try:
        with open(output_path, "a", buffering=1) as f:
            for line in proc.stdout:
                f.write(line)
                f.flush()
                captured.append(line)
        proc.wait()
    finally:
        if timer:
            timer.cancel()
        if proc.stdout:
            proc.stdout.close()
        with _procs_lock:
            RUNNING_PROCS.pop(run_id, None)
        stopped = run_id in STOP_REQUESTED

    if stopped:
        with open(output_path, "a") as f:
            f.write("\n--- stopped by user ---\n")
        raise RunStopped()
    if timed_out["flag"]:
        with open(output_path, "a") as f:
            f.write(f"\n--- killed after {timeout}s timeout ---\n")
        raise subprocess.TimeoutExpired(argv, timeout)
    return "".join(captured)


# ==========================================================================
# Output parsers
# ==========================================================================
def _parse_nmap_xml(scan_id, run_id, xml_path):
    if not os.path.exists(xml_path):
        return
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return
    for host_el in root.findall("host"):
        ip = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr"); break
        if not ip:
            continue
        for port_el in host_el.findall("ports/port"):
            st = port_el.find("state")
            state = st.get("state") if st is not None else "unknown"
            svc = port_el.find("service")
            service = svc.get("name") if svc is not None else None
            product = svc.get("product") if svc is not None else None
            version = svc.get("version") if svc is not None else None
            db.add_port(scan_id, run_id, ip, int(port_el.get("portid")),
                        port_el.get("protocol"), state, service, product, version)


def _parse_smbmap(scan_id, run_id, ip, output):
    """Extract share rows from smbmap output as findings."""
    text = _ANSI.sub("", output)
    in_block = False
    found = 0
    for line in text.splitlines():
        if "Disk" in line and "Permissions" in line:
            in_block = True
            continue
        if in_block:
            if not line.strip() or line.strip().startswith("---"):
                continue
            if line.strip().startswith("[") or "Permissions" in line:
                in_block = False
                continue
            parts = line.split()
            if parts:
                share = parts[0]
                perm = " ".join(parts[1:3]) if len(parts) > 1 else ""
                db.add_finding(scan_id, run_id, "smbmap", ip, share, perm)
                found += 1
    if found == 0:
        snippet = next((l.strip() for l in text.splitlines()
                        if l.strip() and ("[" in l or "error" in l.lower())), "No shares listed")
        db.add_finding(scan_id, run_id, "smbmap", ip, "No accessible shares", snippet[:300])


def _parse_gobuster(scan_id, run_id, ip, output, port=None):
    """Parse gobuster paths as findings; note the port since a host may be
    scanned on several ports (each its own run)."""
    text = _ANSI.sub("", output)
    found = 0
    for line in text.splitlines():
        m = _GOBUSTER_LINE.search(line.strip())
        if m:
            detail = f"Status {m.group('status')}"
            if m.group("size"):
                detail += f", {m.group('size')} bytes"
            if port:
                detail += f" - port {port}"
            db.add_finding(scan_id, run_id, "gobuster", ip, m.group("path"), detail)
            found += 1
    if found == 0:
        db.add_finding(scan_id, run_id, "gobuster", ip, "No paths discovered",
                       f"port {port}" if port else None)


# ==========================================================================
# Job runner (called by the worker thread)
# ==========================================================================
def run_job(scan_id, preset_ids, custom_cmd, ips, ports, port_spec, hostname):
    # Build the full plan up front, create every run row as 'queued' so the whole
    # scan is visible immediately, then execute the runnable tasks concurrently
    # (up to MAX_CONCURRENCY) so a slow nmap no longer blocks smbmap / gobuster.
    scan_dir = _run_dir(scan_id)
    if ips:
        write_ip_file(scan_id, ips)

    planned = []

    # --- expand presets into planned runs ---
    for pid in preset_ids:
        preset = PRESET_BY_ID.get(pid)
        if not preset:
            continue
        if not tool_available(preset["tool"]):
            planned.append({
                "kind": "error", "tool": preset["tool"], "fname": preset["tool"],
                "cmd": _substitute(preset["template"], ips, port_spec, hostname, loop=preset["loop"]),
                "message": f"{preset['tool']} is not installed on this host.",
            })
            continue
        if "port" in preset["loop"] and len(ports) > MAX_GOBUSTER_PORTS:
            planned.append({
                "kind": "error", "tool": preset["tool"], "fname": preset["tool"],
                "cmd": _substitute(preset["template"], ips, port_spec, hostname, loop=preset["loop"]),
                "message": (f"{len(ports)} ports selected; gobuster runs one request per port "
                            f"and is capped at {MAX_GOBUSTER_PORTS}. Narrow the port list."),
            })
            continue
        for cmd_str, target, port_val in _build_runs(preset, ips, ports, port_spec, hostname):
            planned.append({
                "kind": "run", "tool": preset["tool"], "parse": preset["parse"], "fname": preset["tool"],
                "cmd": cmd_str, "target": target, "port": port_val,
            })

    # --- custom command (single run over all targets) ---
    if custom_cmd and custom_cmd.strip():
        cmd_str = _substitute(custom_cmd.strip(), ips, port_spec, hostname)
        parts = shlex.split(cmd_str)
        tool = parts[0] if parts else "custom"
        if tool == "sudo" and len(parts) > 1:
            tool = parts[1]
        planned.append({
            "kind": "run", "tool": tool, "parse": None, "fname": "custom",
            "cmd": cmd_str, "target": None, "port": None,
        })

    # --- create every row as 'queued' and open its output file with the header ---
    for pr in planned:
        rid = db.create_run(scan_id, pr["tool"], pr["cmd"], pr.get("target"), status="queued")
        pr["rid"] = rid
        out_path = os.path.join(scan_dir, f"run_{rid}_{pr['fname']}.txt")
        db.set_run_output(rid, out_path)
        with open(out_path, "w", buffering=1) as f:
            f.write(f"$ {pr['cmd']}\n\n")
            f.flush()
        pr["out_path"] = out_path

    # --- resolve error rows immediately ---
    for pr in planned:
        if pr["kind"] == "error":
            with open(pr["out_path"], "a") as f:
                f.write(pr["message"] + "\n")
            db.finish_run(pr["rid"], "error", error=pr["message"])

    runnable = [pr for pr in planned if pr["kind"] == "run"]

    def _do(pr):
        rid = pr["rid"]
        if scan_id in CANCELLED_SCANS:
            db.finish_run(rid, "stopped")
            return
        db.set_run_status(rid, "running")
        argv = shlex.split(pr["cmd"])
        xml_path = os.path.join(scan_dir, f"run_{rid}.xml")
        if pr["parse"] == "nmap":
            argv += ["-oX", xml_path]
        try:
            output = _execute(rid, argv, pr["out_path"], None)   # no timeout for any tool
            if pr["parse"] == "nmap":
                _parse_nmap_xml(scan_id, rid, xml_path)
            elif pr["parse"] == "smbmap":
                _parse_smbmap(scan_id, rid, pr["target"], output)
            elif pr["parse"] == "gobuster":
                _parse_gobuster(scan_id, rid, pr["target"], output, pr["port"])
            db.finish_run(rid, "completed")
        except RunStopped:
            db.finish_run(rid, "stopped")
        except Exception as e:                                   # noqa: BLE001
            db.finish_run(rid, "error", error=str(e))
        finally:
            STOP_REQUESTED.discard(rid)

    try:
        if runnable:
            with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as ex:
                list(ex.map(_do, runnable))
        db.set_scan_status(scan_id, "stopped" if scan_id in CANCELLED_SCANS else "completed")
    except Exception:                                            # noqa: BLE001
        db.set_scan_status(scan_id, "error")
        raise
    finally:
        CANCELLED_SCANS.discard(scan_id)
