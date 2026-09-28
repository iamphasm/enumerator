#!/usr/bin/env python3
"""vscan - enumerate services with nmap and nikto and flag outdated software.

    python3 vscan.py <ip-or-hostname> [options]

1. Runs `nmap -sV <target>` and parses every detected product and version.
2. Runs `nikto -h <target>` against each web port nmap found and parses the
   Server / X-Powered-By banners and nikto's own "outdated" notes.
3. Strips each product down to a software name, looks it up in the local
   database (data/software.db, see swdb.py) and fetches the current release
   versions from the URL stored there.
4. Writes a report to scans/<date_time>.scan.
5. If the target is this machine, also writes scans/<date_time>_update.sh,
   a script that upgrades the outdated packages and restarts their services.

Only scan hosts you own or are authorised to test.
"""
import argparse
import ipaddress
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

import swdb

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(BASE_DIR, "scans")

# Status labels, worst first (used for sorting and the summary).
OUTDATED, OLD_BRANCH, LOOKUP_FAILED, UNKNOWN, NOT_IN_DB, UP_TO_DATE = (
    "OUTDATED", "OLD BRANCH", "LOOKUP FAILED", "NO VERSION", "NOT IN DB", "UP-TO-DATE")
STATUS_ORDER = [OUTDATED, OLD_BRANCH, LOOKUP_FAILED, UNKNOWN, NOT_IN_DB, UP_TO_DATE]

# Banner products that would be mis-matched to something else in the database.
IGNORED_PRODUCTS = {"apache-coyote"}
DISTRO_HINT = re.compile(r"ubuntu|debian|deb\d|\.el\d|fc\d|centos|red ?hat|suse|alpine", re.I)


def log(msg):
    print(f"[vscan] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Target handling
# --------------------------------------------------------------------------
def validate_target(target):
    """Allow only an IP address or a hostname, so nothing can be injected as an option."""
    if target.startswith("-"):
        raise ValueError("target must not start with '-'")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?", target):
        return target
    raise ValueError(f"not a valid IP address or hostname: {target!r}")


def is_local_target(target):
    """True if the target resolves to an address that belongs to this machine."""
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror:
        return False
    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        try:
            if ipaddress.ip_address(addr.split("%")[0]).is_loopback:
                return True
        except ValueError:
            continue
        try:  # binding only succeeds for an address assigned to a local interface
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.bind((addr, 0))
            return True
        except OSError:
            pass
    return False


# --------------------------------------------------------------------------
# Running the tools
# --------------------------------------------------------------------------
def run_tool(cmd, timeout=None):
    log("running: " + " ".join(shlex.quote(c) for c in cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return -1, out, f"timed out after {timeout}s"


def run_nmap(target, extra_args, timeout):
    cmd = ["nmap", "-sV", *extra_args, "-oX", "-", target]
    return cmd, *run_tool(cmd, timeout)


def run_nikto(target, ports, maxtime, timeout):
    cmd = ["nikto", "-h", target, "-nointeractive"]
    if ports:
        cmd += ["-p", ",".join(str(p) for p in ports)]
    if maxtime:
        cmd += ["-maxtime", maxtime]
    return cmd, *run_tool(cmd, timeout)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------
def parse_nmap(xml_text):
    """Return (list of open-port dicts, host state string)."""
    services, state = [], "unknown"
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return services, "nmap output could not be parsed"
    for host in root.findall("host"):
        st = host.find("status")
        if st is not None:
            state = st.get("state", state)
        for port in host.findall("./ports/port"):
            pstate = port.find("state")
            if pstate is None or pstate.get("state") != "open":
                continue
            svc = port.find("service")
            svc = svc if svc is not None else ET.Element("service")
            services.append({
                "port": int(port.get("portid")),
                "proto": port.get("protocol", "tcp"),
                "service": svc.get("name", "unknown"),
                "tunnel": svc.get("tunnel", ""),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "extrainfo": svc.get("extrainfo", ""),
                "cpes": [c.text for c in svc.findall("cpe") if c.text],
            })
    hosts = root.find("./runstats/hosts")
    if root.find("host") is None and hosts is not None and hosts.get("up") == "0":
        state = "down (no reply to host discovery; if the host is up, retry with --nmap-args -Pn)"
    return services, state


def web_ports(services):
    return sorted({s["port"] for s in services
                   if s["proto"] == "tcp" and ("http" in s["service"] or s["tunnel"] == "ssl"
                                               and s["service"] in ("https", "http", "ssl"))})


_BANNER_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.+\-]*?)/(\d[\w.\-]*)")


def parse_nikto(text):
    """Return list of findings: {port, product, version, nikto_current}."""
    findings, port = [], None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"\+ Target Port:\s*(\d+)", line)
        if m:
            port = int(m.group(1))
            continue
        m = re.match(r"\+ Server:\s*(.+)", line)
        if m and "No banner retrieved" not in line:
            for prod, ver in _BANNER_TOKEN.findall(m.group(1)):
                findings.append({"port": port, "product": prod, "version": ver.rstrip("."),
                                 "nikto_current": None})
            continue
        m = re.search(r"(x-powered-by|x-aspnet-version|x-aspnetmvc-version)\s+header:\s*(.+)", line, re.I)
        if m:
            header_val = m.group(2).strip().rstrip(".")
            toks = _BANNER_TOKEN.findall(header_val)
            if not toks and m.group(1).lower() != "x-powered-by":
                toks = [("ASP.NET", header_val)]
            for prod, ver in toks:
                findings.append({"port": port, "product": prod, "version": ver.rstrip("."),
                                 "nikto_current": None})
            continue
        m = re.search(r"\]?\s*(\S+?)/(\d[\w.\-]*) appears to be outdated \(current is at least ([^)]+)\)", line)
        if m:
            findings.append({"port": port, "product": m.group(1).split()[-1], "version": m.group(2),
                             "nikto_current": m.group(3).strip()})
    return findings


# --------------------------------------------------------------------------
# Merge and evaluate
# --------------------------------------------------------------------------
_EXTRA_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.+\-]*)[ /](\d+(?:\.\d+)+[a-z]?(?:p\d+)?)")


def normalise(product, version):
    """Special cases where the real product hides in the version string."""
    m = re.search(r"(\d+\.\d+\.\d+)-MariaDB", version or "", re.I)
    if m:
        return "MariaDB", m.group(1)
    return product, version


def split_cpe(cpe):
    """'cpe:/a:apache:http_server:2.4.41' -> ('apache:http_server', '2.4.41' or '')."""
    parts = cpe.split(":")
    if len(parts) < 4:
        return None, ""
    return f"{parts[2]}:{parts[3]}".lower(), (parts[4] if len(parts) > 4 else "")


def collect_findings(nmap_services, nikto_findings, matcher):
    merged, order = {}, []

    def add(port, proto, service, product, version, source, cpes=(), entry=None,
            nikto_current=None, extrainfo=""):
        hint = f"{version} {extrainfo} {' '.join(cpes)}"
        product, version = normalise(product, version)
        if entry is None and product and product.lower() not in IGNORED_PRODUCTS:
            entry = matcher.match(product)
        name = entry["name"] if entry else (product.lower() or f"({service})")
        key = (port, name)
        if key not in merged:
            merged[key] = {"port": port, "proto": proto, "service": service, "product": product,
                           "raw_version": version, "cpes": list(cpes), "entry": entry, "name": name,
                           "sources": [], "nikto_current": None, "hint": ""}
            order.append(key)
        f = merged[key]
        f["hint"] += " " + hint
        if source not in f["sources"]:
            f["sources"].append(source)
        # keep the most specific version string
        if version and len(swdb.parse_version(version) or ()) > len(swdb.parse_version(f["raw_version"]) or ()):
            f["raw_version"] = version
        if nikto_current:
            f["nikto_current"] = nikto_current

    for s in nmap_services:
        product, version = normalise(s["product"], s["version"])
        primary = matcher.match(product) if product and product.lower() not in IGNORED_PRODUCTS else None
        extra = []   # (product, version, entry) for other software nmap reported on this port
        for cpe in s["cpes"]:
            vp, cver = split_cpe(cpe)
            e = matcher.match_cpe(vp) if vp else None
            if not e or (primary and e["name"] == primary["name"]):
                continue
            same_as_product = (not primary and (not cver or not version or
                               swdb.clean_version(cver) == swdb.clean_version(version)))
            if same_as_product and product:
                primary = e          # product name not in the aliases, but its CPE is
            else:
                extra.append((vp.split(":")[1], cver, e))
        # nmap often puts bundled software in extrainfo, e.g. "(Python 3.13.15)" or "PHP 7.4.3"
        for prod, ver in _EXTRA_TOKEN.findall(s["extrainfo"]):
            e = matcher.match(prod) if prod.lower() not in IGNORED_PRODUCTS else None
            if e and not (primary and e["name"] == primary["name"]):
                extra.append((prod, ver, e))
        add(s["port"], s["proto"], s["service"], s["product"], s["version"], "nmap",
            cpes=s["cpes"], entry=primary, extrainfo=s["extrainfo"])
        for prod, ver, e in extra:
            add(s["port"], s["proto"], s["service"], prod, ver, "nmap", entry=e)
    for n in nikto_findings:
        add(n["port"], "tcp", "http", n["product"], n["version"], "nikto",
            nikto_current=n["nikto_current"])
    return [merged[k] for k in order]


def evaluate(findings, conn, refresh=False):
    for f in findings:
        entry, raw = f["entry"], f["raw_version"]
        f["installed"] = swdb.clean_version(raw) if raw else None
        f["latest"] = f["newest"] = None
        f["notes"] = []
        if DISTRO_HINT.search(f["hint"]):
            f["notes"].append("distro build: security fixes may be backported without a version bump")
        if f["nikto_current"]:
            f["notes"].append(f"nikto says current is at least {f['nikto_current']}")
        if entry is None:
            f["status"] = NOT_IN_DB
            continue
        if entry["notes"]:
            f["notes"].append(entry["notes"])
        try:
            versions = swdb.release_versions(conn, entry, refresh=refresh)
        except Exception as exc:
            f["status"] = LOOKUP_FAILED
            f["notes"].append(str(exc))
            continue
        f["latest"], f["newest"] = swdb.pick_latest(f["installed"], versions, entry["branch_depth"])
        if not f["installed"]:
            f["status"] = UNKNOWN
            continue
        if swdb.compare_versions(f["installed"], f["latest"]) < 0:
            f["status"] = OUTDATED
        elif swdb.compare_versions(f["installed"], f["newest"]) < 0:
            f["status"] = OLD_BRANCH
            f["notes"].append(f"latest in this branch, but {f['newest']} is the newest release")
        else:
            f["status"] = UP_TO_DATE
    findings.sort(key=lambda f: (STATUS_ORDER.index(f["status"]), f["port"] or 0, f["name"]))
    return findings


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def format_table(rows, headers):
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*(str(c) for c in r)) for r in rows]
    return "\n".join(lines)


def build_report(ctx, findings):
    counts = {s: sum(1 for f in findings if f["status"] == s) for s in STATUS_ORDER}
    out = [
        "VSCAN REPORT",
        "=" * 78,
        f"Target        : {ctx['target']}",
        f"Host state    : {ctx['host_state']}",
        f"Scan started  : {ctx['started']:%Y-%m-%d %H:%M:%S}",
        f"Scan finished : {ctx['finished']:%Y-%m-%d %H:%M:%S}",
        f"Local target  : {'yes' if ctx['local'] else 'no'}",
        f"nmap command  : {ctx['nmap_cmd']}",
        f"nikto command : {ctx['nikto_cmd']}",
        "",
        "SUMMARY: " + ", ".join(f"{counts[s]} {s.lower()}" for s in STATUS_ORDER if counts[s]),
        "",
    ]
    if findings:
        rows = [(f"{f['port']}/{f['proto']}" if f["port"] else "-", f["service"], f["name"],
                 f["product"] or "-", f["installed"] or "?", f["latest"] or "-", f["status"],
                 "+".join(f["sources"])) for f in findings]
        out.append(format_table(rows, ("PORT", "SERVICE", "SOFTWARE", "DETECTED AS",
                                       "INSTALLED", "LATEST", "STATUS", "SOURCE")))
        noted = [f for f in findings if f["notes"]]
        if noted:
            out += ["", "NOTES"]
            for f in noted:
                for n in f["notes"]:
                    out.append(f"  {f['name']} ({f['port']}/{f['proto']}): {n}")
    else:
        out.append("No services with product information were found.")
    if counts[NOT_IN_DB]:
        out += ["", "Software marked NOT IN DB can be added to the database with:",
                "  python3 swdb.py add <name> --url <releases page> --regex '<one version group>' --alias <nmap name>"]
    if ctx.get("update_script"):
        out += ["", f"Update script : {ctx['update_script']}"]
    elif ctx.get("update_note"):
        out += ["", f"Update script : {ctx['update_note']}"]
    if ctx["warnings"]:
        out += ["", "WARNINGS"] + [f"  {w}" for w in ctx["warnings"]]
    return "\n".join(out) + "\n"


def build_update_script(ctx, findings):
    """Bash script that upgrades outdated packages on this machine."""
    todo = [f for f in findings if f["status"] in (OUTDATED, OLD_BRANCH) and f["entry"]]
    seen, pkg_entries, manual = set(), [], []
    for f in todo:
        e = f["entry"]
        if e["name"] in seen:
            continue
        seen.add(e["name"])
        (pkg_entries if e["packages"] else manual).append((e, f))
    if not seen:
        return None

    def pkg_list(pm):
        pkgs = []
        for e, _ in pkg_entries:
            for p in e["packages"].get(pm, []):
                if p not in pkgs:
                    pkgs.append(p)
        return " ".join(shlex.quote(p) for p in pkgs)

    units = []
    for e, _ in pkg_entries:
        for u in e["services"]:
            if u not in units:
                units.append(u)
    summary = "\n".join(f"#   {e['name']:16} {f['installed'] or '?':>12} -> {f['latest']}"
                        for e, f in pkg_entries + manual)
    manual_lines = "\n".join(
        f'echo "  - {e["name"]}: installed {f["installed"]}, latest {f["latest"]}. '
        f'No package mapping; update manually. Releases: {e["url"]}"'
        for e, f in manual) or 'echo "  (none)"'
    yum_pkgs = pkg_list("dnf")

    return f"""#!/usr/bin/env bash
# Generated by vscan on {ctx['started']:%Y-%m-%d %H:%M:%S} for target {ctx['target']}.
# Upgrades the packages that provide the software vscan found outdated:
{summary}
#
# Distro repositories often lag upstream. This script installs the newest
# version your package manager offers, which may still be older than "latest".
#
# Usage: sudo ./{os.path.basename(ctx['update_script'])} [--dry-run] [--yes]
set -euo pipefail

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

run() {{
  echo "+ $*"
  if [[ $DRY_RUN -eq 0 ]]; then "$@"; fi
}}

if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then
  echo "This script must be run as root (or use --dry-run)." >&2
  exit 1
fi

if   command -v apt-get >/dev/null 2>&1; then PM=apt;    PKGS=({pkg_list('apt')})
elif command -v dnf     >/dev/null 2>&1; then PM=dnf;    PKGS=({yum_pkgs})
elif command -v yum     >/dev/null 2>&1; then PM=yum;    PKGS=({yum_pkgs})
elif command -v pacman  >/dev/null 2>&1; then PM=pacman; PKGS=({pkg_list('pacman')})
elif command -v zypper  >/dev/null 2>&1; then PM=zypper; PKGS=({pkg_list('zypper')})
elif command -v apk     >/dev/null 2>&1; then PM=apk;    PKGS=({pkg_list('apk')})
else echo "No supported package manager found." >&2; exit 1
fi

is_installed() {{
  case "$PM" in
    apt)        dpkg-query -W -f='${{Status}}' "$1" 2>/dev/null | grep -q "install ok installed" ;;
    dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
    pacman)     pacman -Q "$1" >/dev/null 2>&1 ;;
    apk)        apk info -e "$1" >/dev/null 2>&1 ;;
  esac
}}

# Only upgrade packages that are actually installed; never install new ones.
INSTALLED=()
for p in "${{PKGS[@]}}"; do
  if is_installed "$p"; then INSTALLED+=("$p"); else echo "skip: $p is not installed via $PM"; fi
done

echo "Package manager : $PM"
echo "Will upgrade    : ${{INSTALLED[*]:-(nothing)}}"

if [[ ${{#INSTALLED[@]}} -gt 0 ]]; then
  if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
    read -r -p "Proceed? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || {{ echo "Aborted."; exit 0; }}
  fi
  case "$PM" in
    apt)    run apt-get update
            run env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "${{INSTALLED[@]}}" ;;
    dnf)    run dnf upgrade -y "${{INSTALLED[@]}}" ;;
    yum)    run yum update -y "${{INSTALLED[@]}}" ;;
    pacman) echo "Arch does not support partial upgrades; running a full system upgrade."
            run pacman -Syu --noconfirm ;;
    zypper) run zypper --non-interactive refresh
            run zypper --non-interactive update "${{INSTALLED[@]}}" ;;
    apk)    run apk update
            run apk upgrade "${{INSTALLED[@]}}" ;;
  esac

  # Restart affected services that are currently running.
  if command -v systemctl >/dev/null 2>&1; then
    for unit in {' '.join(shlex.quote(u) for u in units)}; do
      if systemctl list-unit-files "$unit.service" >/dev/null 2>&1 && systemctl is-active --quiet "$unit"; then
        run systemctl try-restart "$unit"
      fi
    done
  fi
fi

echo
echo "Software that needs a manual update:"
{manual_lines}
echo
echo "Done. Run vscan again to confirm the new versions."
"""


def timestamp_path(out_dir, started, suffix):
    base = os.path.join(out_dir, f"{started:%Y-%m-%d_%H-%M-%S}{suffix}")
    path, n = base, 1
    while os.path.exists(path):
        path = base.replace(suffix, f"_{n}{suffix}")
        n += 1
    return path


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Enumerate services with nmap + nikto and flag outdated software.")
    ap.add_argument("target", help="IP address or hostname to scan")
    ap.add_argument("--nmap-args", default="", help='extra nmap arguments, e.g. "-p- -T4 -Pn"')
    ap.add_argument("--nmap-timeout", type=int, default=None, help="seconds before nmap is killed")
    ap.add_argument("--no-nikto", action="store_true", help="skip the nikto web scan")
    ap.add_argument("--nikto-all", action="store_true",
                    help="run nikto on its default port even if nmap found no web ports")
    ap.add_argument("--nikto-maxtime", default=None, help="nikto -maxtime value per host, e.g. 10m")
    ap.add_argument("--nikto-timeout", type=int, default=None, help="seconds before nikto is killed")
    ap.add_argument("--refresh", action="store_true", help="ignore cached release versions")
    ap.add_argument("--out-dir", default=DEFAULT_OUT, help="where to write reports (default: scans/)")
    loc = ap.add_mutually_exclusive_group()
    loc.add_argument("--local", action="store_true", help="treat the target as this machine")
    loc.add_argument("--remote", action="store_true", help="never generate an update script")
    args = ap.parse_args()

    try:
        target = validate_target(args.target)
    except ValueError as exc:
        ap.error(str(exc))
    for tool in ("nmap",) + (() if args.no_nikto else ("nikto",)):
        if not shutil.which(tool):
            sys.exit(f"{tool} is not installed or not on PATH")

    os.makedirs(args.out_dir, exist_ok=True)
    conn = swdb.connect()
    matcher = swdb.Matcher(conn)
    started = datetime.now()
    ctx = {"target": target, "started": started, "warnings": [],
           "local": args.local or (not args.remote and is_local_target(target))}

    nmap_cmd, rc, nmap_xml, nmap_err = run_nmap(target, shlex.split(args.nmap_args), args.nmap_timeout)
    ctx["nmap_cmd"] = " ".join(shlex.quote(c) for c in nmap_cmd)
    if rc != 0:
        ctx["warnings"].append(f"nmap exited with {rc}: {nmap_err.strip()[:500]}")
    services, ctx["host_state"] = parse_nmap(nmap_xml)
    log(f"nmap found {len(services)} open port(s)")

    nikto_out, nikto_findings = "", []
    ports = web_ports(services)
    if args.no_nikto:
        ctx["nikto_cmd"] = "(skipped: --no-nikto)"
    elif not ports and not args.nikto_all:
        ctx["nikto_cmd"] = "(skipped: nmap found no web ports; use --nikto-all to force)"
    else:
        cmd, rc, nikto_out, nikto_err = run_nikto(target, ports, args.nikto_maxtime, args.nikto_timeout)
        ctx["nikto_cmd"] = " ".join(shlex.quote(c) for c in cmd)
        if rc not in (0, 1) or not nikto_out.strip():
            ctx["warnings"].append(f"nikto exited with {rc}: {nikto_err.strip()[:500]}")
        nikto_findings = parse_nikto(nikto_out)
        log(f"nikto reported {len(nikto_findings)} software banner(s)")

    log("looking up current versions")
    findings = evaluate(collect_findings(services, nikto_findings, matcher), conn, refresh=args.refresh)
    ctx["finished"] = datetime.now()

    if ctx["local"]:
        ctx["update_script"] = timestamp_path(args.out_dir, started, "_update.sh")
        script = build_update_script(ctx, findings)
        if script:
            with open(ctx["update_script"], "w", encoding="utf-8") as fh:
                fh.write(script)
            os.chmod(ctx["update_script"], 0o755)
        else:
            ctx["update_script"] = None
            ctx["update_note"] = "not written, nothing outdated"
    else:
        ctx["update_note"] = "not written, target is a remote host"

    report = build_report(ctx, findings)
    scan_path = timestamp_path(args.out_dir, started, ".scan")
    with open(scan_path, "w", encoding="utf-8") as fh:
        fh.write(report)
        fh.write("\n\n" + "=" * 78 + "\nRAW NMAP OUTPUT (XML)\n" + "=" * 78 + "\n" + nmap_xml)
        if nikto_out:
            fh.write("\n\n" + "=" * 78 + "\nRAW NIKTO OUTPUT\n" + "=" * 78 + "\n" + nikto_out)
    print(report)
    log(f"report written to {scan_path}")
    if ctx.get("update_script"):
        log(f"update script written to {ctx['update_script']} (review it, then run with sudo)")
    return 1 if any(f["status"] == OUTDATED for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
