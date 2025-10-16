#!/usr/bin/env python3
"""
robust_nmap_scanner.py

Requirements:
 - nmap (the Nmap binary) installed and in PATH
 - python-nmap package: pip install python-nmap

Usage examples:
  python robust_nmap_scanner.py --target 192.168.1.0/24 --scan-type syn --ports 1-1024
  python robust_nmap_scanner.py --target example.com --scan-type version --save results.json
  python robust_nmap_scanner.py --target 203.0.113.5 --scan-type idle --zombie 198.51.100.23

Only scan hosts you own or have explicit permission to test.
"""

import argparse
import json
import sys
import time
from datetime import datetime

try:
    import nmap
except ModuleNotFoundError:
    print("ERROR: python-nmap is not installed. Run: python -m pip install python-nmap")
    sys.exit(1)


SCAN_PRESETS = {
    "connect": {"args": "-sT"},       # TCP connect scan
    "syn": {"args": "-sS"},           # SYN stealth scan (requires root on many systems)
    "udp": {"args": "-sU"},           # UDP scan (slow)
    "version": {"args": "-sV -sC"},   # service/version detection + default scripts
    "os": {"args": "-O -sV -sC"},     # OS detection + version and scripts
    "all": {"args": "-sS -sU -sV -O -sC"},  # aggressive combined scan
    # idle (zombie) is special: requires a zombie host IP -> -sI <zombie>
    "idle": {"args": "-sI"},
}


def build_nmap_args(scan_type: str, ports: str = None, zombie: str = None) -> str:
    preset = SCAN_PRESETS.get(scan_type)
    if not preset:
        raise ValueError(f"Unknown scan type: {scan_type}")

    args = preset["args"]

    # handle idle (zombie) scan requiring zombie host
    if scan_type == "idle":
        if not zombie:
            raise ValueError("Idle scan requires --zombie <zombie_ip>")
        # nmap expects "-sI <zombie_ip>"
        args = f"-sI {zombie} -sV -sC"  # include version + default scripts optionally

    if ports:
        args += f" -p {ports}"

    # safe defaults: provide timing option if user wants faster or slower
    return args


def run_scan(target: str, nmap_args: str, timeout: int = 0):
    """
    Runs nmap scan using python-nmap PortScanner.
    If timeout>0, python-nmap will not necessarily enforce a hard timeout; nmap has its own timing flags.
    Returns the PortScanner object (with results) on success.
    """
    nm = nmap.PortScanner()
    print(f"[+] Running nmap on {target} with arguments: {nmap_args}")
    start = time.time()
    try:
        # python-nmap's scan method: nm.scan(hosts=target, arguments=nmap_args)
        nm.scan(hosts=target, arguments=nmap_args)
    except nmap.PortScannerError as e:
        print(f"[!] nmap error: {e}")
        raise
    except Exception as e:
        print(f"[!] Unexpected error while scanning: {e}")
        raise
    elapsed = time.time() - start
    print(f"[+] Scan finished in {elapsed:.1f}s")
    return nm


def summarize_results(nm: nmap.PortScanner) -> dict:
    data = {"scanned_at": datetime.utcnow().isoformat() + "Z", "hosts": []}
    for host in nm.all_hosts():
        host_entry = {
            "host": host,
            "hostname": nm[host].hostname() if nm[host].hostname() else "",
            "state": nm[host].state(),
            "protocols": {},
        }

        for proto in nm[host].all_protocols():
            proto_info = {}
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                port_data = nm[host][proto][port]
                # port_data is usually a dict with keys like 'state','name','product','version','extrainfo','reason','conf'
                proto_info[port] = port_data
            host_entry["protocols"][proto] = proto_info

        # OS detection info (if present)
        if "osmatch" in nm[host]:
            host_entry["os"] = nm[host]["osmatch"]

        data["hosts"].append(host_entry)
    return data


def save_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    print(f"[+] Results saved to {path}")


def print_human_summary(summary: dict):
    print("\n=== Scan Summary ===")
    for h in summary["hosts"]:
        print(f"Host: {h['host']} ({h.get('hostname','')}) - {h['state']}")
        for proto, ports in h["protocols"].items():
            if not ports:
                print(f"  Protocol: {proto} - no open ports found or not scanned")
                continue
            print(f"  Protocol: {proto}")
            for port, info in ports.items():
                # gracefully handle possible missing fields
                state = info.get("state", "unknown")
                name = info.get("name", "")
                service = info.get("product", "")
                version = info.get("version", "")
                print(f"    {port:5} {state:7} {name} {service} {version}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Robust Nmap Scanner (use responsibly)."
    )
    parser.add_argument("--target", "-t", required=True, help="Target IP, CIDR or hostname")
    parser.add_argument("--scan-type", "-s", choices=SCAN_PRESETS.keys(), default="version",
                        help="Scan type: " + ", ".join(SCAN_PRESETS.keys()))
    parser.add_argument("--ports", "-p", help="Port range, e.g. 1-1024 or 22,80,443")
    parser.add_argument("--zombie", "-z", help="Zombie host IP for idle (-sI) scan")
    parser.add_argument("--save", "-o", help="Save results to JSON file (e.g. results.json)")
    parser.add_argument("--show", action="store_true", help="Show human-readable summary")
    parser.add_argument("--force", action="store_true", help="Skip the authorization reminder and proceed")
    return parser.parse_args()


def main():
    args = parse_args()

    warning = (
        "WARNING: Make sure you have explicit permission to scan the target(s). "
        "Unauthorized scanning can be illegal or disruptive."
    )
    if not args.force:
        print(warning)
        resp = input("Type 'YES' to confirm you have permission to scan the target(s): ")
        if resp.strip().upper() != "YES":
            print("Aborting. Run with --force to skip this interactive check (only if you truly have permission).")
            sys.exit(1)
    else:
        print("[!] --force used: skipping permission prompt. Make sure you are authorized.")

    try:
        nmap_args = build_nmap_args(args.scan_type, ports=args.ports, zombie=args.zombie)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    try:
        nm = run_scan(args.target, nmap_args)
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        sys.exit(1)

    summary = summarize_results(nm)

    if args.show:
        print_human_summary(summary)

    if args.save:
        save_json(summary, args.save)
    else:
        # if not saved, print a short summary
        host_count = len(summary["hosts"])
        print(f"\n[+] Scan complete. Hosts found: {host_count}. Use --save to write detailed JSON output.")


if __name__ == "__main__":
    main()

