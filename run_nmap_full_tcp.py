#!/usr/bin/env python3
"""
run_nmap_full_tcp.py (improved)
- Ensures we call a real executable (nmap.exe) and avoid launching stray nmap.py files.
- Prompts for target if not provided.
- Runs: nmap -Pn -sT -p- <target>
"""
import argparse
import ipaddress
import os
import shutil
import subprocess
import sys

COMMON_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]

def find_nmap_executable():
    # 1) Try shutil.which for nmap.exe first (prefer executable)
    exe = shutil.which("nmap.exe")
    if exe:
        return exe

    # 2) Fallback to searching for any PATH entry that is an executable (honor PATHEXT)
    pathext = os.environ.get("PATHEXT", ".EXE;.BAT;.CMD;.COM").split(";")
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for d in path_dirs:
        if not d:
            continue
        for ext in pathext:
            candidate = os.path.join(d, "nmap" + ext.lower())
            if os.path.isfile(candidate):
                return candidate
            # also try uppercase ext
            candidate2 = os.path.join(d, "nmap" + ext.upper())
            if os.path.isfile(candidate2):
                return candidate2

    # 3) Try common install locations
    for p in COMMON_NMAP_PATHS:
        if os.path.isfile(p):
            return p

    # 4) As a last resort, shutil.which("nmap") (may return a .py or other)
    fallback = shutil.which("nmap")
    if fallback and os.path.isfile(fallback):
        # still prefer only if executable extension
        _, ext = os.path.splitext(fallback)
        if ext.lower() in [".exe", ".bat", ".cmd", ".com"]:
            return fallback

    return None

def validate_ip_or_hostname(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Empty target")
    try:
        ipaddress.ip_address(value)
        return value
    except Exception:
        # Basic hostname sanity check
        import re
        if len(value) > 255:
            raise ValueError("Hostname too long")
        if not re.match(r'^[A-Za-z0-9\.\-]+$', value):
            raise ValueError("Hostname contains invalid characters")
        return value

def prompt_for_target():
    try:
        while True:
            target = input("Enter IP address or hostname to scan: ").strip()
            try:
                return validate_ip_or_hostname(target)
            except ValueError as e:
                print("Invalid target:", e)
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(1)

def run_nmap(target: str, output_file: str = None, timeout: int = 600):
    nmap_bin = find_nmap_executable()
    if not nmap_bin:
        print("ERROR: 'nmap' executable not found in PATH or common locations. Please install Nmap and ensure nmap.exe is available.", file=sys.stderr)
        # Helpful diagnostic suggestion:
        print("Diagnostic: run 'where nmap' or 'Get-Command nmap' in PowerShell to see which file is being picked up.", file=sys.stderr)
        return 2

    # print the exact binary we'll execute
    print("Using nmap binary:", nmap_bin)

    cmd = [nmap_bin, "-Pn", "-sT", "-p-", target]
    print("Running:", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"ERROR: nmap timed out after {timeout} seconds.", file=sys.stderr)
        return 3
    except Exception as e:
        print("ERROR: subprocess failed:", e, file=sys.stderr)
        return 4

    if proc.stdout:
        print(proc.stdout)
    if proc.stderr:
        print("--- nmap stderr ---", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(proc.stdout or "")
            print(f"Saved stdout to: {output_file}")
        except Exception as e:
            print("Warning: failed to write output file:", e, file=sys.stderr)
            return 5

    return proc.returncode

def parse_args():
    p = argparse.ArgumentParser(description="Run nmap -Pn -sT -p- <target> and optionally save output.")
    p.add_argument("target", nargs="?", help="Target IP or hostname (e.g. 10.10.10.155). If omitted, you'll be prompted.")
    p.add_argument("-o", "--output", help="Save nmap stdout to this file")
    p.add_argument("-t", "--timeout", type=int, default=600, help="Timeout seconds for the nmap process (default 600)")
    return p.parse_args()

def main():
    args = parse_args()
    if args.target:
        try:
            target = validate_ip_or_hostname(args.target)
        except ValueError as e:
            print("Invalid target argument:", e)
            target = prompt_for_target()
    else:
        target = prompt_for_target()

    rc = run_nmap(target, args.output, args.timeout)
    if rc != 0:
        sys.exit(rc)

if __name__ == "__main__":
    main()
