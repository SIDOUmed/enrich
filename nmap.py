
import shutil
import sys

try:
    import nmap
except Exception as e:
    print("ERROR: failed to import python-nmap. Did you install 'python-nmap' with pip?")
    print("Exception:", e)
    sys.exit(1)

def check_nmap_installed():
    # check if nmap binary is available in PATH
    if shutil.which("nmap") is None:
        print("WARNING: 'nmap' executable not found in PATH. 'python-nmap' may still work for simple operations,"
              " but full scanning requires the nmap program installed. Install nmap and ensure it's on PATH.")
        return False
    return True

def nmap_scan(target):
    # create PortScanner object
    try:
        nm = nmap.PortScanner()
    except AttributeError as e:
        print("ERROR: the 'nmap' module does not expose PortScanner().")
        print("Possible causes: your script is named 'nmap.py' or python-nmap is not installed.")
        print("Exception:", e)
        # helpful diagnostic:
        try:
            print("nmap module file:", getattr(nmap, '__file__', 'built-in or unknown'))
        except Exception:
            pass
        return

    print(f"Scanning target: {target}")
    try:
        nm.scan(hosts=target, arguments='-sV')
    except Exception as e:
        print("ERROR: nmap scan failed:", e)
        return

    for host in nm.all_hosts():
        print(f"\nHost: {host}")
        print(f"State: {nm[host].state()}")

        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto}")
            ports = nm[host][proto].keys()
            print("PORT\tSTATE\tSERVICE\tVERSION")
            for port in sorted(ports):
                port_info = nm[host][proto][port]
                version_info = port_info.get('version', '')
                product_info = port_info.get('product', '')
                extra_info = port_info.get('extrainfo', '')
                version_detail = " ".join(filter(None, [product_info, version_info, extra_info])).strip()
                print(f"{port}/{proto}\t{port_info.get('state','')}\t{port_info.get('name','')}\t{version_detail}")

if __name__ == "__main__":
    check_nmap_installed()
    target_host = input("Enter an IP address or domain name to scan: ").strip()
    if not target_host:
        print("No target provided. Exiting.")
        sys.exit(0)
    nmap_scan(target_host)