#!/usr/bin/env python3

import socket
import threading
from queue import Queue
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)

print(Fore.CYAN + "\n==== Advanced Port Scanner Tool ====\n")

# ---- User Inputs ----

hosts_input = input("Enter host(s) (comma-separated): ").strip()
hosts = [h.strip() for h in hosts_input.split(",")]

try:
    thread_count = int(input("Enter number of threads: ").strip())
except ValueError:
    print("Invalid thread number. Using default (50 threads).")
    thread_count = 50

try:
    start_port = int(input("Enter START port: "))
    end_port = int(input("Enter END port: "))
    if start_port > end_port:
        raise ValueError
except ValueError:
    print(Fore.YELLOW + "Invalid range. Using default 1-1024.")
    start_port, end_port = 1, 1024

PORT_RANGE = range(start_port, end_port + 1)

# ---- Logging ----
log_file = "scan_log.txt"

def log(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(log_file, "a") as f:
        f.write(f"{timestamp} {message}\n")


# ---- Worker Queue ----
queue = Queue()


def detect_os(ttl):
    """Crude OS fingerprinting based on TTL value."""
    if ttl >= 100:
        return "Linux/Unix"
    elif ttl <= 64:
        return "Windows"
    else:
        return "Unknown"


def grab_banner(sock):
    """Try retrieving service banner (version detection)."""
    try:
        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return None


def scan_port(host):
    """Scan TCP port & detect version if open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        result = sock.connect_ex((host, port))
        if result == 0:

            # ---- Banner / Version detection ----
            banner = grab_banner(sock)

            msg = f"[{host}] Port {port} OPEN"
            if banner:
                msg += f" --> Service: {banner.splitlines()[0]}"

            print(Fore.GREEN + msg)
            log(msg)

        return result == 0

    except socket.error:
        return False
    finally:
        sock.close()


def detect_os_and_ping(host):
    """Ping and fingerprint TTL after the scan."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, 80))
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        
        detected = detect_os(ttl)
        print(Fore.MAGENTA + f"[{host}] Possible OS: {detected} (TTL={ttl})")
        log(f"[{host}] OS Guess: {detected} (TTL={ttl})")
    except:
        print(Fore.RED + f"[{host}] OS Detection Failed")
        log(f"[{host}] OS Detection Failed")


def worker(host, pbar):
    """Thread consumer for ports."""
    while not queue.empty():
        global port
        port = queue.get()
        scan_port(host)
        queue.task_done()
        pbar.update(1)


def scan_host(host):
    print(Fore.CYAN + f"\n>>> Scanning {host}...\n")
    log(f"--- Starting scan for {host} ---")

    for p in PORT_RANGE:
        queue.put(p)

    pbar = tqdm(total=len(PORT_RANGE), desc=f"Scanning {host}", ncols=80)

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(host, pbar))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    pbar.close()
    detect_os_and_ping(host)

    print(Fore.YELLOW + f"\n--- Completed scanning: {host} ---\n")
    log(f"--- Completed scanning {host} ---")


# ---- Main Execution ----
log("\n========== NEW SCAN SESSION ==========\n")

for host in hosts:
    scan_host(host)

log("All hosts scanned.\n")
print(Fore.CYAN + "Scan completed for all hosts. Results saved in scan_log.txt")
