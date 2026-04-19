import socket
from concurrent.futures import ThreadPoolExecutor
import time
import random


# -----------------------------
# REAL SCAN (same contract)
# -----------------------------
def scan_port(target, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))

        if result == 0:
            return port, True

        return port, False

    except socket.error:
        return port, False

    finally:
        sock.close()


# -----------------------------
# BULK SCAN (unchanged logic)
# -----------------------------
def scan_targets(targets, ports, timeout=1):
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []

        for target in targets:
            for port in ports:
                futures.append(
                    executor.submit(scan_port, target, port, timeout)
                )

        for future in futures:
            results.append(future.result())

    return results


# -----------------------------
# FAKE SCAN (NOW MATCHES CONTRACT)
# -----------------------------
def fake_scan_port(target, port, timeout):
    result = random.choice([True, False])
    return port, result