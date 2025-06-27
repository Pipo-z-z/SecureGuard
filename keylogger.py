import psutil
from datetime import datetime

SUSPICIOUS_PORTS = [4444, 1337, 5555, 8080, 9001]

def detect_suspicious_connections(verbose=False):
    found = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.raddr:
                r_ip = conn.raddr.ip
                r_port = conn.raddr.port
                l_ip = conn.laddr.ip
                l_port = conn.laddr.port
                status = conn.status
                pid = conn.pid

                if r_port in SUSPICIOUS_PORTS:
                    if pid:
                        pname = psutil.Process(pid).name()
                        found.append([pname, str(pid), f"{l_ip}:{l_port}", f"{r_ip}:{r_port}", status])
                    else:
                        found.append(["N/A", "N/A", f"{l_ip}:{l_port}", f"{r_ip}:{r_port}", status])
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue

    return found