import psutil
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate

init(autoreset=True)

SUSPICIOUS_PORTS = [4444, 1337, 5555, 8080, 9001]


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_info(msg):
    print(f"{Fore.CYAN}[{timestamp()}] [INFO]{Style.RESET_ALL} {msg}")


def log_alert(msg):
    print(f"{Fore.RED}[{timestamp()}] [ALERTA]{Style.RESET_ALL} {msg}")


def log_debug(msg):
    print(f"{Fore.YELLOW}[{timestamp()}] [DEBUG]{Style.RESET_ALL} {msg}")


def detect_suspicious_connections(verbose=False):
    log_info("Escaneando conexiones sospechosas...\n")

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

                if verbose:
                    log_debug(f"{l_ip}:{l_port} → {r_ip}:{r_port} [{status}] PID={pid if pid else 'N/A'}")

                if r_port in SUSPICIOUS_PORTS:
                    if pid:
                        pname = psutil.Process(pid).name()
                        log_alert(f"Proceso sospechoso: {pname} (PID {pid}) conectado a {r_ip}:{r_port} [{status}]")
                        found.append([pname, pid, f"{l_ip}:{l_port}", f"{r_ip}:{r_port}", status])
                    else:
                        log_alert(f"Conexión sospechosa sin proceso: {l_ip}:{l_port} → {r_ip}:{r_port} [{status}]")
                        found.append(["N/A", "N/A", f"{l_ip}:{l_port}", f"{r_ip}:{r_port}", status])
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            continue

    if found:
        print("\n" + Fore.GREEN + "Resumen de conexiones sospechosas:\n" + Style.RESET_ALL)
        headers = ["Proceso", "PID", "Origen", "Destino", "Estado"]
        print(tabulate(found, headers=headers, tablefmt="fancy_grid"))
    else:
        log_info("No se detectaron conexiones sospechosas.")


if __name__ == "__main__":
    detect_suspicious_connections(verbose=False)
