from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def capturar_paquetes(cantidad=50):
    paquetes_analizados = []
    http_links_detectados = []

    def analizar(pkt):
        if IP in pkt:
            fila = {
                'tiempo': datetime.now().strftime("%H:%M:%S"),
                'origen': pkt[IP].src,
                'destino': pkt[IP].dst,
                'protocolo': pkt[IP].proto,
                'nombre': {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(pkt[IP].proto, 'Otro'),
                'ttl': pkt[IP].ttl,
                'longitud': len(pkt),
                'id_ip': pkt[IP].id,
                'puerto_origen': '-',
                'puerto_destino': '-',
                'flags': '-'
            }

            if TCP in pkt:
                fila['puerto_origen'] = pkt[TCP].sport
                fila['puerto_destino'] = pkt[TCP].dport
                fila['flags'] = str(pkt[TCP].flags)

                if Raw in pkt:
                    try:
                        data = pkt[Raw].load.decode(errors="ignore")
                        if "Host:" in data and "GET" in data:
                            host, path = "", "/"
                            for line in data.split("\r\n"):
                                if line.startswith("Host:"):
                                    host = line.split(":", 1)[1].strip()
                                if line.startswith("GET"):
                                    parts = line.split()
                                    if len(parts) > 1:
                                        path = parts[1]
                            if host:
                                http_links_detectados.append(f"http://{host}{path}")
                    except:
                        pass

            elif UDP in pkt:
                fila['puerto_origen'] = pkt[UDP].sport
                fila['puerto_destino'] = pkt[UDP].dport

            paquetes_analizados.append(fila)

    sniff(filter="ip", prn=analizar, store=0, count=cantidad)
    return paquetes_analizados, list(set(http_links_detectados))