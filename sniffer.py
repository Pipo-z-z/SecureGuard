from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import pandas as pd
import joblib

# Cargar modelo y encoder
modelo = joblib.load("modelo_sniffer.pkl")
encoder = joblib.load("label_encoder.pkl")

def capturar_paquetes_con_ia(cantidad=50):
    resultados = []

    def analizar(pkt):
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            proto_num = pkt[IP].proto
            proto_nombre = {1: 'icmp', 6: 'tcp', 17: 'udp'}.get(proto_num, 'otro')
            ttl = pkt[IP].ttl
            longitud = len(pkt)

            puerto_origen = "-"
            puerto_destino = "-"
            flags = "-"
            service_guess = "other"

            if TCP in pkt:
                puerto_origen = pkt[TCP].sport
                puerto_destino = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    service_guess = "http"
            elif UDP in pkt:
                puerto_origen = pkt[UDP].sport
                puerto_destino = pkt[UDP].dport
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    service_guess = "dns"

            muestra = {
                'dur': 0.1,
                'proto': proto_nombre,
                'service': service_guess,
                'state': 'FIN',
                'sbytes': longitud,
                'dbytes': int(longitud * 0.5),
                'sttl': ttl,
                'dttl': ttl,
                'sload': 0,
                'dload': 0,
                'sloss': 0,
                'dloss': 0
            }

            df = pd.DataFrame([muestra])
            for col in ['proto', 'service', 'state']:
                df[col] = df[col].astype('category').cat.codes

            pred = modelo.predict(df)[0]
            clase = encoder.inverse_transform([pred])[0]

            resultado = {
                'tiempo': datetime.now().strftime('%H:%M:%S'),
                'origen': ip_src,
                'destino': ip_dst,
                'protocolo': proto_nombre.upper(),
                'servicio': service_guess,
                'ttl': ttl,
                'longitud': longitud,
                'id_ip': '-',  # opcional
                'puerto_origen': puerto_origen,
                'puerto_destino': puerto_destino,
                'flags': flags,
                'clasificacion': clase
            }

            resultados.append(resultado)

    sniff(filter="ip", prn=analizar, store=0, count=cantidad)
    return resultados
