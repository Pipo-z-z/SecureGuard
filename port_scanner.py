import nmap

puertos_vulnerables = {
    21: "FTP - Acceso anónimo o credenciales débiles",
    22: "SSH - Fuerza bruta o claves inseguras",
    23: "Telnet - Comunicación sin cifrado",
    80: "HTTP - Exploits web, directorios sensibles",
    443: "HTTPS - SSL débil o Heartbleed",
    445: "SMB - EternalBlue / WannaCry",
    3306: "MySQL - Acceso remoto sin autenticación",
    3389: "RDP - Fuerza bruta",
    5900: "VNC - Puerto alternativo",
    8080: "HTTP Proxy - Exposición de servicio interno",
    27017: "MongoDB - Sin autenticación",
}

def escanear_puertos(ip_objetivo):
    scanner = nmap.PortScanner()
    scanner.scan(ip_objetivo, '1-65535', arguments='-sT -T4 -Pn')
    
    resultado = {
        "estado_host": scanner[ip_objetivo].state(),
        "puertos_abiertos": [],
        "vulnerables": []
    }

    for proto in scanner[ip_objetivo].all_protocols():
        for puerto in sorted(scanner[ip_objetivo][proto].keys()):
            estado = scanner[ip_objetivo][proto][puerto]['state']
            if estado == 'open':
                resultado["puertos_abiertos"].append((puerto, proto))
                if puerto in puertos_vulnerables:
                    resultado["vulnerables"].append({
                        "puerto": puerto,
                        "descripcion": puertos_vulnerables[puerto]
                    })

    return resultado