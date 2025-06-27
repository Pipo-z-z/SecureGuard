import nmap

puertos_vulnerables = {
    21: "FTP - Acceso anónimo o credenciales débiles",
    22: "SSH - Fuerza bruta o claves inseguras",
    23: "Telnet - Comunicación sin cifrado",
    25: "SMTP - Relay abierto",
    53: "DNS - Transferencia de zona",
    80: "HTTP - Exploits web, directorios sensibles",
    110: "POP3 - Credenciales expuestas",
    119: "NNTP - Acceso no autenticado",
    123: "NTP - Amplificación DDoS",
    135: "RPC - DCOM",
    137: "NetBIOS - Enumeración",
    138: "NetBIOS - Enumeración",
    139: "NetBIOS - EternalBlue",
    143: "IMAP - Autenticación insegura",
    161: "SNMP - Información sensible",
    162: "SNMP Trap - Escucha remota",
    389: "LDAP - Enumeración",
    443: "HTTPS - SSL débil o Heartbleed",
    445: "SMB - EternalBlue / WannaCry",
    512: "rsh - Sin autenticación segura",
    513: "rlogin - Sin autenticación segura",
    514: "rshell - Sin autenticación segura",
    515: "LPD - Impresión remota abusiva",
    587: "SMTP Seguro - Configuración incorrecta",
    631: "CUPS - Impresión web local",
    636: "LDAPs - Vulnerable si certificado inseguro",
    993: "IMAPS - Ataques por fuerza bruta",
    995: "POP3S - Ataques por fuerza bruta",
    1080: "SOCKS Proxy - Uso malicioso",
    1433: "MSSQL - Ataques por defectos de configuración",
    1521: "Oracle DB - Credenciales por defecto",
    2049: "NFS - Exposición de archivos",
    2121: "FTP - Puerto alternativo",
    2301: "HP OpenView - Vulnerabilidades",
    2375: "Docker API - Sin protección",
    2376: "Docker API TLS - Certificados débiles",
    2483: "Oracle DB - Puerto alternativo",
    2484: "Oracle DB - Puerto alternativo",
    3128: "Squid Proxy - Exposición interna",
    3306: "MySQL - Acceso remoto sin autenticación",
    3389: "RDP - Fuerza bruta",
    3780: "McAfee ePO - Vulnerabilidades web",
    4444: "Metasploit Framework / Hydra",
    4488: "Servicio personalizado común",
    4848: "GlassFish Admin - Exploits conocidos",
    49152: "UPnP - Vulnerabilidad MS10-070",
    5000: "Web UI - Aplicaciones locales",
    5001: "Web UI - Aplicaciones locales",
    5432: "PostgreSQL - Acceso sin autenticación",
    5500: "VNC - Puerto estándar",
    5900: "VNC - Puerto alternativo",
    6000: "X11 - Acceso remoto",
    6666: "DOOM - Puerto usado por malware",
    7001: "WebLogic - Vulnerabilidades RCE",
    7070: "WebAdmin - Puerto HTTP secundario",
    7777: "Web Server - Puerto alternativo",
    8000: "HTTP Alt - Servidor local",
    8008: "HTTP Alt - Puerto secundario",
    8080: "HTTP Proxy - Exposición de servicio interno",
    8081: "HTTP Proxy - Puerto alternativo",
    8161: "ActiveMQ - Consola vulnerable",
    8443: "HTTPS Alt - Puerto alternativo",
    8888: "HTTP - Puerto proxy/test",
    9000: "FastCGI - Exploitable en servidores web",
    9043: "WebSphere Admin - Vulnerabilidades",
    9080: "WebSphere App - Sin seguridad",
    9090: "Web Proxy / Servidor interno",
    9091: "Web Proxy / Servidor interno",
    9200: "Elasticsearch - Sin autenticación",
    9300: "Elasticsearch - Puerto transporte",
    11211: "Memcached - Amplificación DDoS",
    15000: "Symantec AV - Buffer overflow",
    16992: "Intel AMT - Acceso remoto sin contraseña",
    16993: "Intel AMT - Acceso remoto seguro",
    27017: "MongoDB - Sin autenticación",
    27018: "MongoDB - Puerto secundario",
    28017: "MongoDB - Puerto HTTP"
}

def escanear_puertos(ip_objetivo):
    scanner = nmap.PortScanner()
    scanner.scan(ip_objetivo, '1-65535', arguments='-sT -T4 -Pn')

    resultado = {
        "estado_host": scanner[ip_objetivo].state().upper(),
        "puertos_abiertos": [],
        "vulnerables": []
    }

    for proto in scanner[ip_objetivo].all_protocols():
        for puerto in sorted(scanner[ip_objetivo][proto].keys()):
            estado = scanner[ip_objetivo][proto][puerto]['state']
            resultado["puertos_abiertos"].append((puerto, proto.upper(), estado))

            if estado == 'open' and puerto in puertos_vulnerables:
                resultado["vulnerables"].append({
                    "puerto": puerto,
                    "descripcion": puertos_vulnerables[puerto]
                })

    return resultado
