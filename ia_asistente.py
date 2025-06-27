import openai

key=""
client = openai.OpenAI(api_key=key)

output_sniffer = [
    ["01:25:59", "74.125.250.254", "192.168.100.84", 17, "UDP", 54, 164, 0, 3478, 65168, "-"],
    ["01:25:59", "74.125.250.242", "192.168.100.84", 17, "UDP", 54, 106, 0, 3478, 62870, "-"],
    ["01:28:27", "184.31.176.162", "192.168.100.84", 6, "TCP", 50, 54, 52150, 80, 5318, "FA"]
]
output_scaner_puertos="""135, TCP, OPEN
137, TCP, FILTRERED
139, TCP, OPEN
445, TCP, OPEN
902, TCP, OPEN
912, TCP, OPEN
5040, TCP, OPEN
27000, TCP, OPEN
27036, TCP, OPEN
38000, TCP, OPEN
39000, TCP, OPEN
49664, TCP, OPEN
49665, TCP, OPEN
49666, TCP, OPEN
49667, TCP, OPEN
49668, TCP, OPEN
49681, TCP, OPEN"""
output_detector_keylogger=""


def generar_informe_ia(nmap_results, keylogger_detected, packet_sniff_summary):
    prompt = f"""
    Eres un asistente experto en ciberseguridad. Con base en los siguientes datos generados por herramientas de análisis, redacta un resumen ejecutivo y recomendaciones generales de seguridad para un usuario técnico:

    🔍 Resultados del escaneo de puertos (Nmap):
    Formato en lista: [Puerto] - [Servicio] - [Estado]
    {nmap_results}

    🖱️ Detección de keylogger:
    {'Se detectó actividad sospechosa relacionada a keyloggers.' if keylogger_detected else 'No se detectó actividad de keyloggers.'}

    🌐 Monitoreo de red (Sniffer):
    Formato en lista: [Hora] - [IP origen] - [IP destino] - [Protocolo] - [Nombre] - [TTL] - [Long] - [IP-ID] - [Puerto origen] - [Puerto destino] - [Flag]
    {packet_sniff_summary}

    🎯 Estructura esperada:
    1. ✅ Resumen General (en máximo 3 párrafos)
    2. 🛠️ Recomendaciones Generales (con viñetas, orientadas a mejorar la seguridad)

    El informe debe ser claro, técnico y directo. No repitas el input, solo analiza y genera.
    """

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Eres un generador de informes técnicos en ciberseguridad."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.4,
        max_tokens=700
    )

    return response.choices[0].message.content




