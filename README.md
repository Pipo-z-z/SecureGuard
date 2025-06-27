# SecureGuard : Detección de Vulnerabilidades Mediante Escaneo de Puertos, Sniffer y Keylogger
### SecureGuard es una aplicación de ciberseguridad diseñada para identificar vulnerabilidades comunes en sistemas y redes locales a través de herramientas integradas de análisis pasivo y activo. Su enfoque está orientado tanto a usuarios técnicos como a estudiantes de seguridad informática que buscan una solución compacta para tareas básicas de auditoría.
## Tabla de contenidos
### 🔍 Escaneo de Puertos (Nmap)
#### Detecta puertos abiertos, protocolos y posibles vulnerabilidades asociadas en el host objetivo.

### 🌐 Sniffer de Red (Scapy)
Captura y analiza 50 paquetes en tiempo real, mostrando encabezados IP, puertos, protocolos y posibles enlaces HTTP.

### 🖥️ Detector de Keylogger (Pynput + netstat)
Identifica conexiones sospechosas entre procesos internos y direcciones IP externas, útil para detectar actividad maliciosa.

### 🤖 Informe Inteligente (OpenAI GPT-4o)
Genera automáticamente un resumen ejecutivo y recomendaciones de seguridad personalizadas basadas en los hallazgos de las herramientas.

### 📤 Exportación de Reportes
Exporta los resultados a PDF, JSON o CSV, con formato estructurado y claridad profesional.

### 🎨 Interfaz Gráfica Moderna (PySide6)
Diseño intuitivo con panel lateral, temas claro/oscuro, y navegación fluida entre módulos.


## 📊 Componentes por Capas
### 1. Interfaz de Usuario
* PySide6, QMainWindow, QTabWidget, QTableWidget

* Temas: claro / oscuro

* Navegación lateral + pestañas de herramientas

### 2. Lógica de Control
* SecurityApp: controlador central (eventos, navegación, datos)

### 3. Módulos Funcionales
* port_scanner.py – Wrapper para Nmap

* sniffer.py – Captura de paquetes con Scapy

* keylogger.py – Detección de procesos sospechosos

### 4. IA y Reportes
* ia_asistente.py – Llama a GPT-4o con datos y genera informe técnico

### 5. Exportación
* fpdf para guardar informes en PDF
* Planificado: JSON / CSV



## 📦 Arquitectura por Archivos
| Archivo                         | Descripción                                           |
| ------------------------------- | ----------------------------------------------------- |
| `interface.py`                  | Interfaz gráfica principal y navegación entre módulos |
| `port_scanner.py`               | Escaneo de puertos usando Nmap                        |
| `sniffer.py`                    | Captura y análisis de paquetes con Scapy              |
| `keylogger.py`                  | Detección de conexiones sospechosas                   |
| `ia_asistente.py`               | Generación del informe con IA (GPT-4o)                |
| `pdf_generator.py` *(opcional)* | Exportación a PDF/CSV (en desarrollo)                 |
| `requirements.txt`              | Dependencias del proyecto                             |

## ¿Cómo Ejecutar?
### Requisitos
* Python 3.9+
* Clave API de OpenAI (para los informes IA)
* Permisos de administrador si deseas usar funcionalidades de red
### Instalación
```bash
git clone https://github.com/tu_usuario/secureguard.git
cd secureguard
pip install -r requirements.txt
```
## Autores
###
* Ccama Cruz, Carlos David
* Guerrero Sotil, Rodrigo Arian
* Herrera, Johan Neira
* Vasquez de la Torre, Pablo David
