import sys
from scapy.all import sniff, IP, TCP, UDP, wrpcap
from collections import Counter
import time
import os
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QStackedWidget, QPushButton, QLabel, 
                             QTextEdit, QProgressBar, QGroupBox, QRadioButton,
                             QCheckBox, QComboBox, QSpinBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QFileDialog,
                             QMessageBox, QTabWidget, QScrollArea, QFrame,
                             QGridLayout, QSplitter)
from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont, QPixmap, QIcon, QPalette, QColor
import datetime


# Diccionario de puertos comúnmente asociados a vulnerabilidades
puertos_vulnerables = {
    21: "FTP - Acceso anónimo o credenciales débiles",
    22: "SSH - Fuerza bruta o claves inseguras",
    23: "Telnet - Comunicación sin cifrado",
    25: "SMTP - Relay abierto",
    53: "DNS - Transferencia de zona",
    80: "HTTP - Exploits web, directorios sensibles",
    110: "POP3 - Credenciales expuestas",
    443: "HTTPS - SSL débil o Heartbleed",
    445: "SMB - EternalBlue / WannaCry",
    3306: "MySQL - Acceso remoto sin autenticación",
    3389: "RDP - Fuerza bruta",
    8080: "HTTP Proxy - Exposición de servicio interno",
    27017: "MongoDB - Sin autenticación",
    5900: "VNC - Sin autenticación"
}



from PySide6.QtCore import QThread, Signal
import nmap

class PortScannerThread(QThread):
    scan_finished = Signal(list)
    log_signal = Signal(str)

    def __init__(self, ip_target, parent=None):
        super().__init__(parent)
        self.ip_target = ip_target

    def run(self):
        scanner = nmap.PortScanner()
        self.log_signal.emit(f"[+] Escaneando {self.ip_target}...")
        try:
            scanner.scan(self.ip_target, '1-65535', arguments='-sT -T4 -Pn')
        except Exception as e:
            self.log_signal.emit(f"[!] Error de escaneo: {str(e)}")
            return

        puertos_abiertos = []
        for proto in scanner[self.ip_target].all_protocols():
            puertos = scanner[self.ip_target][proto].keys()
            for puerto in sorted(puertos):
                estado = scanner[self.ip_target][proto][puerto]['state']
                if estado == 'open':
                    puertos_abiertos.append((puerto, proto))
                    self.log_signal.emit(f"Puerto {puerto}/{proto} está abierto")

        self.scan_finished.emit(puertos_abiertos)


class SnifferThread(QThread):
    progress_updated = Signal(int)
    scan_complete = Signal(list)
    log_signal = Signal(str)

    def __init__(self, interface=None, timeout=10, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.timeout = timeout

    def run(self):
        from scapy.all import sniff, IP, TCP, UDP, wrpcap
        from collections import Counter
        import time

        stats = {
            "total_packets": 0,
            "suspicious_packets": 0,
            "protocols": Counter(),
            "ips": Counter(),
            "suspicious_packets_list": []
        }

        SUSPICIOUS_PORTS = [4444, 1337, 5555, 8080, 9001]

        def packet_callback(packet):
            stats["total_packets"] += 1
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                stats["ips"][ip_src] += 1
                stats["ips"][ip_dst] += 1

                proto = None
                port_src = None
                port_dst = None

                if TCP in packet:
                    port_src = packet[TCP].sport
                    port_dst = packet[TCP].dport
                    proto = "TCP"
                elif UDP in packet:
                    port_src = packet[UDP].sport
                    port_dst = packet[UDP].dport
                    proto = "UDP"

                if proto and (port_src in SUSPICIOUS_PORTS or port_dst in SUSPICIOUS_PORTS):
                    stats["suspicious_packets"] += 1
                    stats["protocols"][proto] += 1
                    stats["suspicious_packets_list"].append(packet)
                    self.log_signal.emit(f"🚨 Paquete sospechoso: {ip_src}:{port_src} → {ip_dst}:{port_dst} [{proto}]")

        start_time = time.time()
        try:
            sniff(
                iface=self.interface,
                prn=packet_callback,
                filter="tcp or udp",
                timeout=self.timeout,
                store=0
            )
        except Exception as e:
            self.log_signal.emit(f"❌ Error al capturar paquetes: {e}")
            return

        end_time = time.time()
        duration = end_time - start_time

        # ➕ Aquí va la parte que guardará el archivo pcap SI HAY PAQUETES SOSPECHOSOS
        base_folder = "C:/Users/Pablo/Desktop/Proyecto POO/Sniffer"
        os.makedirs(base_folder, exist_ok=True)

        pcap_file = os.path.join(
            base_folder,
            f"suspicious_{time.strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
        )

        if stats["suspicious_packets_list"]:
            wrpcap(pcap_file, stats["suspicious_packets_list"])
            self.log_signal.emit(f"📁 Guardados paquetes sospechosos en: {pcap_file}")
        else:
            self.log_signal.emit("ℹ️ No se encontraron paquetes sospechosos.")

        # ➕ Fin de la parte de guardado del .pcap

        # ➕ Enviar estadísticas finales
        self.scan_complete.emit([{
            'total': stats["total_packets"],
            'suspicious': stats["suspicious_packets"],
            'protocols': dict(stats["protocols"]),
            'ips': dict(stats["ips"]),
            'pcap_file': pcap_file,
            'duration': duration
        }])

class SecurityApp(QMainWindow):
    def append_log_output(self, message):
        self.log_output.append(message)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureGuard Pro - Auditoría de Seguridad Ética")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 700)
        
        # Configurar tema oscuro
        self.setup_theme()
        
        # Widget central y stack de páginas
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Layout principal
        main_layout = QHBoxLayout(self.central_widget)
        
        # Panel de navegación lateral
        self.setup_navigation_panel()
        
        # Área de contenido principal
        self.content_stack = QStackedWidget()
        
        # Crear todas las páginas
        self.create_home_page()
        self.create_vulnerability_scan_page()
        self.create_penetration_test_page()
        self.create_reports_page()
        self.create_settings_page()
        
        # Agregar al layout principal
        main_layout.addWidget(self.nav_panel, 1)
        main_layout.addWidget(self.content_stack, 4)
        
        # Mostrar página de inicio por defecto
        self.show_page(0)
        
    def setup_theme(self):
        """Configurar tema oscuro profesional"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(45, 45, 48))
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Base, QColor(35, 35, 38))
        palette.setColor(QPalette.AlternateBase, QColor(60, 60, 63))
        palette.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
        palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(53, 53, 57))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
        self.setPalette(palette)
        
    def setup_navigation_panel(self):
        """Crear panel de navegación lateral"""
        self.nav_panel = QFrame()
        self.nav_panel.setFrameStyle(QFrame.StyledPanel)
        self.nav_panel.setMaximumWidth(250)
        self.nav_panel.setStyleSheet("""
            QFrame {
                background-color: #2d2d30;
                border-right: 2px solid #404040;
            }
            QPushButton {
                text-align: left;
                padding: 12px 16px;
                border: none;
                background-color: transparent;
                color: #ffffff;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #404040;
            }
            QPushButton:pressed {
                background-color: #2a82da;
            }
        """)
        
        nav_layout = QVBoxLayout(self.nav_panel)
        
        # Logo/Título
        title_label = QLabel("🛡️ SecureGuard Pro")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #2a82da;
                padding: 20px;
                border-bottom: 2px solid #404040;
                margin-bottom: 10px;
            }
        """)
        nav_layout.addWidget(title_label)
        
        # Botones de navegación
        nav_buttons = [
            ("🏠 Inicio", 0),
            ("🔍 Escaneo de Vulnerabilidades", 1),
            ("🎯 Pruebas de Penetración", 2),
            ("📊 Reportes", 3),
            ("⚙️ Configuración", 4)
        ]
        
        self.nav_buttons = []
        for text, page_index in nav_buttons:
            btn = QPushButton(text)
            btn.clicked.connect(lambda checked, idx=page_index: self.show_page(idx))
            nav_layout.addWidget(btn)
            self.nav_buttons.append(btn)
        
        nav_layout.addStretch()
        
        # Información del usuario
        user_info = QLabel("👤 Usuario: Admin\n🕒 " + datetime.datetime.now().strftime("%H:%M:%S"))
        user_info.setAlignment(Qt.AlignCenter)
        user_info.setStyleSheet("""
            QLabel {
                padding: 10px;
                border-top: 1px solid #404040;
                font-size: 12px;
                color: #cccccc;
            }
        """)
        nav_layout.addWidget(user_info)
        
    def create_home_page(self):
        """Crear página de inicio"""
        home_page = QWidget()
        layout = QVBoxLayout(home_page)
        
        # Header
        header = QLabel("Bienvenido a SecureGuard Pro")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                font-size: 28px;
                font-weight: bold;
                color: #2a82da;
                margin: 20px 0;
            }
        """)
        layout.addWidget(header)
        
        # Descripción
        description = QLabel("""
        SecureGuard Pro es una suite completa de herramientas para auditoría de seguridad ética.
        Diseñada para profesionales de ciberseguridad, permite realizar análisis exhaustivos
        de vulnerabilidades y pruebas de penetración de manera controlada y responsable.
        """)
        description.setWordWrap(True)
        description.setAlignment(Qt.AlignCenter)
        description.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #cccccc;
                margin: 20px 40px;
                line-height: 1.6;
            }
        """)
        layout.addWidget(description)
        
        # Panel de estadísticas rápidas
        stats_group = QGroupBox("Estado del Sistema")
        stats_layout = QGridLayout(stats_group)
        
        stats = [
            ("Última auditoría:", "15/06/2025 14:30", "#4CAF50"),
            ("Vulnerabilidades críticas:", "0", "#4CAF50"),
            ("Vulnerabilidades altas:", "2", "#FF9800"),
            ("Estado del sistema:", "Seguro", "#4CAF50")
        ]
        
        for i, (label, value, color) in enumerate(stats):
            label_widget = QLabel(label)
            value_widget = QLabel(value)
            value_widget.setStyleSheet(f"color: {color}; font-weight: bold;")
            stats_layout.addWidget(label_widget, i, 0)
            stats_layout.addWidget(value_widget, i, 1)
        
        layout.addWidget(stats_group)
        
        # Accesos rápidos
        quick_actions = QGroupBox("Acciones Rápidas")
        quick_layout = QGridLayout(quick_actions)
        
        quick_scan_btn = QPushButton("Escaneo Rápido")
        quick_scan_btn.clicked.connect(lambda: self.show_page(1))
        quick_scan_btn.setStyleSheet(self.get_button_style("#4CAF50"))
        
        full_scan_btn = QPushButton("Análisis Completo")
        full_scan_btn.clicked.connect(lambda: self.show_page(1))
        full_scan_btn.setStyleSheet(self.get_button_style("#2a82da"))
        
        reports_btn = QPushButton("Ver Reportes")
        reports_btn.clicked.connect(lambda: self.show_page(3))
        reports_btn.setStyleSheet(self.get_button_style("#9C27B0"))
        
        quick_layout.addWidget(quick_scan_btn, 0, 0)
        quick_layout.addWidget(full_scan_btn, 0, 1)
        quick_layout.addWidget(reports_btn, 1, 0, 1, 2)
        
        layout.addWidget(quick_actions)
        layout.addStretch()
        
        self.content_stack.addWidget(home_page)
        
    def create_vulnerability_scan_page(self):
        """Crear página de escaneo de vulnerabilidades"""
        scan_page = QWidget()
        layout = QVBoxLayout(scan_page)
        
        # Header
        header = QLabel("🔍 Escaneo de Vulnerabilidades")
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px 0;")
        layout.addWidget(header)
        
        # Tabs para diferentes tipos de escaneo
        scan_tabs = QTabWidget()
        
        # Tab 1: Análisis Rápido
        quick_tab = QWidget()
        quick_layout = QVBoxLayout(quick_tab)
        
        quick_options = QGroupBox("Opciones de Escaneo Rápido")
        quick_options_layout = QVBoxLayout(quick_options)
        
        self.quick_network_check = QCheckBox("Escaneo de red local")
        self.quick_ports_check = QCheckBox("Puertos abiertos")
        self.quick_services_check = QCheckBox("Servicios en ejecución")
        self.quick_updates_check = QCheckBox("Actualizaciones pendientes")
        
        for check in [self.quick_network_check, self.quick_ports_check, 
                     self.quick_services_check, self.quick_updates_check]:
            check.setChecked(True)
            quick_options_layout.addWidget(check)
        
        quick_layout.addWidget(quick_options)
        
        # Botón de escaneo rápido
        quick_scan_btn = QPushButton("Iniciar Escaneo Rápido")
        quick_scan_btn.clicked.connect(self.start_quick_scan)
        quick_scan_btn.setStyleSheet(self.get_button_style("#4CAF50"))
        quick_layout.addWidget(quick_scan_btn)
        
        # Progress bar
        self.quick_progress = QProgressBar()
        self.quick_progress.setVisible(False)
        quick_layout.addWidget(self.quick_progress)
        
        quick_layout.addStretch()
        scan_tabs.addTab(quick_tab, "Análisis Rápido")
        
        # Tab 2: Análisis Detallado
        detailed_tab = QWidget()
        detailed_layout = QVBoxLayout(detailed_tab)
        
        detailed_options = QGroupBox("Configuración de Análisis Detallado")
        detailed_options_layout = QGridLayout(detailed_options)
        
        detailed_options_layout.addWidget(QLabel("Rango de IP:"), 0, 0)
        self.ip_range_input = QComboBox()
        self.ip_range_input.addItems(["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24", "Personalizado"])
        detailed_options_layout.addWidget(self.ip_range_input, 0, 1)
        
        detailed_options_layout.addWidget(QLabel("Timeout (ms):"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 5000)
        self.timeout_spin.setValue(1000)
        detailed_options_layout.addWidget(self.timeout_spin, 1, 1)
        
        detailed_options_layout.addWidget(QLabel("Threads:"), 2, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 100)
        self.threads_spin.setValue(10)
        detailed_options_layout.addWidget(self.threads_spin, 2, 1)
        
        # Opciones avanzadas
        self.detailed_os_detect = QCheckBox("Detección de SO")
        self.detailed_service_detect = QCheckBox("Detección de servicios")
        self.detailed_vuln_scan = QCheckBox("Escaneo de vulnerabilidades")
        self.detailed_stealth = QCheckBox("Modo sigiloso")
        
        for i, check in enumerate([self.detailed_os_detect, self.detailed_service_detect, 
                                 self.detailed_vuln_scan, self.detailed_stealth]):
            detailed_options_layout.addWidget(check, 3 + i//2, i%2)
        
        detailed_layout.addWidget(detailed_options)
        
        # Botón de escaneo detallado
        detailed_scan_btn = QPushButton("Iniciar Análisis Detallado")
        detailed_scan_btn.clicked.connect(self.start_detailed_scan)
        detailed_scan_btn.setStyleSheet(self.get_button_style("#FF5722"))
        detailed_layout.addWidget(detailed_scan_btn)
        
        # Progress bar detallado
        self.detailed_progress = QProgressBar()
        self.detailed_progress.setVisible(False)
        detailed_layout.addWidget(self.detailed_progress)
        
        detailed_layout.addStretch()
        scan_tabs.addTab(detailed_tab, "Análisis Detallado")
        
        # Tab 3: Resultados
        results_tab = QWidget()
        results_layout = QVBoxLayout(results_tab)
        
        # Tabla de resultados
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Host", "Puerto", "Servicio", "Vulnerabilidad", "Riesgo"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        # Área de logs
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)
        results_layout.addWidget(self.log_output)
        
        # Datos de ejemplo
        sample_data = [
            ["192.168.1.1", "22", "SSH", "OpenSSH 7.4 - Weak Cipher", "Medio"],
            ["192.168.1.10", "80", "HTTP", "Apache 2.4.6 - Directory Traversal", "Alto"],
            ["192.168.1.15", "445", "SMB", "SMBv1 Enabled", "Crítico"]
        ]
        
        self.results_table.setRowCount(len(sample_data))
        for i, row_data in enumerate(sample_data):
            for j, cell_data in enumerate(row_data):
                item = QTableWidgetItem(cell_data)
                if j == 4:  # Columna de riesgo
                    if cell_data == "Crítico":
                        item.setBackground(QColor("#F44336"))
                    elif cell_data == "Alto":
                        item.setBackground(QColor("#FF9800"))
                    elif cell_data == "Medio":
                        item.setBackground(QColor("#FFC107"))
                    else:
                        item.setBackground(QColor("#4CAF50"))
                self.results_table.setItem(i, j, item)
        
        results_layout.addWidget(self.results_table)
        
        # Botones de acción para resultados
        results_buttons = QHBoxLayout()
        export_btn = QPushButton("Exportar Resultados")
        export_btn.clicked.connect(self.export_results)
        generate_report_btn = QPushButton("Generar Reporte")
        generate_report_btn.clicked.connect(lambda: self.show_page(3))
        
        results_buttons.addWidget(export_btn)
        results_buttons.addWidget(generate_report_btn)
        results_buttons.addStretch()
        results_layout.addLayout(results_buttons)
        
        scan_tabs.addTab(results_tab, "Resultados")
        
        layout.addWidget(scan_tabs)
        self.content_stack.addWidget(scan_page)
        
    def create_penetration_test_page(self):
        """Crear página de pruebas de penetración"""
        pentest_page = QWidget()
        layout = QVBoxLayout(pentest_page)
        
        # Header
        header = QLabel("🎯 Pruebas de Penetración Ética")
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px 0;")
        layout.addWidget(header)
        
        # Warning
        warning = QLabel("⚠️ ADVERTENCIA: Use estas herramientas solo en sistemas autorizados")
        warning.setStyleSheet("color: #FF5722; font-weight: bold; background: #2d2d30; padding: 10px; border: 2px solid #FF5722;")
        layout.addWidget(warning)
        
        # Tabs para diferentes pruebas
        pentest_tabs = QTabWidget()
        
        # Tab 1: Simulación de Penetración
        simulation_tab = QWidget()
        sim_layout = QVBoxLayout(simulation_tab)
        
        # Configuración de objetivo
        target_group = QGroupBox("Configuración del Objetivo")
        target_layout = QGridLayout(target_group)
        
        target_layout.addWidget(QLabel("IP Objetivo:"), 0, 0)
        self.target_ip = QComboBox()
        self.target_ip.setEditable(True)
        self.target_ip.addItems(["192.168.1.1", "127.0.0.1", "192.168.1.100"])
        target_layout.addWidget(self.target_ip, 0, 1)
        
        target_layout.addWidget(QLabel("Puertos:"), 1, 0)
        self.target_ports = QComboBox()
        self.target_ports.setEditable(True)
        self.target_ports.addItems(["1-1000", "21,22,23,53,80,110,443", "1-65535"])
        target_layout.addWidget(self.target_ports, 1, 1)
        
        sim_layout.addWidget(target_group)
        
        # Tipos de pruebas
        tests_group = QGroupBox("Tipos de Pruebas")
        tests_layout = QVBoxLayout(tests_group)
        
        self.port_scan_check = QCheckBox("Escaneo de puertos")
        self.service_enum_check = QCheckBox("Enumeración de servicios")
        self.vuln_exploit_check = QCheckBox("Explotación de vulnerabilidades")
        self.brute_force_check = QCheckBox("Ataques de fuerza bruta")
        self.web_app_test_check = QCheckBox("Pruebas de aplicaciones web")
        
        for check in [self.port_scan_check, self.service_enum_check, 
                     self.vuln_exploit_check, self.brute_force_check, self.web_app_test_check]:
            tests_layout.addWidget(check)
        
        sim_layout.addWidget(tests_group)
        
        # Botón de inicio
        start_pentest_btn = QPushButton("Iniciar Pruebas de Penetración")
        start_pentest_btn.clicked.connect(self.start_penetration_test)
        start_pentest_btn.setStyleSheet(self.get_button_style("#FF5722"))
        sim_layout.addWidget(start_pentest_btn)
        
        # Progress
        self.pentest_progress = QProgressBar()
        self.pentest_progress.setVisible(False)
        sim_layout.addWidget(self.pentest_progress)
        
        sim_layout.addStretch()
        pentest_tabs.addTab(simulation_tab, "Simulación")
        
        # Tab 2: Análisis de Resultados
        analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(analysis_tab)
        
        # Resultados de pruebas
        self.pentest_results = QTextEdit()
        self.pentest_results.setPlainText("""
RESULTADOS DE PRUEBAS DE PENETRACIÓN
====================================

TARGET: 192.168.1.100
FECHA: 15/06/2025 14:30:00

ESCANEO DE PUERTOS:
- Puerto 22/tcp: ABIERTO (SSH)
- Puerto 80/tcp: ABIERTO (HTTP)
- Puerto 443/tcp: ABIERTO (HTTPS)

ENUMERACIÓN DE SERVICIOS:
- SSH: OpenSSH 7.4p1 (protocol 2.0)
- HTTP: Apache/2.4.6 (CentOS)
- HTTPS: Apache/2.4.6 (CentOS) mod_ssl/2.4.6

VULNERABILIDADES DETECTADAS:
[ALTO] CVE-2016-6210: SSH user enumeration vulnerability
[MEDIO] Weak SSL/TLS ciphers enabled
[BAJO] Server version disclosure

RECOMENDACIONES:
1. Actualizar OpenSSH a la versión más reciente
2. Configurar cifrados SSL/TLS más seguros
3. Ocultar información del servidor web
        """)
        self.pentest_results.setReadOnly(True)
        analysis_layout.addWidget(self.pentest_results)
        
        # Botones de análisis
        analysis_buttons = QHBoxLayout()
        save_results_btn = QPushButton("Guardar Resultados")
        save_results_btn.clicked.connect(self.save_pentest_results)
        generate_recommendations_btn = QPushButton("Generar Recomendaciones")
        
        analysis_buttons.addWidget(save_results_btn)
        analysis_buttons.addWidget(generate_recommendations_btn)
        analysis_buttons.addStretch()
        analysis_layout.addLayout(analysis_buttons)
        
        pentest_tabs.addTab(analysis_tab, "Análisis de Resultados")
        
        layout.addWidget(pentest_tabs)
        self.content_stack.addWidget(pentest_page)
        
    def create_reports_page(self):
        """Crear página de reportes"""
        reports_page = QWidget()
        layout = QVBoxLayout(reports_page)
        
        # Header
        header = QLabel("📊 Generación de Reportes")
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px 0;")
        layout.addWidget(header)
        
        # Splitter para dividir la página
        splitter = QSplitter(Qt.Horizontal)
        
        # Panel izquierdo - Configuración
        config_panel = QWidget()
        config_layout = QVBoxLayout(config_panel)
        
        # Tipo de reporte
        report_type_group = QGroupBox("Tipo de Reporte")
        report_type_layout = QVBoxLayout(report_type_group)
        
        self.executive_summary_radio = QRadioButton("Resumen Ejecutivo")
        self.technical_report_radio = QRadioButton("Reporte Técnico Detallado")
        self.compliance_report_radio = QRadioButton("Reporte de Cumplimiento")
        self.executive_summary_radio.setChecked(True)
        
        for radio in [self.executive_summary_radio, self.technical_report_radio, self.compliance_report_radio]:
            report_type_layout.addWidget(radio)
        
        config_layout.addWidget(report_type_group)
        
        # Configuración de exportación
        export_group = QGroupBox("Configuración de Exportación")
        export_layout = QGridLayout(export_group)
        
        export_layout.addWidget(QLabel("Formato:"), 0, 0)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF", "HTML", "CSV", "JSON"])
        export_layout.addWidget(self.format_combo, 0, 1)
        
        export_layout.addWidget(QLabel("Incluir gráficos:"), 1, 0)
        self.include_charts_check = QCheckBox()
        self.include_charts_check.setChecked(True)
        export_layout.addWidget(self.include_charts_check, 1, 1)
        
        export_layout.addWidget(QLabel("Nivel de detalle:"), 2, 0)
        self.detail_combo = QComboBox()
        self.detail_combo.addItems(["Básico", "Intermedio", "Completo"])
        self.detail_combo.setCurrentText("Intermedio")
        export_layout.addWidget(self.detail_combo, 2, 1)
        
        config_layout.addWidget(export_group)
        
        # Botones de acción
        action_buttons = QVBoxLayout()
        
        generate_btn = QPushButton("Generar Reporte")
        generate_btn.clicked.connect(self.generate_report)
        generate_btn.setStyleSheet(self.get_button_style("#4CAF50"))
        
        preview_btn = QPushButton("Vista Previa")
        preview_btn.clicked.connect(self.preview_report)
        
        export_btn = QPushButton("Exportar")
        export_btn.clicked.connect(self.export_report)
        export_btn.setStyleSheet(self.get_button_style("#2a82da"))
        
        for btn in [generate_btn, preview_btn, export_btn]:
            action_buttons.addWidget(btn)
        
        config_layout.addLayout(action_buttons)
        config_layout.addStretch()
        
        # Panel derecho - Vista previa
        preview_panel = QWidget()
        preview_layout = QVBoxLayout(preview_panel)
        
        preview_label = QLabel("Vista Previa del Reporte")
        preview_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        preview_layout.addWidget(preview_label)
        
        self.report_preview = QTextEdit()
        self.report_preview.setPlainText("""
RESUMEN EJECUTIVO - AUDITORÍA DE SEGURIDAD
==========================================

INFORMACIÓN GENERAL
Organización: Mi Empresa S.A.
Fecha de auditoría: 15 de Junio, 2025
Auditor: SecureGuard Pro v1.0
Alcance: Red corporativa (192.168.1.0/24)

RESUMEN DE HALLAZGOS
Total de vulnerabilidades encontradas: 12
- Críticas: 1
- Altas: 3
- Medias: 5
- Bajas: 3

VULNERABILIDADES CRÍTICAS
1. SMBv1 habilitado en servidor de archivos
   - Riesgo: Ejecución remota de código
   - Recomendación: Deshabilitar SMBv1 inmediatamente

RECOMENDACIONES PRIORITARIAS
1. Aplicar parches de seguridad pendientes
2. Implementar segmentación de red
3. Configurar monitoreo de seguridad 24/7
4. Capacitar al personal en ciberseguridad

CONCLUSIÓN
El nivel de seguridad actual es MEDIO-BAJO.
Se requiere acción inmediata para las vulnerabilidades críticas.
        """)
        self.report_preview.setReadOnly(True)
        preview_layout.addWidget(self.report_preview)
        
        # Agregar paneles al splitter
        splitter.addWidget(config_panel)
        splitter.addWidget(preview_panel)
        splitter.setSizes([300, 700])
        
        layout.addWidget(splitter)
        self.content_stack.addWidget(reports_page)
        
    def create_settings_page(self):
        """Crear página de configuración"""
        settings_page = QWidget()
        layout = QVBoxLayout(settings_page)
        
        # Header
        header = QLabel("⚙️ Configuración y Preferencias")
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px 0;")
        layout.addWidget(header)
        
        # Scroll area para configuraciones
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # Configuración de escaneo
        scan_config = QGroupBox("Configuración de Escaneo")
        scan_config_layout = QGridLayout(scan_config)
        
        scan_config_layout.addWidget(QLabel("Timeout por defecto (ms):"), 0, 0)
        self.default_timeout = QSpinBox()
        self.default_timeout.setRange(100, 10000)
        self.default_timeout.setValue(3000)
        scan_config_layout.addWidget(self.default_timeout, 0, 1)
        
        scan_config_layout.addWidget(QLabel("Threads simultáneos:"), 1, 0)
        self.default_threads = QSpinBox()
        self.default_threads.setRange(1, 200)
        self.default_threads.setValue(50)
        scan_config_layout.addWidget(self.default_threads, 1, 1)
        
        scan_config_layout.addWidget(QLabel("Guardar logs automáticamente:"), 2, 0)
        self.auto_save_logs = QCheckBox()
        self.auto_save_logs.setChecked(True)
        scan_config_layout.addWidget(self.auto_save_logs, 2, 1)
        
        scroll_layout.addWidget(scan_config)
        
        # Configuración de red
        network_config = QGroupBox("Configuración de Red")
        network_config_layout = QGridLayout(network_config)
        
        network_config_layout.addWidget(QLabel("Rango IP por defecto:"), 0, 0)
        self.default_ip_range = QComboBox()
        self.default_ip_range.addItems(["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/24"])
        network_config_layout.addWidget(self.default_ip_range, 0, 1)
        
        network_config_layout.addWidget(QLabel("Usar proxy:"), 1, 0)
        self.use_proxy = QCheckBox()
        network_config_layout.addWidget(self.use_proxy, 1, 1)
        
        scroll_layout.addWidget(network_config)
        
        # Configuración de reportes
        report_config = QGroupBox("Configuración de Reportes")
        report_config_layout = QGridLayout(report_config)
        
        report_config_layout.addWidget(QLabel("Directorio de reportes:"), 0, 0)
        self.reports_dir = QPushButton("Seleccionar directorio...")
        self.reports_dir.clicked.connect(self.select_reports_directory)
        report_config_layout.addWidget(self.reports_dir, 0, 1)
        
        report_config_layout.addWidget(QLabel("Formato por defecto:"), 1, 0)
        self.default_format = QComboBox()
        self.default_format.addItems(["PDF", "HTML", "CSV"])
        report_config_layout.addWidget(self.default_format, 1, 1)
        
        scroll_layout.addWidget(report_config)
        
        # Botones de configuración
        config_buttons = QHBoxLayout()
        save_config_btn = QPushButton("Guardar Configuración")
        save_config_btn.clicked.connect(self.save_configuration)
        save_config_btn.setStyleSheet(self.get_button_style("#4CAF50"))
        
        reset_config_btn = QPushButton("Restablecer por Defecto")
        reset_config_btn.clicked.connect(self.reset_configuration)
        
        config_buttons.addWidget(save_config_btn)
        config_buttons.addWidget(reset_config_btn)
        config_buttons.addStretch()
        
        scroll_layout.addLayout(config_buttons)
        scroll_layout.addStretch()
        
        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)
        
        self.content_stack.addWidget(settings_page)
        
    def get_button_style(self, color):
        """Obtener estilo para botones"""
        return f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }}
            QPushButton:hover {{
                background-color: {color}dd;
            }}
            QPushButton:pressed {{
                background-color: {color}aa;
            }}
        """
    
    def show_page(self, index):
        """Mostrar página específica"""
        self.content_stack.setCurrentIndex(index)
        
        # Actualizar estilo de botones de navegación
        for i, btn in enumerate(self.nav_buttons):
            if i == index:
                btn.setStyleSheet("""
                    QPushButton {
                        text-align: left;
                        padding: 12px 16px;
                        border: none;
                        background-color: #2a82da;
                        color: #ffffff;
                        font-size: 14px;
                        font-weight: bold;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        text-align: left;
                        padding: 12px 16px;
                        border: none;
                        background-color: transparent;
                        color: #ffffff;
                        font-size: 14px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #404040;
                    }
                """)

    def start_quick_scan(self):
        print("[DEBUG] Iniciando escaneo rápido")
        self.quick_progress.setVisible(True)
        self.quick_progress.setValue(0)
        self.results_table.setRowCount(0)
        if hasattr(self, 'log_output'):
            self.log_output.clear()

        self.quick_scan_duration = 10  # segundos (igual que el timeout del sniffer)
        self.quick_scan_elapsed = 0

        # Configurar temporizador visual de barra
        self.quick_timer = QTimer()
        self.quick_timer.timeout.connect(self.update_quick_progress)
        self.quick_timer.start(1000)  # cada 1 segundo

        # Iniciar sniffer
        self.sniffer_thread = SnifferThread(interface=None, timeout=self.quick_scan_duration)
        self.sniffer_thread.progress_updated.connect(self.quick_progress.setValue)
        self.sniffer_thread.scan_complete.connect(self.handle_sniffer_results)
        self.sniffer_thread.log_signal.connect(self.append_log_output)
        self.sniffer_thread.start()

        def append_log_output(self, message):
            self.log_output.append(message)
    def handle_sniffer_results(self, results_list):
        """Actualizar la interfaz con los resultados del sniffer"""
        self.quick_progress.setVisible(False)
        self.quick_progress.setValue(100)

        self.results_table.setRowCount(0)
        for result in results_list:
            total = result['total']
            suspicious = result['suspicious']
            protocols = result['protocols']
            ips = result['ips']

            # Mostrar resultados en tabla
            self.results_table.setRowCount(len(ips))
            row = 0
            for ip, count in ips.items():
                self.results_table.setItem(row, 0, QTableWidgetItem(ip))
                self.results_table.setItem(row, 1, QTableWidgetItem("N/A"))
                self.results_table.setItem(row, 2, QTableWidgetItem("Paquete sospechoso"))
                self.results_table.setItem(row, 3, QTableWidgetItem("Alto"))
                row += 1
            self.log_output.append(f"[+] Total de paquetes capturados: {total}")
            self.log_output.append(f"[!] Paquetes sospechosos detectados: {suspicious}")
            self.log_output.append(f"[i] Protocolos afectados: {protocols}")
            self.log_output.append(f"[i] Archivo guardado en: {result['pcap_file']}")

            QMessageBox.information(self, "Análisis Completado",
                                    f"Total de paquetes: {total}\n"
                                    f"Paquetes sospechosos: {suspicious}\n"
                                    f"Protocolos afectados: {protocols}\n"
                                    f"Guardados en: {result['pcap_file']}")

    def update_quick_progress(self):
        """Actualizar progreso visual del escaneo rápido"""
        self.quick_scan_elapsed += 1
        porcentaje = int((self.quick_scan_elapsed / self.quick_scan_duration) * 100)
        self.quick_progress.setValue(porcentaje)

        if self.quick_scan_elapsed >= self.quick_scan_duration:
            self.quick_timer.stop()

    def start_detailed_scan(self):
        """Iniciar escaneo detallado"""
        self.detailed_progress.setVisible(True)
        self.detailed_progress.setValue(0)
        QMessageBox.information(self, "Análisis Iniciado", "El análisis detallado ha comenzado. Esto puede tomar varios minutos...")
    
    
    def show_port_scan_results(self, port_list):
        self.pentest_progress.setVisible(False)
        if not port_list:
            self.pentest_results.append("[+] No se encontraron puertos abiertos.")
            return

        self.pentest_results.append("PUERTOS ABIERTOS DETECTADOS:\n")
        for puerto, proto in port_list:
            desc = puertos_vulnerables.get(puerto, "No se encontró vulnerabilidad conocida")
            self.pentest_results.append(f"- Puerto {puerto}/{proto}: {desc}")
    

    def start_penetration_test(self):
        reply = QMessageBox.question(
            self,
            "Confirmar Pruebas",
            "¿Está seguro de que desea iniciar las pruebas de penetración?\nAsegúrese de tener autorización para el sistema objetivo.",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
                ip = self.target_ip.currentText()
                self.pentest_progress.setVisible(True)
                self.pentest_progress.setValue(0)
                self.pentest_results.clear()

                self.port_scanner_thread = PortScannerThread(ip)
                self.port_scanner_thread.log_signal.connect(self.append_log_output)
                self.port_scanner_thread.scan_finished.connect(self.show_port_scan_results)
                self.port_scanner_thread.start()


    def export_results(self):
        """Exportar resultados desde la tabla de resultados"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Guardar Resultados",
            "resultados_vulnerabilidades.csv",
            "CSV Files (*.csv);;JSON Files (*.json)"
        )

        if not filename:
            return

        try:
            data = []
            for row in range(self.results_table.rowCount()):
                row_data = {}
                for col in range(self.results_table.columnCount()):
                    header = self.results_table.horizontalHeaderItem(col).text()
                    cell = self.results_table.item(row, col)
                    row_data[header] = cell.text() if cell else ""
                data.append(row_data)

            if filename.endswith(".json"):
                import json
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)
            else:  # CSV por defecto
                import csv
                with open(filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)

            QMessageBox.information(self, "Exportación", f"Resultados exportados a: {filename}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo exportar los resultados:\n{e}")


    def generate_report(self):
        """Generar reporte"""
        QMessageBox.information(self, "Reporte", "Generando reporte... Esto puede tomar unos momentos.")
    
    def preview_report(self):
        """Vista previa del reporte"""
        QMessageBox.information(self, "Vista Previa", "Mostrando vista previa del reporte en el panel derecho.")
    
    def export_report(self):
        """Exportar reporte"""
        format_ext = self.format_combo.currentText().lower()
        filename, _ = QFileDialog.getSaveFileName(self, "Exportar Reporte", 
                                                f"reporte_seguridad.{format_ext}",
                                                f"{format_ext.upper()} Files (*.{format_ext})")
        if filename:
            QMessageBox.information(self, "Exportación", f"Reporte exportado a: {filename}")
    
    def save_pentest_results(self):
        """Guardar resultados de pruebas de penetración"""
        filename, _ = QFileDialog.getSaveFileName(self, "Guardar Resultados de Penetración", 
                                                "resultados_pentest.txt",
                                                "Text Files (*.txt);;JSON Files (*.json)")
        if filename:
            QMessageBox.information(self, "Guardado", f"Resultados guardados en: {filename}")
    
    def select_reports_directory(self):
        """Seleccionar directorio de reportes"""
        directory = QFileDialog.getExistingDirectory(self, "Seleccionar Directorio de Reportes")
        if directory:
            self.reports_dir.setText(f"Directorio: {directory}")
    
    def save_configuration(self):
        """Guardar configuración"""
        QMessageBox.information(self, "Configuración", "Configuración guardada exitosamente.")
    
    def reset_configuration(self):
        """Restablecer configuración por defecto"""
        reply = QMessageBox.question(self, "Restablecer", 
                                   "¿Está seguro de que desea restablecer la configuración por defecto?",
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            QMessageBox.information(self, "Configuración", "Configuración restablecida a valores por defecto.")

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Usar estilo Fusion para mejor apariencia
    
    window = SecurityApp()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()