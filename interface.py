import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                               QPushButton, QLabel, QTextEdit, QLineEdit, QTableWidget, QTableWidgetItem,
                               QHeaderView, QGroupBox, QGridLayout, QMessageBox, QProgressBar)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QPalette

import port_scanner
import sniffer
import keylogger

class ScannerThread(QThread):
    result_ready = Signal(dict)

    def __init__(self, ip):
        super().__init__()
        self.ip = ip

    def run(self):
        result = port_scanner.escanear_puertos(self.ip)
        self.result_ready.emit(result)

class SnifferThread(QThread):
    result_ready = Signal(list, list)

    def run(self):
        paquetes, links = sniffer.capturar_paquetes()
        self.result_ready.emit(paquetes, links)

class KeyloggerThread(QThread):
    result_ready = Signal(list)

    def run(self):
        data = keylogger.detect_suspicious_connections()
        self.result_ready.emit(data)

class SecurityApp(QMainWindow):
    from PySide6.QtCore import QTimer

    def update_progress(self, bar):
        bar.setValue(0)
        self.timer = QTimer()
        self.timer.timeout.connect(lambda: self.advance_bar(bar))
        self.timer.start(50)

    def advance_bar(self, bar):
        current = bar.value()
        if current < 100:
            bar.setValue(current + 5)
        else:
            self.timer.stop()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureGuard Pro - Auditoría Modular")
        self.setGeometry(100, 100, 1200, 800)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        header = QLabel("🔍 Módulos de Escaneo de Seguridad")
        header.setStyleSheet("font-size: 22px; font-weight: bold;")
        main_layout.addWidget(header)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.init_port_scan_tab()
        self.init_sniffer_tab()
        self.init_keylogger_tab()

    def init_port_scan_tab(self):
        tab = QWidget()
        layout = QHBoxLayout(tab)

        controls = QVBoxLayout()
        layout.addLayout(controls, 1)

        controls.addWidget(QLabel("IP objetivo:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Ej. 192.168.1.1")
        controls.addWidget(self.ip_input)

        btn = QPushButton("Iniciar Escaneo")
        btn.clicked.connect(self.run_port_scan)
        controls.addWidget(btn)
        controls.addStretch()

        self.port_output = QTextEdit()
        self.port_output.setReadOnly(True)
        
        self.port_progress = QProgressBar()
        self.port_progress.setValue(0)
        controls.addWidget(self.port_progress)
        layout.addWidget(self.port_output, 3)
    

        self.tabs.addTab(tab, "Escaneo de Puertos")

    def init_sniffer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        btn = QPushButton("Capturar 50 paquetes")
        btn.clicked.connect(self.run_sniffer)
        layout.addWidget(btn)

        self.sniff_output = QTextEdit()
        self.sniff_output.setReadOnly(True)
        
        self.sniff_progress = QProgressBar()
        self.sniff_progress.setValue(0)
        layout.addWidget(self.sniff_progress)
        layout.addWidget(self.sniff_output)
    

        self.tabs.addTab(tab, "Sniffer de Red")

    def init_keylogger_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        btn = QPushButton("Buscar conexiones sospechosas")
        btn.clicked.connect(self.run_keylogger)
        layout.addWidget(btn)

        self.keylog_output = QTableWidget()
        self.keylog_output.setColumnCount(5)
        self.keylog_output.setHorizontalHeaderLabels(["Proceso", "PID", "Origen", "Destino", "Estado"])
        self.keylog_output.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        self.keylog_progress = QProgressBar()
        self.keylog_progress.setValue(0)
        layout.addWidget(self.keylog_progress)
        layout.addWidget(self.keylog_output)
    

        self.tabs.addTab(tab, "Keylogger / Conexiones")

    def run_port_scan(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Error", "Debe ingresar una IP.")
            return
        self.port_output.clear()
        self.thread = ScannerThread(ip)
        self.thread.result_ready.connect(self.display_port_results)
        self.port_progress.setValue(0)
        self.thread.start()
        self.update_progress(self.port_progress)

    def display_port_results(self, data):
        self.port_output.append(f"Estado del host: {data['estado_host']}")
        for puerto, proto in data["puertos_abiertos"]:
            self.port_output.append(f"Puerto abierto: {puerto}/{proto}")
        if data["vulnerables"]:
            self.port_output.append("\n[!] Vulnerabilidades detectadas:")
            for vuln in data["vulnerables"]:
                self.port_output.append(f"Puerto {vuln['puerto']}: {vuln['descripcion']}")
        else:
            self.port_output.append("\nNo se detectaron vulnerabilidades conocidas.")

    def run_sniffer(self):
        self.sniff_output.clear()
        self.sniff_thread = SnifferThread()
        self.sniff_thread.result_ready.connect(self.display_sniff_results)
        self.sniff_progress.setValue(0)
        self.sniff_thread.start()
        self.update_progress(self.sniff_progress)

    def display_sniff_results(self, packets, links):
        for pkt in packets:
            self.sniff_output.append(f"{pkt['tiempo']} {pkt['origen']}->{pkt['destino']} {pkt['nombre']} TTL={pkt['ttl']} Flags={pkt['flags']}")
        if links:
            self.sniff_output.append("\n🌐 Enlaces HTTP detectados:")
            for i, link in enumerate(links, 1):
                self.sniff_output.append(f"{i}. {link}")
        else:
            self.sniff_output.append("\nNo se detectaron enlaces HTTP.")

    def run_keylogger(self):
        self.keylog_output.setRowCount(0)
        self.keylog_thread = KeyloggerThread()
        self.keylog_thread.result_ready.connect(self.display_keylogger_results)
        self.keylog_progress.setValue(0)
        self.keylog_thread.start()
        self.update_progress(self.keylog_progress)

    def display_keylogger_results(self, rows):
        self.keylog_output.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                if row[4] != "ESTABLISHED":
                    item.setBackground(QColor("#FFCDD2"))  # rojo claro si estado no es "establecido"
                self.keylog_output.setItem(i, j, item)


        app.setStyle('Fusion')
        dark_palette = app.palette()
        dark_palette.setColor(app.palette().Window, QColor(30, 30, 30))
        dark_palette.setColor(app.palette().WindowText, QColor(255, 255, 255))
        dark_palette.setColor(app.palette().Base, QColor(25, 25, 25))
        dark_palette.setColor(app.palette().AlternateBase, QColor(30, 30, 30))
        dark_palette.setColor(app.palette().ToolTipBase, QColor(255, 255, 255))
        dark_palette.setColor(app.palette().ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(app.palette().Text, QColor(255, 255, 255))
        dark_palette.setColor(app.palette().Button, QColor(45, 45, 45))
        dark_palette.setColor(app.palette().ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(app.palette().BrightText, QColor(255, 0, 0))
        dark_palette.setColor(app.palette().Link, QColor(42, 130, 218))
        dark_palette.setColor(app.palette().Highlight, QColor(42, 130, 218))
        dark_palette.setColor(app.palette().HighlightedText, QColor(0, 0, 0))
        app.setPalette(dark_palette)


def main():
    app = QApplication(sys.argv)
    # Estilo oscuro
    app.setStyle('Fusion')
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(30, 30, 30))
    dark_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.AlternateBase, QColor(30, 30, 30))
    dark_palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.Text, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.Button, QColor(45, 45, 45))
    dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
    app.setPalette(dark_palette)

    win = SecurityApp()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

    def update_progress(self, bar):
        from PySide6.QtCore import QTimer
        bar.setValue(0)
        self.timer = QTimer()
        def update():
            v = bar.value()
            if v < 100:
                bar.setValue(v + 5)
            else:
                self.timer.stop()
        self.timer.timeout.connect(update)
        self.timer.start(50)