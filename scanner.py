# neon_port_scanner.py
# PyQt6 Neon-styled Port Scanner ("scary ports" like RDP, Tor, SMB, etc.)
# - Dark surface UI with purple glowing borders and text
# - Non-blocking: scanning runs in a QThread and uses a ThreadPoolExecutor
# - Shows live results and final SAFE / UNSAFE verdict
# - Added Self Scan / Targeted Scan toggle with auto-detect local IP
#
# Usage:
# 1. Install dependencies: pip install PyQt6
# 2. Run: python neon_port_scanner.py
#
# WARNING: Only scan machines/networks you own or have permission to test.

import socket
import concurrent.futures
import sys
import time
import os

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QPlainTextEdit,
    QFrame, QSizePolicy, QRadioButton, QButtonGroup
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import QGraphicsDropShadowEffect


# --- CONFIG: risky ports to check ---
RISKY_PORTS = [
    (22, "SSH - Secure Shell"),
    (23, "Telnet - Unencrypted remote login"),
    (445, "SMB - Windows File Sharing"),
    (3389, "RDP - Remote Desktop Protocol"),
    (5900, "VNC - Remote Desktop"),
    (9001, "Tor Relay ORPort"),
    (9002, "Tor Additional ORPort"),
    (9030, "Tor Directory Port"),
    (9050, "Tor SOCKS Proxy"),
    (9150, "Tor Browser SOCKS Proxy"),
    (1080, "SOCKS Proxy (generic)"),
    (21, "FTP - File Transfer Protocol"),
    (1433, "Microsoft SQL Server"),
    (3306, "MySQL Database"),
    (5432, "PostgreSQL Database"),
    (5060, "SIP - VoIP"),
    (8080, "HTTP Alternate / Proxy"),
    (8443, "HTTPS Alternate"),
]

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # connect to public IP, no packets sent
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


# Scanner thread will run the network checks and emit results
class ScannerThread(QThread):
    result_signal = pyqtSignal(int, bool, str)  # port, is_open, description
    finished_signal = pyqtSignal(list)  # list of open ports
    progress_signal = pyqtSignal(str)  # status text

    def __init__(self, target: str, ports: list, timeout: float = 0.6):
        super().__init__()
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self._stopped = False

    def stop(self):
        self._stopped = True

    def scan_port(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                res = sock.connect_ex((host, port))
                return res == 0
        except Exception:
            return False

    def run(self):
        open_ports = []
        total = len(self.ports)
        self.progress_signal.emit(f"Starting scan of {self.target} ({total} ports)")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_map = {executor.submit(self.scan_port, self.target, p): (p, desc) for p, desc in self.ports}
            checked = 0
            for fut in concurrent.futures.as_completed(future_map):
                if self._stopped:
                    self.progress_signal.emit("Scan stopped by user.")
                    break
                port, desc = future_map[fut]
                try:
                    is_open = fut.result()
                except Exception:
                    is_open = False
                checked += 1
                self.progress_signal.emit(f"Checked {checked}/{total} ports")
                self.result_signal.emit(port, is_open, desc)
                if is_open:
                    open_ports.append((port, desc))

        self.finished_signal.emit(open_ports)


# Main GUI
class NeonScannerUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Neon Port Safety Scanner")
        base_dir = os.path.dirname(__file__)
        icon_path = os.path.join(base_dir, "icons", "icon.png")
        self.setWindowIcon(QIcon(icon_path))
        self.setMinimumSize(760, 520)
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.scanner_thread = None
        self._build_ui()
        self.local_ip = get_local_ip()
        self.ip_input.setText(self.local_ip)
        self.toggle_mode_changed()

    def _build_ui(self):
        root = QVBoxLayout()
        root.setContentsMargins(18, 18, 18, 18)

        # Title
        title_frame = QFrame()
        title_frame.setObjectName("neonFrame")
        title_layout = QHBoxLayout()
        title_frame.setLayout(title_layout)
        title_label = QLabel("NEON PORT SAFETY SCANNER")
        title_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_layout.addWidget(title_label)

        # Scan mode toggles
        mode_frame = QFrame()
        mode_layout = QHBoxLayout()
        mode_frame.setLayout(mode_layout)

        self.radio_self = QRadioButton("Self Scan (Local IP)")
        self.radio_target = QRadioButton("Targeted Scan (Enter IP)")
        self.radio_self.setChecked(True)
        self.radio_self.toggled.connect(self.toggle_mode_changed)

        mode_layout.addWidget(self.radio_self)
        mode_layout.addWidget(self.radio_target)

        # Controls frame
        control_frame = QFrame()
        control_layout = QHBoxLayout()
        control_frame.setLayout(control_layout)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP (e.g. 127.0.0.1)")
        self.ip_input.setFixedHeight(36)
        self.ip_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self.scan_btn = QPushButton("SCAN")
        self.scan_btn.setFixedWidth(110)
        self.scan_btn.setFixedHeight(36)
        self.scan_btn.clicked.connect(self.on_scan_clicked)

        self.stop_btn = QPushButton("STOP")
        self.stop_btn.setFixedWidth(110)
        self.stop_btn.setFixedHeight(36)
        self.stop_btn.clicked.connect(self.on_stop_clicked)
        self.stop_btn.setEnabled(False)

        control_layout.addWidget(self.ip_input)
        control_layout.addWidget(self.scan_btn)
        control_layout.addWidget(self.stop_btn)

        # Result area
        result_frame = QFrame()
        result_layout = QVBoxLayout()
        result_frame.setLayout(result_layout)

        self.result_text = QPlainTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setMinimumHeight(300)
        self.result_text.setStyleSheet(
            "QPlainTextEdit {background: #0d0d10; border: none; font-family: 'Consolas', monospace; font-size: 12px;}")

        verdict_layout = QHBoxLayout()
        self.verdict_label = QLabel("Status: Idle")
        self.verdict_label.setFont(QFont("Segoe UI", 12, QFont.Weight.DemiBold))
        verdict_layout.addWidget(self.verdict_label, alignment=Qt.AlignmentFlag.AlignLeft)

        hint_label = QLabel("Only scan systems you own or have permission to test.")
        hint_label.setStyleSheet("color: #a091c9; font-size: 11px;")
        verdict_layout.addWidget(hint_label, alignment=Qt.AlignmentFlag.AlignRight)

        result_layout.addWidget(self.result_text)
        result_layout.addLayout(verdict_layout)

        footer = QLabel("Developed By MaxMouse — Neon style port safety check")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("font-size: 11px; color: #cbb7ff;")

        # Assemble all
        root.addWidget(title_frame)
        root.addSpacing(8)
        root.addWidget(mode_frame)
        root.addSpacing(6)
        root.addWidget(control_frame)
        root.addSpacing(10)
        root.addWidget(result_frame)
        root.addSpacing(8)
        root.addWidget(footer)

        self.setLayout(root)
        self._apply_styles(title_frame)

    def _apply_styles(self, title_frame):
        self.setStyleSheet("""
            QWidget {
                background-color: #07060a;
                color: #d7cfff;
            }
            #neonFrame {
                background: QLinearGradient(spread:pad, x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(30,8,60,200), stop:1 rgba(50,12,80,200));
                border-radius: 12px;
                border: 2px solid rgba(160,80,255,0.9);
            }
            QPushButton {
                background: transparent;
                border-radius: 8px;
                border: 1px solid rgba(150,80,255,0.9);
                padding: 6px;
                color: #e7d9ff;
                font-weight: 600;
            }
            QPushButton:hover { box-shadow: 0 0 14px rgba(160,80,255,0.18); }
            QPushButton:pressed { background: rgba(120,40,220,0.12); }
            QLineEdit {
                background: #0b0b0e;
                border: 1px solid rgba(120,60,220,0.85);
                border-radius: 8px;
                padding-left: 10px;
                color: #e6ddff;
            }
            QLabel { color: #d9ccff; }
            QRadioButton {
                color: #b288ff;
                font-weight: 600;
            }
            QRadioButton::indicator:checked {
                background-color: #9f7bff;
                border: 1px solid #cbb7ff;
            }
        """)

        glow = QGraphicsDropShadowEffect(self)
        glow.setBlurRadius(28)
        glow.setOffset(0, 0)
        glow.setColor(Qt.GlobalColor.white)  # purple glow effect
        title_frame.setGraphicsEffect(glow)

        for child in title_frame.children():
            if isinstance(child, QLabel):
                child.setStyleSheet(
                    "color: QLinearGradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #f2e6ff, stop:1 #b28cff); font-size: 16px;")

        title_frame.setStyleSheet(title_frame.styleSheet() + "\nQFrame { box-shadow: 0 0 20px rgba(150,80,255,0.9); }")

    def toggle_mode_changed(self):
        if self.radio_self.isChecked():
            self.ip_input.setText(self.local_ip)
            self.ip_input.setEnabled(False)
        else:
            self.ip_input.setEnabled(True)

    def on_scan_clicked(self):
        target = self.ip_input.text().strip()
        if not target:
            self._append_line("Please enter an IP address (e.g. 127.0.0.1)")
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.result_text.clear()
        self._set_verdict("Scanning...", color="#c9a1ff")

        self.scanner_thread = ScannerThread(target, RISKY_PORTS, timeout=0.6)
        self.scanner_thread.result_signal.connect(self._on_port_result)
        self.scanner_thread.progress_signal.connect(self._on_progress)
        self.scanner_thread.finished_signal.connect(self._on_finished)
        self.scanner_thread.start()

    def on_stop_clicked(self):
        if self.scanner_thread:
            self.scanner_thread.stop()
            self._append_line("Stopping scan...")
            self.stop_btn.setEnabled(False)

    def _on_progress(self, text):
        self._append_line(f"[info] {text}")

    def _on_port_result(self, port, is_open, desc):
        if is_open:
            self._append_line(f"[OPEN] Port {port}: {desc}")
        else:
            self._append_line(f"[closed] Port {port}")

    def _on_finished(self, open_ports):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if open_ports:
            self._set_verdict("UNSAFE - Open risky ports found", color="#ff6b6b")
            self._append_line("\nScan complete: Potential issues found. Please secure these ports and verify services.")
            for p, desc in open_ports:
                self._append_line(f" -> {p}: {desc}")
        else:
            self._set_verdict("SAFE - No risky ports open", color="#8cffc9")
            self._append_line("\nScan complete: No risky ports found. System looks safe (for the checked ports).")

    def _append_line(self, text: str):
        timestamp = time.strftime('%H:%M:%S')
        self.result_text.appendPlainText(f"[{timestamp}] {text}")

    def _set_verdict(self, text: str, color: str = "#c9a1ff"):
        self.verdict_label.setText(f"Status: {text}")
        self.verdict_label.setStyleSheet(f"color: {color}; font-weight: 700;")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = NeonScannerUI()
    ui.show()
    sys.exit(app.exec())
