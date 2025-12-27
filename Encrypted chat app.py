import socket
import threading
import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

HOST = "127.0.0.1"
PORT = 6000   # ✅ CHANGED PORT (IMPORTANT)
KEY = b"this_is_a_32_byte_secret_key!!xx"
LOG_FILE = "chat.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(message)s")

clients = []

# ---------- ENCRYPT ----------
def encrypt(msg):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(msg.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded) + encryptor.finalize()

def decrypt(data):
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

# ---------- SERVER ----------
def broadcast(data, sender):
    for c in clients:
        if c != sender:
            try:
                c.send(data)
            except:
                clients.remove(c)

def handle_client(c, addr):
    print(f"[+] Connected: {addr}")
    while True:
        try:
            data = c.recv(4096)
            if not data:
                break
            broadcast(data, c)
        except:
            break
    print(f"[-] Disconnected: {addr}")
    clients.remove(c)
    c.close()

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # ✅ FIX
    s.bind((HOST, PORT))
    s.listen()
    print(f"✅ Server running on {HOST}:{PORT}")
    while True:
        c, addr = s.accept()
        clients.append(c)
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()

# ---------- CLIENT ----------
def receive_messages(c):
    while True:
        try:
            print("Friend:", decrypt(c.recv(4096)))
        except:
            break

def start_client():
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect((HOST, PORT))
    threading.Thread(target=receive_messages, args=(c,), daemon=True).start()
    while True:
        c.send(encrypt(input("You: ")))

# ---------- MAIN ----------
if __name__ == "__main__":
    mode = input("Enter mode (server/client): ").strip().lower()
    if mode == "server":
        start_server()
    elif mode == "client":
        start_client()
    else:
        print("Invalid mode")
