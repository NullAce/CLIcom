import socket
import threading
import argparse
from datetime import datetime
from colorama import Fore, Style, init
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Initialize colorama
init(autoreset=True)

# Configuration
PORT = 65432  # Port to use for communication
BUFFER_SIZE = 1024

# Generate Diffie-Hellman parameters (used by both server and client)
dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Function to derive a shared key using Diffie-Hellman
def derive_shared_key(private_key: DHPrivateKey, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    # Use HKDF to derive a strong encryption key from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

# Helper functions for encryption and decryption
def derive_key(shared_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_key.encode())

def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_message(key, ciphertext):
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded_plaintext = decryptor.update(data[16:]) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

# Function to handle sending messages
def send_messages(sock, key):
    while True:
        msg = input()
        if msg.lower() == "exit":
            print(f"{Fore.YELLOW}[INFO] Closing connection...")
            encrypted_exit = encrypt_message(key, "EXIT")
            sock.sendall(encrypted_exit.encode())  # Notify the other side
            sock.close()
            break
        encrypted_msg = encrypt_message(key, msg)
        sock.sendall(encrypted_msg.encode())  # Send the encrypted message to the peer

# Function to handle receiving messages
def receive_messages(sock, key):
    while True:
        try:
            data = sock.recv(BUFFER_SIZE)
            if not data:
                print(f"{Fore.YELLOW}[INFO] Connection closed by peer.")
                break
            decrypted_data = decrypt_message(key, data.decode())
            if decrypted_data == "EXIT":
                print(f"{Fore.YELLOW}[INFO] Peer has exited. Closing connection...")
                sock.close()
                break
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n{Fore.CYAN}[{timestamp}] Peer: {decrypted_data}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Connection error: {e}")
            break

# Parse arguments
parser = argparse.ArgumentParser(description="CLI Chat Application")
parser.add_argument("--key", required=True, help="Shared key to connect devices")
parser.add_argument("--mode", required=True, choices=["server", "client"], help="Run as server or client")
args = parser.parse_args()

shared_key = args.key
mode = args.mode

if mode == "server":
    # Run as server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind(("0.0.0.0", PORT))
        server_socket.listen(1)
        print(f"{Fore.YELLOW}[INFO] Waiting for connection...")
        conn, addr = server_socket.accept()
        print(f"{Fore.YELLOW}[INFO] Connected to {addr}")

        # Generate server's private and public keys
        server_private_key = dh_parameters.generate_private_key()
        server_public_key = server_private_key.public_key()

        # Send server's public key to the client
        server_public_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(server_public_bytes)

        # Receive client's public key
        client_public_bytes = conn.recv(BUFFER_SIZE)
        client_public_key = serialization.load_pem_public_key(client_public_bytes, backend=default_backend())

        # Derive the shared encryption key
        encryption_key = derive_shared_key(server_private_key, client_public_key)
        print(f"{Fore.GREEN}[INFO] Shared encryption key established.")

        # Start sending and receiving threads
        send_thread = threading.Thread(target=send_messages, args=(conn, encryption_key))
        receive_thread = threading.Thread(target=receive_messages, args=(conn, encryption_key))
        send_thread.start()
        receive_thread.start()

        # Wait for threads to finish
        send_thread.join()
        receive_thread.join()

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Server error: {e}")

else:
    # Run as client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Automatically resolve the server's hostname
        server_host = socket.gethostname()
        client_socket.connect((server_host, PORT))
        print(f"{Fore.YELLOW}[INFO] Connected to server!")

        # Generate client's private and public keys
        client_private_key = dh_parameters.generate_private_key()
        client_public_key = client_private_key.public_key()

        # Receive server's public key
        server_public_bytes = client_socket.recv(BUFFER_SIZE)
        server_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())

        # Send client's public key to the server
        client_public_bytes = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(client_public_bytes)

        # Derive the shared encryption key
        encryption_key = derive_shared_key(client_private_key, server_public_key)
        print(f"{Fore.GREEN}[INFO] Shared encryption key established.")

        # Start sending and receiving threads
        send_thread = threading.Thread(target=send_messages, args=(client_socket, encryption_key))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, encryption_key))
        send_thread.start()
        receive_thread.start()

        # Wait for threads to finish
        send_thread.join()
        receive_thread.join()

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Connection failed: {e}")
