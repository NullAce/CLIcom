import socket
import threading
import argparse
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configuration
PORT = 65432  # Port to use for communication
BUFFER_SIZE = 1024

# Function to handle sending messages
def send_messages(sock):
    while True:
        msg = input()
        if msg.lower() == "exit":
            print(f"{Fore.YELLOW}[INFO] Closing connection...")
            sock.sendall("EXIT".encode())  # Notify the other side
            sock.close()
            break
        sock.sendall(msg.encode())  # Send the message to the peer

# Function to handle receiving messages
def receive_messages(sock):
    while True:
        try:
            data = sock.recv(BUFFER_SIZE)
            if not data:
                print(f"{Fore.YELLOW}[INFO] Connection closed by peer.")
                break
            decoded_data = data.decode()
            if decoded_data == "EXIT":
                print(f"{Fore.YELLOW}[INFO] Peer has exited. Closing connection...")
                sock.close()
                break
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n{Fore.CYAN}[{timestamp}] Peer: {decoded_data}")
        except:
            print(f"{Fore.RED}[ERROR] Connection error.")
            break

# Prompt user for configuration
shared_key = input("Enter the shared key: ").strip()
mode = input("Enter mode (server/client) [default: client]: ").strip().lower() or "client"
host = None
if mode == "client":
    host = input("Enter server IP address [default: 127.0.0.1]: ").strip() or "127.0.0.1"

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

        # Verify shared key
        conn.sendall("KEY?".encode())
        client_key = conn.recv(BUFFER_SIZE).decode()
        if client_key != shared_key:
            print(f"{Fore.RED}[ERROR] Authentication failed. Closing connection.")
            conn.sendall("AUTH_FAILED".encode())
            conn.close()
        else:
            print(f"{Fore.GREEN}[INFO] Authentication successful.")
            conn.sendall("AUTH_SUCCESS".encode())

            # Start sending and receiving threads
            send_thread = threading.Thread(target=send_messages, args=(conn,))
            receive_thread = threading.Thread(target=receive_messages, args=(conn,))
            send_thread.start()
            receive_thread.start()

            # Wait for threads to finish
            send_thread.join()
            receive_thread.join()

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Server error: {e}")

else:
    # Run as client
    if not host:
        print(f"{Fore.RED}[ERROR] Host IP address is required for client mode.")
        exit(1)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((host, PORT))
        print(f"{Fore.YELLOW}[INFO] Connected to server!")

        # Verify shared key
        server_challenge = client_socket.recv(BUFFER_SIZE).decode()
        if server_challenge == "KEY?":
            client_socket.sendall(shared_key.encode())
            server_response = client_socket.recv(BUFFER_SIZE).decode()
            if server_response == "AUTH_SUCCESS":
                print(f"{Fore.GREEN}[INFO] Authentication successful.")

                # Start sending and receiving threads
                send_thread = threading.Thread(target=send_messages, args=(client_socket,))
                receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
                send_thread.start()
                receive_thread.start()

                # Wait for threads to finish
                send_thread.join()
                receive_thread.join()
            else:
                print(f"{Fore.RED}[ERROR] Authentication failed. Closing connection.")
                client_socket.close()
        else:
            print(f"{Fore.RED}[ERROR] Unexpected server response. Closing connection.")
            client_socket.close()

    except Exception as e:
        print(f"{Fore.RED}[ERROR] Connection failed: {e}")