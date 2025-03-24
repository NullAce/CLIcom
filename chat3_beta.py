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

clients = []  # List to keep track of connected clients

# Function to handle sending messages to all clients
def broadcast_message(msg, sender_sock=None):
    for client in clients:
        if client != sender_sock:  # Don't send the message back to the sender
            try:
                client.sendall(msg.encode())
            except:
                clients.remove(client)
                client.close()

# Function to handle sending messages
def send_messages(sock):
    while True:
        msg = input()
        if msg.lower() == "exit":
            print(f"{Fore.YELLOW}[INFO] Closing connection...")
            sock.sendall("EXIT".encode())  # Notify the other side
            sock.close()
            break
        broadcast_message(msg)

# Function to handle receiving messages from a single client
def handle_client(sock):
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
            broadcast_message(decoded_data, sock)
        except:
            print(f"{Fore.RED}[ERROR] Connection error.")
            break

# Parse arguments
parser = argparse.ArgumentParser(description="CLI Chat Application")
parser.add_argument("--key", required=True, help="Shared key to connect devices")
parser.add_argument("--mode", required=True, choices=["server", "client"], help="Run as server or client")
parser.add_argument("--host", help="Server IP address (for client mode)")
args = parser.parse_args()

shared_key = args.key
mode = args.mode
host = args.host

if mode == "server":
    # Run as server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind(("0.0.0.0", PORT))
        server_socket.listen(5)  # Listen for up to 5 connections
        print(f"{Fore.YELLOW}[INFO] Waiting for connections...")

        while True:
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

                clients.append(conn)  # Add the client to the list

                # Start a new thread to handle the new client
                client_thread = threading.Thread(target=handle_client, args=(conn,))
                client_thread.start()

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
                receive_thread = threading.Thread(target=handle_client, args=(client_socket,))
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