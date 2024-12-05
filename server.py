import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import urlsafe_b64encode

AES_KEY_LENGTH = 32  # Length of the AES key in bytes

clients = {}  # Dictionary to store client_socket -> public_key
global_aes_key = os.urandom(AES_KEY_LENGTH)  # Single AES key for all clients


def rsa_encrypt_value(value, public_key):
    """Encrypt a value using the recipient's public RSA key."""
    encrypted_value = public_key.encrypt(
        value,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[DEBUG] Encrypted AES key: {urlsafe_b64encode(encrypted_value).decode()}")
    return encrypted_value


def handle_client(client_socket, address):
    """Handle communication with a connected client."""
    print(f"[DEBUG] New connection from {address}")

    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            if data.startswith(b"PUBLIC_KEY:"):
                public_key_pem = data[len(b"PUBLIC_KEY:"):]
                public_key = serialization.load_pem_public_key(public_key_pem)
                print(f"[DEBUG] Received and stored public key from {address}:\n{public_key_pem.decode()}")
                clients[client_socket] = public_key

                # Encrypt and send the global AES key
                encrypted_aes_key = rsa_encrypt_value(global_aes_key, public_key)
                client_socket.send(b"AES_KEY:" + encrypted_aes_key)

            else:
                # Relay encrypted messages to all other clients
                relay_data(client_socket, data)

    except Exception as e:
        print(f"[ERROR] Error handling client {address}: {e}")
    finally:
        client_socket.close()
        if client_socket in clients:
            del clients[client_socket]
        print(f"[DEBUG] Client {address} disconnected.")


def relay_data(sender_socket, data):
    """Relay encrypted messages to all other clients except the sender."""
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                client_socket.send(data)
            except Exception as e:
                print(f"[ERROR] Failed to relay data to a client: {e}")


def start_server():
    """Start the server."""
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 12345

    print("[DEBUG] Starting server...")
    print(f"[DEBUG] Generated Global AES Key: {urlsafe_b64encode(global_aes_key).decode()}")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[DEBUG] Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, address), daemon=True).start()


if __name__ == "__main__":
    start_server()
