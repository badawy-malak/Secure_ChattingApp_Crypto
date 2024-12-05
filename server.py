import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode

AES_KEY_LENGTH = 32  # 256-bit AES key
BLOCK_SIZE = 16      # AES block size (for IV)

clients = []  # List of connected clients (socket, address)
shared_aes_key = None  # AES key shared with all clients


def generate_aes_key():
    """Generate a random AES key."""
    key = os.urandom(AES_KEY_LENGTH)
    print(f"[DEBUG] Generated AES key (Base64): {urlsafe_b64encode(key).decode()}")
    return key


def aes_encrypt(message, key):
    """Encrypt a message using AES-GCM."""
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    encrypted_message = iv + encryptor.tag + ciphertext
    print(f"[DEBUG] Encrypted message (Base64): {urlsafe_b64encode(encrypted_message).decode()}")
    return encrypted_message


def aes_decrypt(encrypted_message, key):
    """Decrypt a message using AES-GCM."""
    iv = encrypted_message[:BLOCK_SIZE]
    tag = encrypted_message[BLOCK_SIZE:BLOCK_SIZE + BLOCK_SIZE]
    ciphertext = encrypted_message[BLOCK_SIZE + BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print(f"[DEBUG] Decrypted message: {plaintext.decode()}")
    return plaintext.decode()


def broadcast_aes_key():
    """Broadcast the AES key to all connected clients."""
    global shared_aes_key
    for client_socket, _ in clients:
        try:
            encrypted_key = urlsafe_b64encode(shared_aes_key)
            client_socket.send(f"AES_KEY:{encrypted_key.decode()}".encode())
            print(f"[DEBUG] Sent AES key to client: {encrypted_key.decode()}")
        except Exception as e:
            print(f"[ERROR] Failed to send AES key to client: {e}")


def relay_data(sender_socket, data):
    """Relay encrypted messages to all clients except the sender."""
    for client_socket, _ in clients:
        if client_socket != sender_socket:
            try:
                client_socket.send(data)
            except Exception as e:
                print(f"[ERROR] Failed to relay data to a client: {e}")
                clients.remove((client_socket, _))


def handle_client(client_socket, address):
    """Handle communication with a connected client."""
    global shared_aes_key
    print(f"[DEBUG] New connection from {address}")
    try:
        while True:
            data = client_socket.recv(2048)
            if not data:
                break
            if data.startswith(b"AES_KEY_REQUEST"):
                # Handle AES key request from client
                broadcast_aes_key()
            else:
                print(f"[DEBUG] Relaying encrypted message from {address}: {data.hex()}")
                relay_data(client_socket, data)
    except Exception as e:
        print(f"[ERROR] Error handling client {address}: {e}")
    finally:
        client_socket.close()
        clients.remove((client_socket, address))
        print(f"[DEBUG] Client {address} disconnected.")


def start_server():
    """Start the server."""
    global shared_aes_key
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 12345

    print("[DEBUG] Starting server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"[DEBUG] Server listening on {SERVER_HOST}:{SERVER_PORT}")

    # Generate AES key
    shared_aes_key = generate_aes_key()

    while True:
        client_socket, address = server_socket.accept()
        clients.append((client_socket, address))
        threading.Thread(target=handle_client, args=(client_socket, address)).start()


if __name__ == "__main__":
    start_server()
