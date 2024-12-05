import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

BLOCK_SIZE = 16  # AES block size (for IV)
shared_aes_key = None  # AES key shared with the server


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


def request_aes_key(client_socket):
    """Request the AES key from the server."""
    client_socket.send(b"AES_KEY_REQUEST")
    print("[DEBUG] Requested AES key from server.")


def receive_data(client_socket):
    """Receive and process data from the server."""
    global shared_aes_key
    while True:
        try:
            data = client_socket.recv(2048)
            if not data:
                break
            message = data.decode(errors="replace")
            if message.startswith("AES_KEY:"):
                encrypted_key = urlsafe_b64decode(message[len("AES_KEY:"):])
                print(f"[DEBUG] Received AES key: {urlsafe_b64encode(encrypted_key).decode()}")
                shared_aes_key = encrypted_key
            else:
                # Process encrypted message
                encrypted_message = urlsafe_b64decode(message)
                plaintext = aes_decrypt(encrypted_message, shared_aes_key)
                print(f"[MESSAGE] Decrypted broadcasted message: {plaintext}")
        except Exception as e:
            print(f"[ERROR] Error processing received data: {e}")
            break


def start_client():
    global shared_aes_key
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 12345

    print("[DEBUG] Connecting to server...")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    try:
        threading.Thread(target=receive_data, args=(client_socket,), daemon=True).start()

        # Request AES key from the server
        request_aes_key(client_socket)

        while True:
            if shared_aes_key is None:
                print("[DEBUG] Waiting for AES key...")
                continue

            message = input("Enter message to send (type 'exit' to quit): ")
            if message.lower() == "exit":
                break
            encrypted_message = aes_encrypt(message, shared_aes_key)
            client_socket.send(urlsafe_b64encode(encrypted_message))
    finally:
        client_socket.close()
        print("[DEBUG] Client disconnected.")


if __name__ == "__main__":
    start_client()
