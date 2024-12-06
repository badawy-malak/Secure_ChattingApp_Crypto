import socket
import threading
import os
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode
import bcrypt

AES_KEY_LENGTH = 32  # Length of the AES key in bytes
clients = {}  # Dictionary to store client_socket -> public_key
global_aes_key = os.urandom(AES_KEY_LENGTH)  # Single AES key for all clients
DATABASE_NAME = "chat_app2.db"

def initialize_database():
    """Create the database and tables if they don't exist."""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()

        # Users table for signup/login
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT
            )
        """)

        # Messages table for storing chat history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                aes_key TEXT,
                message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)


        conn.commit()
        conn.close()
        print("[DEBUG] Database initialized with users and messages tables.")
    except Exception as e:
        print(f"[ERROR] Failed to initialize database: {e}")


def aes_encrypt(message, key):
    """Encrypt a message using AES-GCM."""
    iv = os.urandom(12)  # 12-byte IV for AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext


def aes_decrypt(encrypted_message, key):
    """Decrypt a message using AES-GCM."""
    try:
        iv = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        print(f"[DEBUG] Successfully decrypted message: {plaintext}")
        return plaintext.decode()
    except Exception as e:
        print(f"[ERROR] AES decryption failed: {e}")
        return None


def hash_password(password):
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password, hashed_password):
    """Verify a password against its hashed value."""
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


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


def save_message_to_db(username, message):
    """Save a message to the database."""
    try:
        # Generate a new AES key for this message
        aes_key = os.urandom(AES_KEY_LENGTH)
        print(f"[DEBUG] Generated AES key for message: {aes_key.hex()}")
        encrypted_message = aes_encrypt(message, aes_key).hex()
        print(f"[DEBUG] Encrypted message: {encrypted_message}")

        # Encrypt the AES key with the recipient's RSA public key
        public_key = clients.get(username)  # Get recipient's public key
        if not public_key:
            print(f"[ERROR] Public key for '{username}' not found.")
            return
        encrypted_aes_key = rsa_encrypt_value(aes_key, public_key)
        print(f"[DEBUG] Encrypted AES key: {encrypted_aes_key.hex()}")

        # Save the encrypted message and encrypted AES key
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (username, message, aes_key) VALUES (?, ?, ?)",
                       (username, encrypted_message, encrypted_aes_key.hex()))
        conn.commit()
        conn.close()
        print("[DEBUG] Message and AES key saved to database.")
    except Exception as e:
        print(f"[ERROR] Failed to save message: {e}")

def get_chat_history_for_client(client_username):
    """Retrieve encrypted messages and AES keys for a client."""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT username, message, aes_key, timestamp FROM messages ORDER BY timestamp ASC")
        chat_history = cursor.fetchall()
        conn.close()

        history_data = []
        for sender, encrypted_message, encrypted_aes_key, timestamp in chat_history:
            history_data.append({
                "sender": sender,
                "message": encrypted_message,
                "aes_key": encrypted_aes_key,
                "timestamp": timestamp
            })
        return history_data
    except Exception as e:
        print(f"[ERROR] Failed to retrieve chat history: {e}")
        return []


def signup_user(username, password):
    """Sign up a new user."""
    try:
        print(f"[DEBUG] Signing up user '{username}'...")
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        conn.close()
        print(f"[DEBUG] User '{username}' signed up successfully.")
        return True
    except sqlite3.IntegrityError:
        print(f"[ERROR] Username '{username}' already exists.")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to sign up user '{username}': {e}")
        return False


def login_user(username, password):
    """Log in a user by verifying their credentials."""
    try:
        print(f"[DEBUG] Attempting to log in user '{username}'...")
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        if result and verify_password(password, result[0]):
            print(f"[DEBUG] User '{username}' logged in successfully.")
            return True
        print(f"[ERROR] Login failed for user '{username}'.")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to log in user '{username}': {e}")
        return False


def handle_client(client_socket, address):
    """Handle communication with a connected client."""
    print(f"[DEBUG] New connection from {address}")

    authenticated = False  # Track if the client is authenticated
    username = None

    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            if data.startswith(b"SIGNUP:"):
                username, password = data[len(b"SIGNUP:"):].decode().split(",")
                signup_result = signup_user(username, password)
                client_socket.send(b"SIGNUP_SUCCESS" if signup_result else b"SIGNUP_FAILED")

            elif data.startswith(b"LOGIN:"):
                username, password = data[len(b"LOGIN:"):].decode().split(",")
                login_result = login_user(username, password)
                if login_result:
                    client_socket.send(b"LOGIN_SUCCESS")
                    authenticated = True

                    # Retrieve and send the chat history to the client
                    chat_history = get_chat_history_for_client(username)
                    for entry in chat_history:
                        data = f"HISTORY:{entry['timestamp']}|{entry['sender']}|{entry['message']}|{entry['aes_key']}"
                        client_socket.send(data.encode())
                else:
                    client_socket.send(b"LOGIN_FAILED")



            elif authenticated and data.startswith(b"PUBLIC_KEY:"):
                public_key_pem = data[len(b"PUBLIC_KEY:"):]
                public_key = serialization.load_pem_public_key(public_key_pem)
                print(f"[DEBUG] Received and stored public key from {address}:\n{public_key_pem.decode()}")
                clients[username] = public_key

                # Encrypt and send the global AES key
                encrypted_aes_key = rsa_encrypt_value(global_aes_key, public_key)
                client_socket.send(b"AES_KEY:" + encrypted_aes_key.hex().encode())


            elif authenticated and data.startswith(b"MSG:"):
                message = data[len(b"MSG:"):].decode()
                save_message_to_db(username, message)
                relay_data(client_socket, f"{username}: {message}".encode())

            else:
                print(f"[ERROR] Unauthenticated client {address} attempted to send data.")
                client_socket.send(b"ERROR:AUTHENTICATION_REQUIRED")

    except Exception as e:
        print(f"[ERROR] Error handling client {address}: {e}")
    finally:
        client_socket.close()
        if client_socket in clients:
            del clients[client_socket]
        print(f"[DEBUG] Client {address} disconnected.")


def relay_data(sender_socket, data):
    """Relay plaintext messages to all other clients."""
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                client_socket.send(data)
            except Exception as e:
                print(f"[ERROR] Failed to relay message to a client: {e}")


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
    initialize_database()
    start_server()
