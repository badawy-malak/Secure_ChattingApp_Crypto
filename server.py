import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from base64 import urlsafe_b64encode
import sqlite3
import bcrypt
from base64 import urlsafe_b64encode

AES_KEY_LENGTH = 32  # Length of the AES key in bytes

clients = {}  # Dictionary to store client_socket -> public_key
client_usernames = {}  # Dictionary to store client_socket -> username

global_aes_key = os.urandom(AES_KEY_LENGTH)  # Single AES key for all clients

DATABASE_NAME = "users.db"

def initialize_database():
    """Create the database and the users table if they don't exist."""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_username TEXT,
                encrypted_message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
       
        conn.commit()
        conn.close()
        print("[DEBUG] Database initialized and users table ensured.")
    except Exception as e:
        print(f"[ERROR] Failed to initialize database: {e}")

def store_message(username, encrypted_message):
    try:
        # Convert binary data to a base64 string
        encoded_message = urlsafe_b64encode(encrypted_message).decode()

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender_username, encrypted_message) VALUES (?, ?)",
                       (username, encoded_message))
        conn.commit()
        conn.close()
        print(f"[DEBUG] Stored message from '{username}' in database as base64.")
    except Exception as e:
        print(f"[ERROR] Failed to store message: {e}")
        
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
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

def signup_user(username, password):
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        conn.close()
        print(f"[DEBUG] User '{username}' signed up successfully.")
        return True
    except sqlite3.IntegrityError:
        print(f"[ERROR] Username '{username}' already exists.")
        return False

def login_user(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and verify_password(password, result[0]):
        print(f"[DEBUG] User '{username}' logged in successfully.")
        return True
    print(f"[ERROR] Login failed for user '{username}'.")
    return False

def handle_client(client_socket, address):
    """Handle communication with a connected client."""
    print(f"[DEBUG] New connection from {address}")

    authenticated = False  # Track if the client is authenticated
    current_username = None

    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            if data.startswith(b"SIGNUP:"):
                username, password = data[len(b"SIGNUP:"):].decode().split(",")
                signup_result = signup_user(username, password)
                if signup_result:
                    client_socket.send(b"SIGNUP_SUCCESS")
                else:
                    client_socket.send(b"SIGNUP_FAILED")

            elif data.startswith(b"LOGIN:"):
                username, password = data[len(b"LOGIN:"):].decode().split(",")
                login_result = login_user(username, password)
                if login_result:
                    client_socket.send(b"LOGIN_SUCCESS")
                    authenticated = True
                    current_username = username
                    client_usernames[client_socket] = username  # Store the username
                else:
                    client_socket.send(b"LOGIN_FAILED")

            elif authenticated and data.startswith(b"PUBLIC_KEY:"):
                # Handle public key exchange
                public_key_pem = data[len(b"PUBLIC_KEY:"):]
                public_key = serialization.load_pem_public_key(public_key_pem)

                # Retrieve the username from our dictionary
                username = client_usernames.get(client_socket, "Unknown User")

                print(f"[DEBUG] Received public key from user '{username}' at {address}:\n{public_key_pem.decode()}")

                clients[client_socket] = public_key

                # Encrypt and send the global AES key
                encrypted_aes_key = rsa_encrypt_value(global_aes_key, public_key)
                client_socket.send(b"AES_KEY:" + encrypted_aes_key)

            elif authenticated and not data.startswith(b"PUBLIC_KEY:"):
                # This is an encrypted chat message from the authenticated user.
                username = client_usernames.get(client_socket, "Unknown User")

                # Store the encrypted message in the database before relaying
                store_message(username, data)

                # Relay encrypted messages to all other clients
                print(f"[DEBUG] Relaying encrypted message from {address}: {data.hex()}")
                relay_data(client_socket, data)

            else:
                # If we reach here, the client is not authenticated and is sending unknown data
                print(f"[ERROR] Unauthenticated client {address} attempted to send data.")
                client_socket.send(b"ERROR:AUTHENTICATION_REQUIRED")

    except Exception as e:
        print(f"[ERROR] Error handling client {address}: {e}")
    finally:
        client_socket.close()
        if client_socket in clients:
            del clients[client_socket]
        if client_socket in client_usernames:
            del client_usernames[client_socket]
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
    initialize_database()
    start_server()
