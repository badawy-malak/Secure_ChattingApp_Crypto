import socket
import threading
import sqlite3
import sys
import bcrypt  # Import bcrypt for password hashing
import secrets  # For secure random key generation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import logging  # Import logging

# Configure logging
logging.basicConfig(filename='server.log', level=logging.ERROR)

def log_error(message):
    logging.error(message)

# SQLite database setup
DATABASE = 'Secure_Chatting_Application_DB.db'
clients = []

def delete_user_keys(username):
    """Delete the keys associated with a specific username."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys WHERE username = ?", (username,))
        conn.commit()
        print(f"Keys for {username} have been deleted.")
    except sqlite3.Error as e:
        log_error(f"Database error while deleting keys for {username}: {e}")
    finally:
        conn.close()

def initialize_database():
    """Initialize the database and enable WAL mode."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        # Enable WAL mode
        cursor.execute("PRAGMA journal_mode=WAL;")
        # Create the users table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)
        # Create the messages table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        # Add the keys table creation
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            FOREIGN KEY(username) REFERENCES users(username)
        )
        """)


        conn.commit()
    except sqlite3.Error as e:
        log_error(f"Database initialization error: {e}")
    finally:
        conn.close()

def generate_keys(username):
    """Generate an RSA public-private key pair and store them in the database."""
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Derive public key
        public_key = private_key.public_key()

        # Serialize private key to PEM format (plaintext)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')  # Convert bytes to string

        # Serialize public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')  # Convert bytes to string

        # Remove "BEGIN" and "END" lines and line breaks
        private_key_cleaned = "".join(private_key_pem.splitlines()[1:-1])
        public_key_cleaned = "".join(public_key_pem.splitlines()[1:-1])

        # Store keys in the database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO keys (username, public_key, private_key) VALUES (?, ?, ?)",
            (username, public_key_cleaned, private_key_cleaned)
        )
        conn.commit()

        # Print both keys to the server terminal
        print(f"Generated keys for {username}:")
        print(f"Public Key - {public_key_cleaned}")
        print(f"Private Key - {private_key_cleaned}")

        return public_key_cleaned, private_key_cleaned
    except Exception as e:
        log_error(f"Error generating keys for {username}: {e}")
        return None, None
    finally:
        conn.close()

def get_user_keys(username):
    """Retrieve the public and private keys for a specific user."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT public_key, private_key FROM keys WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            return result[0], result[1]  # Return existing keys
        return None, None  # No keys found
    except sqlite3.Error as e:
        log_error(f"Database error while fetching keys: {e}")
        return None, None
    finally:
        conn.close()

def hash_password(password):
    """Hash a password for secure storage."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(stored_password, provided_password):
    """Verify a hashed password."""
    return bcrypt.checkpw(provided_password.encode(), stored_password)

def verify_credentials(username, password):
    """Verify username and password against the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")

        # Check if the username exists
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:  # Username not found in the database
            return False, "This username does not exist."
        
        # Compare the hashed password
        stored_password = result[0]  # This is stored as binary
        if not verify_password(stored_password, password):
            return False, "The password is incorrect."
        
        return True, "Login successful."
    except sqlite3.Error as e:
        return False, f"Database error: {e}"
    finally:
        conn.close()

def register_user(username, password):
    """Register a new user in the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")

        # Check if the username is already taken
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return False, "This username is already taken."

        # Hash the password and store it
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()

        return True, "Signup successful. You can now log in."
    except sqlite3.Error as e:
        return False, f"Database error: {e}"
    finally:
        conn.close()

def broadcast_message(username, message, sender_socket):
    """Broadcast messages to all clients except the sender."""
    save_message(username, message)
    for client, user in clients:
        if client != sender_socket:
            try:
                client.send(f"{username}: {message}".encode())
            except:
                clients.remove((client, user))

def save_message(sender, message):
    """Save a message to the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender, message) VALUES (?, ?)", (sender, message))
        conn.commit()
    except sqlite3.Error as e:
        log_error(f"Database error while saving message: {e}")
    finally:
        conn.close()

def fetch_messages():
    """Fetch the chat history from the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT sender, message, timestamp FROM messages ORDER BY timestamp ASC")
        return cursor.fetchall()
    except sqlite3.Error as e:
        log_error(f"Database error while fetching messages: {e}")
        return []
    finally:
        conn.close()

def handle_client(client_socket, client_address):
    """Handle login, signup, and chat functionality for a single client."""
    username = None  # Initialize username variable
    try:
        print(f"New connection from {client_address}")

        # Ask the client whether they want to login or signup
        client_socket.send("Do you want to (1) Login or (2) Signup? Enter 1 or 2: ".encode())
        choice = client_socket.recv(1024).decode().strip()

        if choice == "2":  # Signup
            attempts = 0
            while attempts < 2:
                client_socket.send("Enter a username: ".encode())
                username = client_socket.recv(1024).decode().strip()

                client_socket.send("Enter a password: ".encode())
                password = client_socket.recv(1024).decode().strip()

                # Attempt to register the user
                success, message = register_user(username, password)
                client_socket.send(message.encode())
                if success:
                    break  # Signup successful
                else:
                    attempts += 1

            if attempts == 2:
                client_socket.send("Too many failed signup attempts. Exiting program.".encode())
                client_socket.close()
                return

        # Proceed with login, allowing up to 2 attempts
        attempts = 0
        while attempts < 2:
            client_socket.send("Enter your username: ".encode())
            username = client_socket.recv(1024).decode().strip()

            client_socket.send("Enter your password: ".encode())
            password = client_socket.recv(1024).decode().strip()

            # Verify credentials
            is_valid, message = verify_credentials(username, password)
            client_socket.send(message.encode())
            if is_valid:
                # Check if keys already exist
                public_key, private_key = get_user_keys(username)
                if not public_key or not private_key:
                    # Generate keys only if they do not exist
                    public_key, private_key = generate_keys(username)
                    if public_key and private_key:
                        print(f"Generated keys for {username}:")
                        print(f"Public Key - {public_key}")
                        print(f"Private Key - {private_key}")
                    else:
                        print(f"Failed to generate keys for {username}.")
                else:
                    print(f"Keys already exist for {username}.")
                break  # Successful login
            else:
                attempts += 1

        if attempts == 2:
            client_socket.send("Too many failed login attempts. Exiting program.".encode())
            client_socket.close()
            return

        # Display chat history
        client_socket.send("Chat history:\n".encode())
        chat_history = fetch_messages()
        for msg in chat_history:
            client_socket.send(f"{msg[2]} - {msg[0]}: {msg[1]}\n".encode())

        # Successful login
        client_socket.send("Welcome to the Chat Room!".encode())
        clients.append((client_socket, username))

        while True:
            try:
                # Receive and decode the message
                message = client_socket.recv(1024).decode()
                if not message:  # If no message, client has disconnected
                    print(f"Connection closed by {username} ({client_address})")
                    break

                # Display the username and message on the server
                print(f"Message from {username}: {message}")

                # Broadcast the username and message to other clients
                broadcast_message(username, message, client_socket)
            except ConnectionResetError:
                print(f"Connection lost with {username} ({client_address})")
                break
    except Exception as e:
        log_error(f"Error handling client {client_address}: {e}")
    finally:
        # Remove the client from the list and delete keys
        if username:
            delete_user_keys(username)
        if (client_socket, username) in clients:
            clients.remove((client_socket, username))
        client_socket.close()

def start_server():
    SERVER_HOST = '0.0.0.0'
    SERVER_PORT = 12345

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))

    server_socket.listen(5)
    print(f"Server started. Listening on {SERVER_HOST}:{SERVER_PORT}...")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    initialize_database()
    start_server()
