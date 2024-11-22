import socket
import threading
import sqlite3

# SQLite database setup
DATABASE = 'Secure_Chatting_Application_DB.db'
clients = []

def verify_credentials(username, password):
    """Verify username and password against the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Check if the username exists
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if not result:  # Username not found in the database
            return False, "This username does not exist."
        
        # Compare the input password with the stored password
        stored_password = result[0]
        if stored_password != password:  # Incorrect password
            return False, "The password is incorrect."
        
        return True, "Login successful."
    except sqlite3.Error as e:
        return False, f"Database error: {e}"
    finally:
        conn.close()

def broadcast_message(message, sender_socket):
    """Broadcast messages to all clients except the sender."""
    for client, user in clients:
        if client != sender_socket:
            try:
                client.send(message.encode())
            except:
                clients.remove((client, user))

def handle_client(client_socket, client_address):
    """Handle login and chat functionality for a single client."""
    try:
        print(f"New connection from {client_address}")

        # Ask the client for login credentials
        client_socket.send("Enter your username: ".encode())
        username = client_socket.recv(1024).decode().strip()

        client_socket.send("Enter your password: ".encode())
        password = client_socket.recv(1024).decode().strip()

        # Verify credentials
        is_valid, message = verify_credentials(username, password)
        client_socket.send(message.encode())
        if not is_valid:
            client_socket.close()
            return

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
                broadcast_message(f"{username}: {message}", client_socket)
            except ConnectionResetError:
                print(f"Connection lost with {username} ({client_address})")
                break
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        # Remove the client from the list and close the socket
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
    # Create the database and users table if not exists
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)
    conn.commit()

    # Insert a test user with plain-text password
    test_username = 'rita'
    test_password = '12'  # Plain-text password
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", (test_username, test_password))
    conn.commit()
    conn.close()

    start_server()
