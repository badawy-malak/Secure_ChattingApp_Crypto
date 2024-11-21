import socket
import threading

# List to hold all connected clients
clients = []

def broadcast_message(message, sender_socket):
    """Send the message to all clients except the sender."""
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                # Remove client if unable to send the message
                clients.remove(client)

def handle_client(client_socket, client_address):
    """Handle communication with a single client."""
    print(f"New connection from {client_address}")
    clients.append(client_socket)  # Add to the list of clients

    try:
        while True:
            # Receive message from client
            message = client_socket.recv(1024)
            if not message:  # If message is empty, client has disconnected
                print(f"Connection closed by {client_address}")
                break

            # Display the client's IP and message on the server
            print(f"Message from {client_address}: {message.decode()}")

            # Broadcast the message to other clients
            broadcast_message(message, client_socket)
    except ConnectionResetError:
        print(f"Connection lost with {client_address}")
    finally:
        # Remove the client from the list and close the socket
        clients.remove(client_socket)
        client_socket.close()

def start_server():
    SERVER_HOST = '0.0.0.0'
    SERVER_PORT = 12345

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))

    # Start listening for connections
    server_socket.listen(5)
    print(f"Server started. Listening on {SERVER_HOST}:{SERVER_PORT}...")

    while True:
        # Accept a new connection
        client_socket, client_address = server_socket.accept()

        # Handle each client connection in a new thread
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

# Start the server
if __name__ == "__main__":
    start_server()
