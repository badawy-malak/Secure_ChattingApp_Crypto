import socket
import threading

def receive_messages(client_socket):
    """Continuously listen for messages from the server."""
    while True:
        try:
            # Receive message from the server
            message = client_socket.recv(1024).decode()
            if not message:
                break
            print(f"\nBroadcast: {message}")
        except ConnectionResetError:
            print("Disconnected from server.")
            break

def start_client():
    SERVER_HOST = '127.0.0.1'  # Replace with server IP if running on a different machine
    SERVER_PORT = 12345

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print("Connected to the server. Type your messages below:")

    # Start a thread to listen for server messages
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    try:
        while True:
            # Send messages to the server
            message = input("You: ")
            if message.lower() == 'exit':
                print("Disconnected from server.")
                break
            client_socket.send(message.encode())
    except KeyboardInterrupt:
        print("\nDisconnected from the server.")
    finally:
        client_socket.close()

# Start the client
if __name__ == "__main__":
    start_client()
