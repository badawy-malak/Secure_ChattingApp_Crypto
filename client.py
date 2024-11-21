
import socket
import threading

def receive_messages(client_socket):
    """Listen for messages from the server."""
    while True:
        try:
            # Receive and decode the message
            message = client_socket.recv(1024).decode()
            if not message:
                break
            print(f"{message}")
        except ConnectionResetError:
            print("Disconnected from server.")
            break


def start_client():
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()
    try:
        while True:
            message = input()
            client_socket.send(message.encode())
    except KeyboardInterrupt:
        print("\nDisconnected from the server.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    start_client()
