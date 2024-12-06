import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

BLOCK_SIZE = 16
shared_aes_key = None  # Shared AES key for message encryption and decryption


def generate_rsa_keypair():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    print("[DEBUG] RSA Key Pair Generated.")
    return private_key, public_key


def rsa_decrypt_value(encrypted_value, private_key):
    """Decrypt a value using the client's private RSA key."""
    decrypted_value = private_key.decrypt(
        encrypted_value,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"[DEBUG] Decrypted AES Key: {urlsafe_b64encode(decrypted_value).decode()}")
    return decrypted_value


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
        return plaintext.decode()
    except Exception as e:
        print(f"[ERROR] AES decryption failed: {e}")
        raise


def send_public_key(client_socket, public_key):
    """Send the client's RSA public key to the server."""
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(b"PUBLIC_KEY:" + public_key_pem)
    print("[DEBUG] Sent public key to server.")


def receive_data(client_socket, private_key):
    """Receive and process data from the server."""
    global shared_aes_key
    while True:
        try:
            data = client_socket.recv(4096).decode()

            # Handle AES key exchange
            if data.startswith("AES_KEY:"):
                encrypted_aes_key = bytes.fromhex(data[len("AES_KEY:"):])
                shared_aes_key = rsa_decrypt_value(encrypted_aes_key, private_key)
                print("[DEBUG] AES key successfully received and decrypted.")

            # Handle chat history
            elif data.startswith("HISTORY:"):
                _, timestamp, sender, encrypted_message, encrypted_aes_key = data.split("|")
                # Decrypt AES key
                aes_key = rsa_decrypt_value(bytes.fromhex(encrypted_aes_key), private_key)
                # Decrypt message
                plaintext_message = aes_decrypt(bytes.fromhex(encrypted_message), aes_key)
                print(f"[{timestamp}] {sender}: {plaintext_message}")

            else:
                print(f"[ERROR] Unknown data format received: {data}")

        except Exception as e:
            print(f"[ERROR] Failed to process received data: {e}")


def start_client():
    SERVER_HOST = '127.0.0.1'
    SERVER_PORT = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print("[DEBUG] Connected to server.")

        while True:
            choice = input("Do you want to (1) Signup or (2) Login? Enter 1 or 2: ").strip()
            if choice == "1":
                username = input("Enter a username: ").strip()
                password = input("Enter a password: ").strip()
                client_socket.send(f"SIGNUP:{username},{password}".encode())
            elif choice == "2":
                username = input("Enter your username: ").strip()
                password = input("Enter your password: ").strip()
                client_socket.send(f"LOGIN:{username},{password}".encode())
            else:
                print("[ERROR] Invalid choice. Please enter 1 or 2.")
                continue

            try:
                response = client_socket.recv(1024).decode()
                if response == "SIGNUP_SUCCESS":
                    print("[DEBUG] Signup successful. You can now login.")
                elif response == "SIGNUP_FAILED":
                    print("[ERROR] Signup failed. Username might already exist.")
                elif response == "LOGIN_SUCCESS":
                    print("[DEBUG] Login successful. Generating RSA key pair.")
                    private_key, public_key = generate_rsa_keypair()
                    send_public_key(client_socket, public_key)

                    threading.Thread(target=receive_data, args=(client_socket, private_key), daemon=True).start()
                    break
                elif response == "LOGIN_FAILED":
                    print("[ERROR] Login failed. Try again.")
                else:
                    print("[ERROR] Unexpected response from server.")
            except Exception as e:
                print(f"[ERROR] Communication error: {e}")
                break

        while True:
            if shared_aes_key is None:
                print("[DEBUG] Waiting for AES key...")
                continue

            message = input("Enter message: ")
            client_socket.send(f"MSG:{message}".encode())
    except ConnectionAbortedError as e:
        print(f"[ERROR] Connection was aborted: {e}")
    except Exception as e:
        print(f"[ERROR] Client error: {e}")
    finally:
        client_socket.close()
        print("[DEBUG] Client disconnected.")


if __name__ == "__main__":
    start_client()
