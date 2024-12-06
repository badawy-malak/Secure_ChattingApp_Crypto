import sys
import os
import socket
import threading
from base64 import urlsafe_b64encode, urlsafe_b64decode

from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton,
                             QLineEdit, QTextEdit, QLabel, QHBoxLayout, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import QThread, pyqtSignal

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

### Crypto Functions ###

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_decrypt_value(encrypted_value, private_key):
    return private_key.decrypt(
        encrypted_value,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def aes_encrypt(message, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def aes_decrypt(encrypted_message, key):
    iv = encrypted_message[:12]
    tag = encrypted_message[12:28]
    ciphertext = encrypted_message[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

### Receiver Thread ###

class ReceiverThread(QThread):
    message_received = pyqtSignal(str)  
    error_occurred = pyqtSignal(str)    
    aes_key_ready = pyqtSignal()        

    def __init__(self, client_socket, private_key):
        super().__init__()
        self.client_socket = client_socket
        self.private_key = private_key
        self.shared_aes_key = None
        self.running = True

    def run(self):
        while self.running:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                if data.startswith(b"AES_KEY:"):
                    encrypted_key = data[len(b"AES_KEY:"):]
                    try:
                        self.shared_aes_key = rsa_decrypt_value(encrypted_key, self.private_key)
                        self.aes_key_ready.emit()
                    except Exception as e:
                        self.error_occurred.emit(f"Error decrypting AES key: {e}")

                else:
                    if self.shared_aes_key is None:
                        continue
                    try:
                        plaintext = aes_decrypt(data, self.shared_aes_key)
                        self.message_received.emit(plaintext)
                    except Exception as e:
                        self.error_occurred.emit(f"Error decrypting message: {e}")
            except Exception as e:
                self.error_occurred.emit(f"Error receiving data: {e}")
                break

    def stop(self):
        self.running = False
        self.client_socket.close()

### Main Window ###

class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat Client")
        self.resize(500, 600)

        # Client related variables
        self.client_socket = None
        self.private_key = None
        self.public_key = None
        self.shared_aes_key = None
        self.receiver_thread = None

        # Track current action: 'login' or 'signup'
        self.current_action = None

        self.init_ui()

    def init_ui(self):
        self.main_layout = QVBoxLayout()

        # Welcome section
        self.welcome_label = QLabel("<h2>Welcome to Secure Chat</h2>", self)
        self.login_btn = QPushButton("Login", self)
        self.signup_btn = QPushButton("Signup", self)

        self.main_layout.addWidget(self.welcome_label, 0)
        self.main_layout.addWidget(self.login_btn, 0)
        self.main_layout.addWidget(self.signup_btn, 0)

        # Credential section (hidden initially)
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.auth_confirm_btn = QPushButton("Confirm", self)

        # We'll add these to the layout later, but start hidden
        self.username_input.hide()
        self.password_input.hide()
        self.auth_confirm_btn.hide()

        self.main_layout.addWidget(self.username_input)
        self.main_layout.addWidget(self.password_input)
        self.main_layout.addWidget(self.auth_confirm_btn)

        # Chat section (hidden until logged in)
        self.chat_label = QLabel("<h3>Chat Window</h3>")
        self.chat_display = QTextEdit(self)
        self.chat_display.setReadOnly(True)
        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText("Type your message...")
        self.send_button = QPushButton("Send", self)

        self.chat_label.hide()
        self.chat_display.hide()
        self.message_input.hide()
        self.send_button.hide()

        self.main_layout.addWidget(self.chat_label)
        self.main_layout.addWidget(self.chat_display)
        self.main_layout.addWidget(self.message_input)
        self.main_layout.addWidget(self.send_button)

        # Connect signals
        self.login_btn.clicked.connect(self.show_login_fields)
        self.signup_btn.clicked.connect(self.show_signup_fields)
        self.auth_confirm_btn.clicked.connect(self.handle_auth)
        self.send_button.clicked.connect(self.handle_send)

        self.setLayout(self.main_layout)

    def show_login_fields(self):
        self.current_action = "login"
        self.toggle_initial_ui(False)
        self.toggle_auth_fields(True)
        self.auth_confirm_btn.setText("Login")

    def show_signup_fields(self):
        self.current_action = "signup"
        self.toggle_initial_ui(False)
        self.toggle_auth_fields(True)
        self.auth_confirm_btn.setText("Signup")

    def toggle_initial_ui(self, visible):
        # Show/hide welcome, login, signup elements
        self.welcome_label.setVisible(visible)
        self.login_btn.setVisible(visible)
        self.signup_btn.setVisible(visible)

    def toggle_auth_fields(self, visible):
        self.username_input.setVisible(visible)
        self.password_input.setVisible(visible)
        self.auth_confirm_btn.setVisible(visible)

    def toggle_chat_ui(self, visible):
        self.chat_label.setVisible(visible)
        self.chat_display.setVisible(visible)
        self.message_input.setVisible(visible)
        self.send_button.setVisible(visible)

    def handle_auth(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not username or not password:
            self.append_chat("[ERROR] Please enter username and password.")
            return

        if not self.client_socket:
            self.connect_to_server()
            if not self.client_socket:
                return

        if self.current_action == "login":
            self.send_login(username, password)
        elif self.current_action == "signup":
            self.send_signup(username, password)

    def send_signup(self, username, password):
        try:
            self.client_socket.send(f"SIGNUP:{username},{password}".encode())
            response = self.client_socket.recv(1024).decode()
            if response == "SIGNUP_SUCCESS":
                self.append_chat("[DEBUG] Signup successful. Please login now.")
                # After signup success, revert to initial screen to allow login
                self.toggle_auth_fields(False)
                self.toggle_initial_ui(True)
            else:
                self.append_chat("[ERROR] Signup failed. Username might already exist.")
        except Exception as e:
            self.append_chat(f"[ERROR] Signup error: {e}")

    def send_login(self, username, password):
        try:
            self.client_socket.send(f"LOGIN:{username},{password}".encode())
            response = self.client_socket.recv(1024).decode()
            if response == "LOGIN_SUCCESS":
                self.logged_in_username = username  # Store the username
                self.append_chat("[DEBUG] Login successful. Generating RSA key pair.")
                self.setup_keys_and_start_receiver()
            else:
                self.append_chat("[ERROR] Login failed. Check credentials.")
        except Exception as e:
            self.append_chat(f"[ERROR] Login error: {e}")

    def setup_keys_and_start_receiver(self):
        self.private_key, self.public_key = generate_rsa_keypair()
        self.send_public_key()

        # Start a thread to receive messages
        self.receiver_thread = ReceiverThread(self.client_socket, self.private_key)
        self.receiver_thread.message_received.connect(self.on_message_received)
        self.receiver_thread.error_occurred.connect(self.on_error_occurred)
        self.receiver_thread.aes_key_ready.connect(self.on_aes_ready)
        self.receiver_thread.start()

        # Once logged in, hide auth fields and show chat UI
        self.toggle_auth_fields(False)
        self.toggle_chat_ui(True)

    def send_public_key(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.client_socket.send(b"PUBLIC_KEY:" + public_key_pem)
        self.append_chat("[DEBUG] Public key sent to server. Waiting for AES key...")

    def on_message_received(self, message):
        self.append_chat(f"[MESSAGE] {message}")

    def on_error_occurred(self, error_message):
        self.append_chat(f"[ERROR] {error_message}")

    def on_aes_ready(self):
        self.shared_aes_key = self.receiver_thread.shared_aes_key
        self.append_chat("[DEBUG] AES key established. You can now send messages.")

    def handle_send(self):
        message = self.message_input.text().strip()
        if not message:
            return
        if self.shared_aes_key is None:
            self.append_chat("[ERROR] AES key not established yet.")
            return

        # Prepend the username so that the message received by others shows the sender's name
        formatted_message = f"[{self.logged_in_username}] {message}"

        # Display locally
        self.append_chat(formatted_message)

        try:
            # Encrypt the formatted message (with username included)
            encrypted_message = aes_encrypt(formatted_message, self.shared_aes_key)
            self.client_socket.send(encrypted_message)
            self.message_input.clear()
        except Exception as e:
            self.append_chat(f"[ERROR] Failed to send message: {e}")


    def append_chat(self, text):
        self.chat_display.append(text)

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            self.append_chat("[DEBUG] Connected to the server.")
        except Exception as e:
            self.append_chat(f"[ERROR] Connection failed: {e}")
            self.client_socket = None


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec_())
