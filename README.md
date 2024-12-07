# **Secure Chat Application**

A secure client-server chat application that ensures confidentiality and integrity of communication using **AES-GCM** encryption and **RSA key exchange**. The application is built with Python and uses PyQt5 for a graphical user interface (GUI). Messages are encrypted before transmission and securely stored in the server's database.

---

## **Features**
- **Secure Communication**: Messages are encrypted using AES-GCM and securely transmitted between clients.
- **RSA Key Exchange**: AES keys are securely exchanged using RSA encryption.
- **Authentication**: Users can sign up or log in using credentials stored in the server's database.
- **Message Storage**: Encrypted messages are stored in the server database for future reference.
- **GUI Interface**: The client uses a PyQt5-based interface for an intuitive user experience.
- **Real-time Communication**: Supports simultaneous communication between multiple clients using multithreading.

---

## **Requirements**
- **Python**: 3.8 or higher
- **Libraries**:
  - PyQt5
  - cryptography
  - bcrypt
  - sqlite3
- **Wireshark** (optional): For monitoring network traffic and verifying encryption.


---

## **Usage**
1. **Server Setup**:
   - The server initializes the SQLite database and listens for client connections.
   - It generates a global AES key for secure communication.

2. **Client Interaction**:
   - The client connects to the server and starts a listener thread for incoming messages.
   - Users can log in or sign up. Credentials are securely hashed using bcrypt before storage.

3. **Secure Messaging**:
   - Messages are encrypted using AES-GCM, including an IV and an authentication tag.
   - Encrypted messages are stored in the database and relayed to other clients.

4. **Monitoring**:
   - Use Wireshark to inspect packet transmissions and verify encrypted data.

---

## **Security Features**
1. **AES-GCM Encryption**:
   - Ensures confidentiality, integrity, and authenticity of messages using AES in GCM mode.
   - Initialization Vector (IV) and Authentication Tag are included with each encrypted message.

2. **RSA Key Exchange**:
   - Secures the AES key exchange between client and server using RSA public/private keys.

3. **Hashed Credentials**:
   - Passwords are securely hashed with bcrypt and stored in the database.

4. **Database Security**:
   - Messages are stored in the server database in Base64-encoded encrypted form.

---

## **Folder Structure**
```
secure-chat-application/
├── client.py        # Client-side code with PyQt5 GUI
├── server.py        # Server-side code with database setup and message handling
├── README.md        # Project documentation
├── requirements.txt # Dependencies
└── database/        # SQLite database (auto-created if not present)
```


