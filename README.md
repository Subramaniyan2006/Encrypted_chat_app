🔐 Encrypted Chat Application (AES)
A secure client–server chat application built using Python as part of the SYNTECXHUB 4-Week Virtual Cyber Security Internship.
All messages are encrypted using AES symmetric encryption before transmission.
📌 Project Overview
This project demonstrates how secure communication can be implemented over TCP sockets using AES encryption, random IVs, and multithreading.
The server supports multiple clients simultaneously and logs only encrypted messages, ensuring confidentiality.
🚀 Features
TCP socket-based client–server communication
AES (CBC mode) encryption for messages
Random IV generated for every message
Pre-shared symmetric key handling
Supports multiple clients (threading)
Encrypted message logging
Works on Windows (PowerShell / CMD)
🛠 Technologies Used
Python 3.x
socket – networking
threading – concurrency
logging – message logging
cryptography – AES encryption

⚙️ Installation & Setup
1️⃣ Install Python
Ensure Python 3.11+ is installed:
Copy code
Bash
python --version
2️⃣ Install Required Library
Copy code
Bash
python -m pip install cryptography

▶️ How to Run
Step 1: Start the Server
Open PowerShell / Command Prompt:
Copy code
Bash
python "Encrypted Chat App.py"
When prompted:
Copy code

Enter mode (server/client): server
You should see:
Copy code

Server listening on 127.0.0.1:5000
Step 2: Start Clients (in new terminals)
Open another PowerShell window and run:
Copy code
Bash
python "Encrypted Chat App.py"
Choose:
Copy code

Enter mode (server/client): client
Repeat this step to connect multiple clients.
Step 3: Chat Securely
Type messages in any client:
Copy code

You: hello
Messages will be:
Encrypted during transmission
Decrypted only at the client
Logged as ciphertext in chat.log
🔒 Security Implementation
AES-256 (CBC mode) used for encryption
Random IV per message prevents pattern attacks
PKCS7 padding ensures block alignment
Encrypted logs only (no plaintext stored)
Example log entry:
Copy code

Encrypted message from ('127.0.0.1', 52522):
8c564196f259c61f79db0ccdcbb363f8...
⚠️ Disclaimer
This project is developed strictly for educational and internship purposes.
Do not use this application for real-world secure communication without implementing:
Secure key exchange (e.g., Diffie-Hellman)
Authentication
TLS/SSL
📈 Future Enhancements
Secure key exchange (Diffie-Hellman)
User authentication
TLS integration
GUI-based client
Message integrity (HMAC)
