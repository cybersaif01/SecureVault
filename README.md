# SecurePassVault

SecurePassVault is a secure, minimal, and user-friendly desktop password manager built using **Python** and **PyQt5**. It provides users with a simple interface to store, retrieve, and generate passwords securely, all encrypted using **Fernet symmetric encryption** from the `cryptography` library.

## Features

* Securely store and retrieve passwords
* Strong encryption using Fernet (AES-based)
* Built-in random password generator
* Password strength checker
* Clean, modern, dark-themed user interface

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/SecurePassVault.git
cd SecurePassVault
```

2. Install the required packages:

```bash
pip install PyQt5 cryptography
```

## Usage

Run the application using:

```bash
python securepassvault.py
```

* Use the input fields to enter site name, username, and password.
* Click **Add Password** to save credentials.
* Click **Retrieve Password** to retrieve saved credentials.
* Click **Generate Password** to create a strong random password.

## Security

All stored data is encrypted using the **Fernet** module, which uses AES encryption in CBC mode with a SHA256 HMAC for authentication. The encryption key is generated automatically and stored locally.

## Disclaimer

This project is intended for educational purposes and lightweight personal use. For enterprise-level or highly sensitive password management, consider using dedicated security solutions.

## Developed By

This application was developed with assistance from **ChatGPT** by **OpenAI**.

---

Thank you for using SecurePassVault.
