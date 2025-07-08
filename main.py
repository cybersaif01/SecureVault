import sys
import json
import os
import random
import string
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QLineEdit, QVBoxLayout, QHBoxLayout,
                             QMessageBox, QTextEdit, QInputDialog, QFrame)
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import QPropertyAnimation, Qt
from cryptography.fernet import Fernet

VAULT_FILE = 'vault.json'
KEY_FILE = 'vault.key'

# Generate or load encryption key
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return Fernet(key)

fernet = load_key()

# Load or initialize vault data
def load_vault():
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, 'rb') as f:
        encrypted_data = f.read()
        if not encrypted_data:
            return {}
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

# Save vault data
def save_vault(vault_data):
    encrypted_data = fernet.encrypt(json.dumps(vault_data).encode())
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted_data)

# Password generator
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

class SecurePassVaultApp(QWidget):
    def __init__(self):
        super().__init__()
        self.vault = load_vault()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('SecurePassVault')
        self.setWindowIcon(QIcon('resources/lock.png'))
        self.resize(500, 400)

        # Title Section
        title = QLabel("🔐 SecurePassVault")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)

        # Input Fields
        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("Site Name")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.textChanged.connect(self.check_password_strength)

        # Password Strength Label
        self.strength_label = QLabel('Strength: ')
        self.strength_label.setStyleSheet('color: #CCCCCC; font-weight: bold;')

        # Buttons
        self.add_button = QPushButton('Add Password')
        self.add_button.clicked.connect(self.add_password)

        self.retrieve_button = QPushButton('Retrieve Password')
        self.retrieve_button.clicked.connect(self.retrieve_password)

        self.generate_button = QPushButton('Generate Password')
        self.generate_button.clicked.connect(self.generate_new_password)

        # Output with Animation
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        self.anim = QPropertyAnimation(self.output_area, b"windowOpacity")
        self.anim.setDuration(600)

        # Layouts
        card = QVBoxLayout()
        card.setSpacing(10)
        card.addWidget(self.site_input)
        card.addWidget(self.username_input)
        card.addWidget(self.password_input)
        card.addWidget(self.strength_label)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.retrieve_button)
        button_layout.addWidget(self.generate_button)

        card.addLayout(button_layout)
        card.addWidget(self.output_area)

        card_frame = QFrame()
        card_frame.setLayout(card)
        card_frame.setObjectName("card")

        main_layout = QVBoxLayout()
        main_layout.addWidget(title)
        main_layout.addWidget(card_frame)
        self.setLayout(main_layout)

    def add_password(self):
        site = self.site_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not site or not username or not password:
            QMessageBox.warning(self, 'Error', 'All fields must be filled.')
            return

        self.vault[site] = {"username": username, "password": password}
        save_vault(self.vault)
        QMessageBox.information(self, 'Success', 'Password saved successfully!')
        self.clear_inputs()

    def retrieve_password(self):
        site, ok = QInputDialog.getText(self, 'Retrieve Password', 'Enter site name:')
        if ok and site:
            entry = self.vault.get(site)
            if entry:
                self.show_output(f"Site: {site}\nUsername: {entry['username']}\nPassword: {entry['password']}")
            else:
                QMessageBox.warning(self, 'Not Found', 'No entry found for this site.')

    def generate_new_password(self):
        length, ok = QInputDialog.getInt(self, 'Generate Password', 'Enter password length:', 12, 6, 32, 1)
        if ok:
            new_password = generate_password(length)
            self.show_output(f"Generated Password: {new_password}")
            self.password_input.setText(new_password)

    def show_output(self, text):
        self.output_area.setText(text)
        self.anim.stop()
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.start()

    def clear_inputs(self):
        self.site_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.strength_label.setText('Strength: ')
        self.strength_label.setStyleSheet('color: #CCCCCC; font-weight: bold;')

    def check_password_strength(self):
        password = self.password_input.text()
        strength, color = self.evaluate_strength(password)
        self.strength_label.setText(f'Strength: {strength}')
        self.strength_label.setStyleSheet(f'color: {color}; font-weight: bold;')

    def evaluate_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        score = sum([has_upper, has_lower, has_digit, has_special])

        if length < 6:
            return 'Too Short', '#FF5555'
        elif length >= 6 and score <= 2:
            return 'Weak', '#FF5555'
        elif length >= 8 and score == 3:
            return 'Medium', '#FFA500'
        elif length >= 10 and score == 4:
            return 'Strong', '#00FF00'
        elif length >= 14 and score == 4:
            return 'Very Strong', '#00CC88'
        else:
            return 'Average', '#CCCCCC'

if __name__ == '__main__':
    app = QApplication(sys.argv)

    dark_stylesheet = """
    QWidget {
        background-color: #1A1A1A;
        color: #FFFFFF;
        font-family: 'Segoe UI';
        font-size: 14px;
    }

    #card {
        background-color: #252525;
        border-radius: 12px;
        padding: 20px;
        border: 1px solid #333333;
    }

    QLineEdit, QTextEdit {
        background-color: #2F2F2F;
        color: #FFFFFF;
        border: 1px solid #444;
        border-radius: 6px;
        padding: 8px;
    }

    QPushButton {
        background-color: #3B82F6;
        color: white;
        border-radius: 8px;
        padding: 10px 16px;
    }

    QPushButton:hover {
        background-color: #2563EB;
    }

    QTextEdit {
        min-height: 80px;
    }
    """

    app.setStyleSheet(dark_stylesheet)

    vault_app = SecurePassVaultApp()
    vault_app.show()

    sys.exit(app.exec_())
