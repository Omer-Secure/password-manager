import os
import pyfiglet
import hashlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from getpass import getpass

PASSWORD_FILE = "passwords.enc"
KEY_FILE = "key.bin"
PASSWORD_HASH_FILE = "password_hash.enc"

# Colors for styling
WHITE = '\033[1;37m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
BLUE = '\033[0;34m'
YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_key():
    if not os.path.exists(KEY_FILE):
        key = os.urandom(32)
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        print(f"{GREEN}Encryption key generated and stored in {KEY_FILE}{NC}")
    else:
        print(f"{GREEN}Key already exists.{NC}")

def verify_password():
    if os.path.exists(PASSWORD_HASH_FILE):
        stored_hash = open(PASSWORD_HASH_FILE, 'r').read().strip()
        input_password = getpass("Enter your password: ")
        input_hash = hashlib.sha256(input_password.encode('utf-8')).hexdigest()
        if stored_hash != input_hash:
            print(f"{RED}Incorrect password. Exiting...{NC}")
            exit(1)
    else:
        set_password()

def set_password():
    password1 = getpass("Set your new password: ")
    password2 = getpass("Re-enter the password: ")
    if password1 != password2:
        print(f"{RED}Error: Passwords do not match.{NC}")
        return
    password_hash = hashlib.sha256(password1.encode('utf-8')).hexdigest()
    with open(PASSWORD_HASH_FILE, 'w') as f:
        f.write(password_hash)
    print(f"{GREEN}Password set successfully.{NC}")

def change_password():
    
    old_password = getpass("Enter your old password: ")
    stored_hash = open(PASSWORD_HASH_FILE, 'r').read().strip()
    old_hash = hashlib.sha256(old_password.encode('utf-8')).hexdigest()
    if stored_hash != old_hash:
        clear_screen()
        print(f"{RED}Incorrect old password. Exiting...{NC}")
        return
    new_password1 = getpass("Enter your new password: ")
    new_password2 = getpass("Re-enter your new password: ")
    if new_password1 != new_password2:
        clear_screen()
        print(f"{RED}Error: New passwords do not match.{NC}")
        return
    new_hash = hashlib.sha256(new_password1.encode('utf-8')).hexdigest()
    with open(PASSWORD_HASH_FILE, 'w') as f:
        f.write(new_hash)
    clear_screen()
    print(f"{GREEN}Password changed successfully.{NC}")

def encrypt_password(password):
    key = open(KEY_FILE, 'rb').read()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000, backend=default_backend())
    key = kdf.derive(key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password.encode('utf-8')) + padder.finalize()
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()
    return salt + encrypted_password

def decrypt_password(encrypted_password):
    key = open(KEY_FILE, 'rb').read()
    salt = encrypted_password[:16]
    encrypted_password = encrypted_password[16:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000, backend=default_backend())
    key = kdf.derive(key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def add_password():
    clear_screen()
    password1 = getpass("Enter password to store: ")
    password2 = getpass("Re-enter password: ")
    if password1 != password2:
        print(f"{RED}Error: Passwords do not match.{NC}")
        return
    label = input("Enter a label for this password: ")
    encrypted_password = encrypt_password(password1)
    with open(PASSWORD_FILE, 'a') as f:
        f.write(f"{label}: {base64.b64encode(encrypted_password).decode('utf-8')}\n")
    print(f"{GREEN}Password stored successfully.{NC}")

def display_labels_and_passwords():
    clear_screen()
    print(f"{BLUE}Stored labels and their passwords:{NC}")
    with open(PASSWORD_FILE, 'r') as f:
        lines = f.readlines()
        for count, line in enumerate(lines, 1):
            label, encrypted_password = line.split(":")
            encrypted_password = base64.b64decode(encrypted_password.strip())
            decrypted_password = decrypt_password(encrypted_password).decode('utf-8')
            print(f"{YELLOW}{count}) Label: {label.strip()}, Password: {decrypted_password}{NC}")

def delete_label():
    label = input("Enter the label of the password to delete: ")
    with open(PASSWORD_FILE, 'r') as f:
        lines = f.readlines()

    with open(PASSWORD_FILE, 'w') as f:
        deleted = False
        for line in lines:
            if not line.startswith(f"{label}:"):
                f.write(line)
            else:
                confirmation = input(f"{YELLOW}Are you sure you want to delete the password for '{label}'? (yes/no): {NC}")
                if confirmation.lower() == 'yes':
                    deleted = True
                else:
                    f.write(line)
        if deleted:
            clear_screen()
            print(f"{GREEN}Password for '{label}' deleted successfully.{NC}")
        else:
            clear_screen()
            print(f"{RED}Deletion canceled or label '{label}' not found.{NC}")


def show_menu():
    banner = pyfiglet.figlet_format("Pass-Manager")

    print(f"""
{BLUE}█████████████████████████████████████████████████████████ {NC}
{WHITE}{banner}{NC}
{YELLOW} BY: {WHITE} https://github.com/Omer-Secure {NC}
{BLUE}█████████████████████████████████████████████████████████ {NC}

{RED}1) {YELLOW}Add a password{NC}
{RED}2) {YELLOW}Display all labels and passwords{NC}
{RED}3) {YELLOW}Delete a password{NC}
{RED}4) {YELLOW}Change Admin password{NC}
{RED}5) {YELLOW}Exit{NC}
""")


def main():
    verify_password()
    generate_key()
    
    while True:
        show_menu()
        option = input("Choose an option: ")
        if option == "1":
            add_password()
        elif option == "2":
            display_labels_and_passwords()
        elif option == "3":
            delete_label()
        elif option == "4":
            change_password()
        elif option == "5":
            print(f"{RED}Goodbye!{NC}")
            break
        else:
            print(f"{RED}Invalid option. Please try again.{NC}")

if __name__ == "__main__":
    main()

