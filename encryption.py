from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import getpass
import shutil

def generate_key(password, salt):
    """
    Generate a cryptographic key from a password and salt using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key, iv):
    """
    Encrypt data using AES in CFB mode.
    """
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(encrypted_data, key, iv):
    """
    Decrypt data using AES in CFB mode.
    """
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(decrypted_data) + unpadder.finalize()

def process_file(file_path, password, encrypt=True):
    """
    Encrypt or decrypt a file depending on the 'encrypt' flag.
    """
    if encrypt:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        iv = os.urandom(16)
        
        with open(file_path, 'rb') as file:
            data = file.read()
        
        encrypted_data = encrypt_data(data, key, iv)
        
        with open(file_path, 'wb') as file:
            file.write(salt + iv + encrypted_data)
    else:
        with open(file_path, 'rb') as file:
            salt = file.read(16)
            iv = file.read(16)
            encrypted_data = file.read()
        
        key = generate_key(password, salt)
        decrypted_data = decrypt_data(encrypted_data, key, iv)
        
        with open(file_path, 'wb') as file:
            file.write(decrypted_data)

def process_directory(directory_path, password, encrypt=True):
    """
    Encrypt or decrypt all files in a directory.
    """
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            process_file(file_path, password, encrypt)

def main():
    """
    Main function to handle user input and call the appropriate encryption or decryption functions.
    """
    choice = input("Do you want to (E)ncrypt or (D)ecrypt? ")
    password = getpass.getpass("Enter password: ")
    
    if choice.lower() == 'e':
        path = input("Enter the file or directory path to encrypt: ")
        if os.path.isdir(path):
            process_directory(path, password, encrypt=True)
            print("Directory encryption complete.")
        elif os.path.isfile(path):
            process_file(path, password, encrypt=True)
            print("File encryption complete.")
        else:
            print("The specified path does not exist.")
    elif choice.lower() == 'd':
        path = input("Enter the file or directory path to decrypt: ")
        if os.path.isdir(path):
            process_directory(path, password, encrypt=False)
            print("Directory decryption complete.")
        elif os.path.isfile(path):
            process_file(path, password, encrypt=False)
            print("File decryption complete.")
        else:
            print("The specified path does not exist.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
