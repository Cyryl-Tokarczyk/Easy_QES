from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
import os

def encrypt_file(file_path, public_key_path):
    with open(public_key_path, 'rb') as key_file:
        try:
            public_key = serialization.load_pem_public_key(key_file.read())
        except ValueError as e:
            print("Błąd podczas ładowania klucza publicznego:", e)
            return

    with open(file_path, 'rb') as file:
        document_data = file.read()

    try:
        encrypted_data = public_key.encrypt(
            document_data,
            padding.PKCS1v15()
        )
    except ValueError as e:
        print("Błąd podczas szyfrowania danych:", e)
        return

    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    print("Plik został zaszyfrowany pomyślnie")

def decrypt_file(file_path, private_key):

    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    try:
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.PKCS1v15()
        )
    except ValueError as e:
        print("Błąd podczas odszyfrowywania danych:", e)
        return

    with open(file_path.replace('.enc', ''), 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
    print("Plik został odszyfrowany pomyślnie")
