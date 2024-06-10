import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

def find_pendrive():
    for drive in os.listdir('/mnt'):
        if 'pendrive' in drive.lower():
            return os.path.join('/mnt', drive)
    return None

def save_keys_to_pendrive(private_key_encryption_pin):
    pendrive_path = find_pendrive()
    if not pendrive_path:
        print("Pendrive not found")
        return False

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    padder = padding.PKCS7(128).padder()
    padded_pem_private_key = padder.update(pem_private_key) + padder.finalize()

    initialization_vector = os.urandom(16)
    cipher = Cipher(AES(private_key_encryption_pin.to_bytes(16, 'big')), modes.CBC(initialization_vector))
    encryptor = cipher.encryptor()
    encrypted_pem_private_key = initialization_vector + encryptor.update(padded_pem_private_key) + encryptor.finalize()

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(os.path.join(pendrive_path, 'encrypted_private_key.pem'), 'wb') as private_key_file:
        private_key_file.write(encrypted_pem_private_key)

    with open(os.path.join(pendrive_path, 'public_key.pub'), 'w') as public_key_file:
        public_key_file.write(pem_public_key.decode())

    return True

def load_keys_from_pendrive(pin):
    pendrive_path = find_pendrive()
    if not pendrive_path:
        print("Pendrive not found")
        return False

    with open(os.path.join(pendrive_path, 'encrypted_private_key.pem'), 'rb') as key_file:
        encrypted_private_key = key_file.read()

    initialization_vector = encrypted_private_key[:16]
    ciphertext = encrypted_private_key[16:]
    cipher = Cipher(AES(pin.to_bytes(16, 'big')), modes.CBC(initialization_vector))

    decryptor = cipher.decryptor()
    decrypted_padded_pem_private_key = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_unpadded_pem_private_key = unpadder.update(decrypted_padded_pem_private_key) + unpadder.finalize()

    private_key = serialization.load_pem_private_key(
        decrypted_unpadded_pem_private_key,
        None
    )

    return private_key
