import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

def generate_keys(private_key_encryption_pin):
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

    private_key_file = open('encrypted_private_key.pem', 'wb')
    private_key_file.write(encrypted_pem_private_key)
    private_key_file.close()

    public_key_file = open('public_key.pub', 'w')
    public_key_file.write(pem_public_key.decode())
    public_key_file.close()

    return True

def decrypt_and_deserialize_private_key(pin, encrypted_private_key = None):
    if encrypted_private_key == None:
        key_file = open('encrypted_private_key.pem', 'rb')
        encrypted_private_key = key_file.read()

    # Get the initialization vector from the first 16 bytes of the encrypted file and vice versa the ciphertext
    initialization_vector = encrypted_private_key[:16]
    ciphertext = encrypted_private_key[16:]
    cipher = Cipher(AES(pin.to_bytes(16, 'big')), modes.CBC(initialization_vector))

    # Decrypt
    decryptor = cipher.decryptor()
    decrypted_padded_pem_private_key = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_unpadded_pem_private_key = unpadder.update(decrypted_padded_pem_private_key) + unpadder.finalize()

    # Deserialize
    private_key = serialization.load_pem_private_key(
        decrypted_unpadded_pem_private_key,
        None
    )

    return private_key

def load_keys_from_pendrive(drive_path, pin):
    private_key_path = os.path.join(drive_path, 'encrypted_private_key.pem')
    public_key_path = os.path.join(drive_path, 'public_key.pub')
    
    # Decrypt the private key
    with open(private_key_path, 'rb') as key_file:
        encrypted_private_key = key_file.read()

    private_key = decrypt_and_deserialize_private_key(pin, encrypted_private_key)

    # Copy keys to current directory
    with open('encrypted_private_key.pem', 'wb') as dest_private_key_file:
        dest_private_key_file.write(encrypted_private_key)

    with open(public_key_path, 'rb') as src_public_key_file:
        public_key = src_public_key_file.read()

    return private_key, public_key

if __name__ == '__main__':
    generate_keys(6969)
    decrypt_and_deserialize_private_key(6969)