import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

pin = 6969

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
cipher = Cipher(AES(pin.to_bytes(16, 'big')), modes.CBC(initialization_vector))
encryptor = cipher.encryptor()
encrypted_pem_private_key = encryptor.update(padded_pem_private_key) + encryptor.finalize()

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