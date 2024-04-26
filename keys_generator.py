from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.algorithms import AES

pin = 6969

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption
)



AES(pin.to_bytes(16, 'big'))

pem_public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

private_key_file = open('encrypted_private_key.pem', 'w')
private_key_file.write(encrypted_pem_private_key.decode())
private_key_file.close()

public_key_file = open('public_key.pub', 'w')
public_key_file.write(pem_public_key.decode())
public_key_file.close()