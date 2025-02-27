import os
import hashlib
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime
import getpass

def sign_document(file_path, private_key):
    with open(file_path, 'rb') as file:
        document_data = file.read()

    document_hash = hashlib.sha256(document_data).digest()
    signature = private_key.sign(
        document_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    signature_file_path = f"{file_path}.sig"
    with open(signature_file_path, 'wb') as sig_file:
        sig_file.write(signature)

    create_signature_xml(file_path, signature_file_path, document_hash, signature, private_key)

def create_signature_xml(file_path, signature_file_path, document_hash, signature, private_key):
    root = ET.Element('Signature')

    # Document Info
    doc_info = ET.SubElement(root, 'DocumentInfo')
    ET.SubElement(doc_info, 'Name').text = os.path.basename(file_path)
    ET.SubElement(doc_info, 'Size').text = f"{os.path.getsize(file_path)} bytes"
    ET.SubElement(doc_info, 'Extension').text = os.path.splitext(file_path)[1]
    ET.SubElement(doc_info, 'LastModified').text = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')

    # Signing User Info
    user_info = ET.SubElement(root, 'UserInfo')
    ET.SubElement(user_info, 'Username').text = getpass.getuser()

    # Signature Info
    sign_info = ET.SubElement(root, 'SignatureInfo')
    ET.SubElement(sign_info, 'SignatureFile').text = signature_file_path

    # Encrypted Document Hash
    encrypted_hash = private_key.sign(
        document_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    ET.SubElement(sign_info, 'EncryptedDocumentHash').text = encrypted_hash.hex()

    # Timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ET.SubElement(sign_info, 'Timestamp').text = timestamp

    tree = ET.ElementTree(root)
    tree.write(f"{signature_file_path}.xml")

def verify_signature(file_path, sig_path):
    with open(file_path, 'rb') as file:
        document_data = file.read()

    document_hash = hashlib.sha256(document_data).digest()
    with open(sig_path, 'rb') as sig_file:
        signature = sig_file.read()

    with open('public_key.pub', 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    try:
        public_key.verify(
            signature,
            document_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False
