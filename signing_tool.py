import os
import hashlib
import xml.etree.ElementTree as ET
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

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

    create_signature_xml(file_path, signature_file_path)

def create_signature_xml(file_path, signature_file_path):
    root = ET.Element('Signature')
    doc_info = ET.SubElement(root, 'DocumentInfo')
    doc_info.text = f"{os.path.basename(file_path)}, {os.path.getsize(file_path)} bytes"
    sign_info = ET.SubElement(root, 'SignatureInfo')
    sign_info.text = signature_file_path
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
