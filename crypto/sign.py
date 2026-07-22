import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from crypto.keygen import load_private_key_from_pem
from utils.logger import logger

def sign_file(file_path: str, sender_private_key_path: str, signature_output_path: str, password: str = None):
    """
    Creates a digital signature for a file using sender's RSA private key and SHA-256 with RSA-PSS padding.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file for signature not found: {file_path}")
        
    logger.info(f"Generating digital signature for file: {file_path}")
    sender_private_key = load_private_key_from_pem(sender_private_key_path, password=password)
    
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
    signature = sender_private_key.sign(
        file_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    os.makedirs(os.path.dirname(os.path.abspath(signature_output_path)), exist_ok=True)
    with open(signature_output_path, "wb") as f:
        f.write(signature)
        
    logger.info(f"Digital signature created successfully -> {signature_output_path}")
    return signature_output_path
