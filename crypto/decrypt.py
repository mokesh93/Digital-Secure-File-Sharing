import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from crypto.keygen import load_private_key_from_pem
from crypto.encrypt import MAGIC_HEADER
from utils.logger import logger

def decrypt_file(encrypted_file_path: str, output_file_path: str, recipient_private_key_path: str, password: str = None):
    """
    Decrypts an encrypted binary container using recipient's RSA private key and AES-256-GCM.
    """
    if not os.path.exists(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted binary file not found: {encrypted_file_path}")
        
    logger.info(f"Starting decryption for file: {encrypted_file_path}")
    logger.info(f"Loading recipient private key from: {recipient_private_key_path}")
    recipient_private_key = load_private_key_from_pem(recipient_private_key_path, password=password)
    
    with open(encrypted_file_path, "rb") as f:
        header = f.read(len(MAGIC_HEADER))
        if header != MAGIC_HEADER:
            raise ValueError("Invalid file format: Magic header missing or corrupted.")
            
        key_len_bytes = f.read(4)
        if len(key_len_bytes) < 4:
            raise ValueError("Corrupted file header: Cannot read key length.")
        key_len = struct.unpack(">I", key_len_bytes)[0]
        
        encrypted_aes_key = f.read(key_len)
        iv = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()
        
    # 1. Decrypt AES symmetric key using recipient's RSA private key
    try:
        aes_key = recipient_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        logger.error(f"Failed to decrypt symmetric key with private key: {e}")
        raise ValueError("Decryption failed: Invalid private key or corrupted ciphertext header.")
        
    # 2. Decrypt payload ciphertext using AES-256-GCM and verify tag
    try:
        aesgcm = AESGCM(aes_key)
        encrypted_payload_with_tag = ciphertext + tag
        plaintext_data = aesgcm.decrypt(iv, encrypted_payload_with_tag, None)
    except Exception as e:
        logger.error(f"AES-GCM decryption / tag verification failed: {e}")
        raise ValueError("Decryption failed: File content modified or corrupted (GCM tag check failed).")
        
    os.makedirs(os.path.dirname(os.path.abspath(output_file_path)), exist_ok=True)
    with open(output_file_path, "wb") as f:
        f.write(plaintext_data)
        
    logger.info(f"Successfully decrypted file -> {output_file_path}")
    return output_file_path
