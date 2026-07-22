import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from crypto.keygen import load_public_key_from_pem
from utils.logger import logger

MAGIC_HEADER = b"SECFILE1"

def encrypt_file(input_file_path: str, output_file_path: str, recipient_public_key_path: str):
    """
    Encrypts a file using AES-256-GCM symmetric encryption, wrapped with RSA-OAEP key exchange.
    
    Binary Format Structure:
    [8 bytes: Magic Header ("SECFILE1")]
    [4 bytes: Encrypted AES Key Length (N)]
    [N bytes: Encrypted AES Key (RSA-OAEP wrapped)]
    [12 bytes: AES-GCM IV]
    [16 bytes: AES-GCM Authentication Tag]
    [Remaining bytes: Ciphertext Payload]
    """
    if not os.path.exists(input_file_path):
        raise FileNotFoundError(f"Input file not found: {input_file_path}")
        
    logger.info(f"Starting encryption for file: {input_file_path}")
    logger.info(f"Loading recipient public key from: {recipient_public_key_path}")
    recipient_public_key = load_public_key_from_pem(recipient_public_key_path)
    
    # 1. Generate random 256-bit AES key & 96-bit IV
    aes_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    
    # 2. Read plaintext payload & encrypt with AES-256-GCM
    with open(input_file_path, "rb") as f:
        plaintext_data = f.read()
        
    aesgcm = AESGCM(aes_key)
    # ciphertext includes tag at the end in cryptography library implementation (last 16 bytes)
    encrypted_payload_with_tag = aesgcm.encrypt(iv, plaintext_data, None)
    
    ciphertext = encrypted_payload_with_tag[:-16]
    tag = encrypted_payload_with_tag[-16:]
    
    # 3. Encrypt AES key using recipient's RSA public key with OAEP padding
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 4. Pack & write binary payload file
    key_len = len(encrypted_aes_key)
    
    os.makedirs(os.path.dirname(os.path.abspath(output_file_path)), exist_ok=True)
    with open(output_file_path, "wb") as f:
        f.write(MAGIC_HEADER)
        f.write(struct.pack(">I", key_len))
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(tag)
        f.write(ciphertext)
        
    logger.info(f"Successfully encrypted file -> {output_file_path}")
    return output_file_path
