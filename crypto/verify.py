import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from crypto.keygen import load_public_key_from_pem
from utils.logger import logger

def verify_signature(file_path: str, signature_path: str, sender_public_key_path: str) -> bool:
    """
    Verifies a digital signature using sender's RSA public key.
    Returns True if valid, False if verification fails.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File for signature verification not found: {file_path}")
    if not os.path.exists(signature_path):
        raise FileNotFoundError(f"Signature file not found: {signature_path}")
        
    logger.info(f"Verifying signature for file: {file_path}")
    sender_public_key = load_public_key_from_pem(sender_public_key_path)
    
    with open(file_path, "rb") as f:
        file_bytes = f.read()
        
    with open(signature_path, "rb") as f:
        signature = f.read()
        
    try:
        sender_public_key.verify(
            signature,
            file_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        logger.info("✅ Digital signature VERIFIED successfully. File authenticity guaranteed.")
        return True
    except InvalidSignature:
        logger.warning("❌ Digital signature VERIFICATION FAILED! Signature does not match or file has been tampered with.")
        return False
    except Exception as e:
        logger.error(f"Error during signature verification: {e}")
        return False
