import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from utils.logger import logger
from utils.helper import ensure_directory_exists

DEFAULT_KEY_SIZE = 4096

def generate_rsa_key_pair(key_size: int = DEFAULT_KEY_SIZE):
    """
    Generates a new RSA private and public key pair.
    Default key size is 4096 bits for high security.
    """
    logger.info(f"Generating {key_size}-bit RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    logger.info(f"Successfully generated {key_size}-bit RSA key pair.")
    return private_key, public_key

def save_key_to_pem(key_obj, file_path: str, is_private: bool = True, password: str = None):
    """
    Exports an RSA key object (private or public) into a standard PEM file.
    """
    ensure_directory_exists(os.path.dirname(file_path))
    
    if is_private:
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))
        else:
            encryption_algorithm = serialization.NoEncryption()
            
        pem_data = key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    else:
        pem_data = key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    with open(file_path, "wb") as f:
        f.write(pem_data)
        
    logger.info(f"Saved {'Private' if is_private else 'Public'} Key to: {file_path}")

def load_private_key_from_pem(file_path: str, password: str = None):
    """
    Loads an RSA private key from a PEM file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Private key file not found: {file_path}")
        
    with open(file_path, "rb") as f:
        pem_data = f.read()
        
    pwd_bytes = password.encode('utf-8') if password else None
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=pwd_bytes
    )
    return private_key

def load_public_key_from_pem(file_path: str):
    """
    Loads an RSA public key from a PEM file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Public key file not found: {file_path}")
        
    with open(file_path, "rb") as f:
        pem_data = f.read()
        
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key
