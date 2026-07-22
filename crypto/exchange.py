import os
from crypto.keygen import generate_rsa_key_pair, save_key_to_pem, load_public_key_from_pem, load_private_key_from_pem, DEFAULT_KEY_SIZE
from utils.logger import logger
from utils.helper import ensure_directory_exists

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_DIR = os.path.join(BASE_DIR, "users")

USER_A_DIR = os.path.join(USERS_DIR, "user_a")
USER_B_DIR = os.path.join(USERS_DIR, "user_b")

def get_user_keys_paths(user_name: str):
    """
    Returns (private_key_path, public_key_path) for a given user identifier.
    """
    user_dir = os.path.join(USERS_DIR, user_name.lower().replace(" ", "_"))
    ensure_directory_exists(user_dir)
    priv_path = os.path.join(user_dir, "private_key.pem")
    pub_path = os.path.join(user_dir, "public_key.pem")
    return priv_path, pub_path

def create_user_keys(user_name: str, key_size: int = DEFAULT_KEY_SIZE, force_overwrite: bool = False):
    """
    Generates and saves a pair of RSA keys for a user (e.g. user_a or user_b).
    """
    priv_path, pub_path = get_user_keys_paths(user_name)
    
    if os.path.exists(priv_path) and os.path.exists(pub_path) and not force_overwrite:
        logger.info(f"Keys for {user_name} already exist at {os.path.dirname(priv_path)}")
        return priv_path, pub_path
        
    priv_key, pub_key = generate_rsa_key_pair(key_size=key_size)
    save_key_to_pem(priv_key, priv_path, is_private=True)
    save_key_to_pem(pub_key, pub_path, is_private=False)
    logger.info(f"Key exchange profile initialized for user '{user_name}' ({key_size}-bit RSA).")
    return priv_path, pub_path

def initialize_default_users(key_size: int = DEFAULT_KEY_SIZE):
    """
    Initializes standard User A and User B key stores.
    """
    paths_a = create_user_keys("user_a", key_size=key_size)
    paths_b = create_user_keys("user_b", key_size=key_size)
    return paths_a, paths_b
