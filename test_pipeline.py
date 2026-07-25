import os
import sys

from crypto.exchange import initialize_default_users, get_user_keys_paths
from crypto.encrypt import encrypt_file
from crypto.decrypt import decrypt_file
from crypto.sign import sign_file
from crypto.verify import verify_signature
from utils.helper import create_sample_file, FILES_DIR

def run_tests():
    print("=== AUTOMATED VERIFICATION TEST SUITE ===")
    
    # 1. Test Key Generation (4096-bit RSA)
    print("\n1. Testing 4096-bit RSA Key Pair Generation...")
    initialize_default_users(key_size=4096)
    priv_a, pub_a = get_user_keys_paths("user_a")
    priv_b, pub_b = get_user_keys_paths("user_b")
    
    assert os.path.exists(priv_a) and os.path.exists(pub_a), "User A keys missing"
    assert os.path.exists(priv_b) and os.path.exists(pub_b), "User B keys missing"
    print("   [PASS] 4096-bit RSA keys generated for User A & User B.")
    
    # 2. Test Sample Creation
    print("\n2. Testing Sample File Creation...")
    sample_file = create_sample_file()
    assert os.path.exists(sample_file), "Sample file missing"
    with open(sample_file, "rb") as f:
        original_bytes = f.read()
    print("   [PASS] Sample file created.")
    
    # 3. Test Hybrid Encryption (User A -> User B)
    print("\n3. Testing Forward Flow (User A -> User B)...")
    enc_file = os.path.join(FILES_DIR, "encrypted.bin")
    sig_file = os.path.join(FILES_DIR, "signature.sig")
    dec_file = os.path.join(FILES_DIR, "decrypted.txt")
    
    encrypt_file(sample_file, enc_file, pub_b)
    sign_file(sample_file, priv_a, sig_file)
    decrypt_file(enc_file, dec_file, priv_b)
    verified = verify_signature(dec_file, sig_file, pub_a)
    
    assert verified is True, "Forward flow signature verification failed!"
    print("   [PASS] Forward flow (User A -> User B) completed and verified.")
    
    # 4. Test Reverse Hybrid Encryption (User B -> User A)
    print("\n4. Testing Reverse Flow (User B -> User A)...")
    enc_rev_file = os.path.join(FILES_DIR, "encrypted_rev.bin")
    sig_rev_file = os.path.join(FILES_DIR, "signature_rev.sig")
    dec_rev_file = os.path.join(FILES_DIR, "decrypted_rev.txt")
    
    encrypt_file(sample_file, enc_rev_file, pub_a)
    sign_file(sample_file, priv_b, sig_rev_file)
    decrypt_file(enc_rev_file, dec_rev_file, priv_a)
    rev_verified = verify_signature(dec_rev_file, sig_rev_file, pub_b)
    
    assert rev_verified is True, "Reverse flow signature verification failed!"
    print("   [PASS] Reverse flow (User B -> User A) completed and verified.")
    
    # 5. Test Tamper Detection
    print("\n5. Testing Tamper Detection on Modified File...")
    tampered_file = os.path.join(FILES_DIR, "tampered.txt")
    with open(tampered_file, "wb") as f:
        f.write(original_bytes + b"\n[TAMPERED EXTRA BYTE]")
        
    tamper_verified = verify_signature(tampered_file, sig_file, pub_a)
    assert tamper_verified is False, "Tampered file passed verification unexpectedly!"
    print("   [PASS] Tampered file correctly rejected by signature verifier.")
    
    print("\n🎉 ALL TEST CASES PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
