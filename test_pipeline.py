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
    
    # 3. Test Hybrid Encryption (User A encrypts for User B)
    print("\n3. Testing Hybrid Encryption (AES-256-GCM + RSA-4096 OAEP)...")
    enc_file = os.path.join(FILES_DIR, "encrypted.bin")
    encrypt_file(sample_file, enc_file, pub_b)
    assert os.path.exists(enc_file), "Encrypted file missing"
    print("   [PASS] File encrypted into binary payload.")
    
    # 4. Test Digital Signature (User A signs sample file)
    print("\n4. Testing Digital Signature Creation (SHA-256 + RSA-PSS)...")
    sig_file = os.path.join(FILES_DIR, "signature.sig")
    sign_file(sample_file, priv_a, sig_file)
    assert os.path.exists(sig_file), "Signature file missing"
    print("   [PASS] Digital signature created.")
    
    # 5. Test Decryption (User B decrypts with User B private key)
    print("\n5. Testing File Decryption...")
    dec_file = os.path.join(FILES_DIR, "decrypted.txt")
    decrypt_file(enc_file, dec_file, priv_b)
    assert os.path.exists(dec_file), "Decrypted file missing"
    with open(dec_file, "rb") as f:
        decrypted_bytes = f.read()
    assert decrypted_bytes == original_bytes, "Decrypted content does NOT match original!"
    print("   [PASS] Decrypted content matches original byte-for-byte!")
    
    # 6. Test Signature Verification
    print("\n6. Testing Digital Signature Verification...")
    verified = verify_signature(dec_file, sig_file, pub_a)
    assert verified is True, "Signature verification failed for authentic file!"
    print("   [PASS] Digital signature successfully verified.")
    
    # 7. Test Tamper Detection (Modify 1 byte in decrypted file and re-verify)
    print("\n7. Testing Tamper Detection on Modified File...")
    tampered_file = os.path.join(FILES_DIR, "tampered.txt")
    with open(tampered_file, "wb") as f:
        f.write(original_bytes + b"\n[TAMPERED EXTRA BYTE]")
        
    tamper_verified = verify_signature(tampered_file, sig_file, pub_a)
    assert tamper_verified is False, "Tampered file passed verification unexpectedly!"
    print("   [PASS] Tampered file correctly rejected by signature verifier.")
    
    print("\n🎉 ALL 7 TEST CASES PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
