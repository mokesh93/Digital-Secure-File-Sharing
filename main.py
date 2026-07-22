import os
import sys
import argparse

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.exchange import initialize_default_users, get_user_keys_paths
from crypto.encrypt import encrypt_file
from crypto.decrypt import decrypt_file
from crypto.sign import sign_file
from crypto.verify import verify_signature
from utils.helper import create_sample_file, FILES_DIR
from utils.logger import logger

def cli_menu():
    """Interactive Command-Line Interface Menu."""
    create_sample_file()
    
    while True:
        print("\n=========================================================")
        print("   🔐 DIGITAL SECURE FILE SHARING (RSA-4096 + AES-256)   ")
        print("=========================================================")
        print(" 1. 🔑 Generate / Reset RSA-4096 Keys for User A & User B")
        print(" 2. 🔒 Encrypt & Sign File (User A -> User B)")
        print(" 3. 🔓 Decrypt & Verify File Signature (User B)")
        print(" 4. 🖥️ Launch Tkinter Desktop GUI")
        print(" 5. ❌ Exit Application")
        print("=========================================================")
        
        choice = input("Enter choice (1-5): ").strip()
        
        if choice == "1":
            print("\n[1] Generating 4096-bit RSA Keys...")
            initialize_default_users(key_size=4096)
            print("✅ User A & User B keys generated inside users/ directory.")
            
        elif choice == "2":
            print("\n[2] Encrypting & Signing File...")
            sample_path = os.path.join(FILES_DIR, "sample.txt")
            out_bin = os.path.join(FILES_DIR, "encrypted.bin")
            out_sig = os.path.join(FILES_DIR, "signature.sig")
            
            _, pub_b = get_user_keys_paths("user_b")
            priv_a, _ = get_user_keys_paths("user_a")
            
            if not os.path.exists(pub_b) or not os.path.exists(priv_a):
                print("❌ Keys missing! Please generate keys first using Option 1.")
                continue
                
            encrypt_file(sample_path, out_bin, pub_b)
            sign_file(sample_path, priv_a, out_sig)
            
            print(f"✅ File Encrypted: {out_bin}")
            print(f"✅ Signature Created: {out_sig}")
            
        elif choice == "3":
            print("\n[3] Decrypting File & Verifying Signature...")
            out_bin = os.path.join(FILES_DIR, "encrypted.bin")
            out_sig = os.path.join(FILES_DIR, "signature.sig")
            out_dec = os.path.join(FILES_DIR, "decrypted.txt")
            
            priv_b, _ = get_user_keys_paths("user_b")
            _, pub_a = get_user_keys_paths("user_a")
            
            if not os.path.exists(out_bin):
                print("❌ Encrypted file missing! Encrypt a file first using Option 2.")
                continue
                
            try:
                decrypt_file(out_bin, out_dec, priv_b)
                verified = verify_signature(out_dec, out_sig, pub_a)
                
                print(f"✅ File Decrypted: {out_dec}")
                if verified:
                    print("✅ DIGITAL SIGNATURE VERIFIED: Sender is authentic & file unaltered.")
                else:
                    print("❌ SIGNATURE VERIFICATION FAILED! File may be altered.")
                    
                with open(out_dec, "r", encoding="utf-8") as f:
                    print("\n--- Decrypted File Content Preview ---")
                    print(f.read(300))
                    print("---------------------------------------")
            except Exception as e:
                print(f"❌ Decryption Failed: {e}")
                
        elif choice == "4":
            print("\nLaunching Desktop GUI Interface...")
            try:
                from gui.app_gui import launch_gui
                launch_gui()
            except Exception as e:
                print(f"❌ Could not launch GUI: {e}")
                
        elif choice == "5":
            print("\nExiting Secure File Sharing Application. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid selection. Please enter a number from 1 to 5.")

def main():
    parser = argparse.ArgumentParser(description="Digital Secure File Sharing (RSA-4096 + AES-256)")
    parser.add_argument("--gui", action="store_true", help="Launch Graphical User Interface")
    parser.add_argument("--cli", action="store_true", help="Launch Interactive Command Line Menu")
    args = parser.parse_args()

    if args.cli:
        cli_menu()
    else:
        # Default launch GUI, fallback to CLI if tkinter or display fails
        try:
            from gui.app_gui import launch_gui
            launch_gui()
        except Exception as e:
            logger.warning(f"GUI launch failed or unavailable ({e}). Falling back to CLI menu.")
            cli_menu()

if __name__ == "__main__":
    main()
