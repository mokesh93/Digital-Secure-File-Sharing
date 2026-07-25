import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading

# Import crypto modules
from crypto.exchange import initialize_default_users, get_user_keys_paths, create_user_keys
from crypto.encrypt import encrypt_file
from crypto.decrypt import decrypt_file
from crypto.sign import sign_file
from crypto.verify import verify_signature
from utils.helper import create_sample_file, FILES_DIR, format_file_size
from utils.logger import logger, LOG_FILE

class SecureFileSharingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Secure File Sharing (RSA-4096 + AES-256)")
        self.root.geometry("850x700")
        self.root.minsize(750, 600)

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Colors
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        
        self.root.configure(bg=self.bg_color)
        self.style.configure(".", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10))
        self.style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#313244", foreground=self.fg_color, padding=[12, 8], font=("Segoe UI", 10, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", "#45475a")], foreground=[("selected", self.accent_color)])
        self.style.configure("TFrame", background=self.bg_color)
        self.style.configure("TLabelframe", background=self.bg_color, foreground=self.accent_color, borderwidth=1, relief="solid")
        self.style.configure("TLabelframe.Label", background=self.bg_color, foreground=self.accent_color, font=("Segoe UI", 10, "bold"))
        self.style.configure("TButton", background="#45475a", foreground="#ffffff", font=("Segoe UI", 10, "bold"), padding=6)
        self.style.map("TButton", background=[("active", "#585b70")])

        # Header Title
        header_frame = tk.Frame(root, bg="#11111b", height=60)
        header_frame.pack(fill="x", side="top")
        
        title_label = tk.Label(
            header_frame, 
            text="🔐 Digital Secure File Sharing (RSA-4096 + AES-256)", 
            font=("Segoe UI", 14, "bold"), 
            bg="#11111b", 
            fg=self.accent_color
        )
        title_label.pack(pady=12)

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=15)

        self.tab_keys = ttk.Frame(self.notebook)
        self.tab_encrypt = ttk.Frame(self.notebook)
        self.tab_decrypt = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_keys, text="🔑 Key Management")
        self.notebook.add(self.tab_encrypt, text="🔒 Encrypt & Sign")
        self.notebook.add(self.tab_decrypt, text="🔓 Decrypt & Verify")
        self.notebook.add(self.tab_logs, text="📜 Security Audit Logs")

        # Build Tab Interfaces
        self._build_key_management_tab()
        self._build_encrypt_tab()
        self._build_decrypt_tab()
        self._build_logs_tab()

        # Status Bar
        self.status_var = tk.StringVar(value="Ready. System initialized.")
        status_bar = tk.Label(root, textvariable=self.status_var, bg="#11111b", fg="#a6adc8", anchor="w", font=("Segoe UI", 9), px=10, py=4)
        status_bar.pack(fill="x", side="bottom")

        # Create sample file if needed
        create_sample_file()
        self.update_key_status()

    # ================= TAB 1: KEY MANAGEMENT =================
    def _build_key_management_tab(self):
        frame = ttk.LabelFrame(self.tab_keys, text=" RSA-4096 User Profiles & Key Exchange ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        # User A Box
        lbl_a = tk.Label(frame, text="User A Profile", font=("Segoe UI", 11, "bold"), bg=self.bg_color, fg="#a6e3a1")
        lbl_a.grid(row=0, column=0, sticky="w", padx=15, pady=(15, 5))
        
        self.lbl_user_a_status = tk.Label(frame, text="Status: Checking...", bg=self.bg_color, fg="#cdd6f4")
        self.lbl_user_a_status.grid(row=1, column=0, sticky="w", padx=15, pady=2)
        
        btn_gen_a = ttk.Button(frame, text="Generate User A Keys (4096-bit)", command=lambda: self.generate_keys_for_user("user_a"))
        btn_gen_a.grid(row=2, column=0, sticky="w", padx=15, pady=10)

        # User B Box
        lbl_b = tk.Label(frame, text="User B Profile", font=("Segoe UI", 11, "bold"), bg=self.bg_color, fg="#f9e2af")
        lbl_b.grid(row=0, column=1, sticky="w", padx=15, pady=(15, 5))
        
        self.lbl_user_b_status = tk.Label(frame, text="Status: Checking...", bg=self.bg_color, fg="#cdd6f4")
        self.lbl_user_b_status.grid(row=1, column=1, sticky="w", padx=15, pady=2)
        
        btn_gen_b = ttk.Button(frame, text="Generate User B Keys (4096-bit)", command=lambda: self.generate_keys_for_user("user_b"))
        btn_gen_b.grid(row=2, column=1, sticky="w", padx=15, pady=10)

        # Batch init
        btn_gen_all = ttk.Button(frame, text="🚀 Generate/Initialize Keys for Both Users", command=self.generate_all_keys)
        btn_gen_all.grid(row=3, column=0, columnspan=2, pady=20, padx=15)

        # Info Box
        info_txt = (
            "📌 Internship Note on RSA-4096 Key Management:\n"
            "• Public keys are shared openly with senders to wrap symmetric encryption keys.\n"
            "• Private keys MUST be kept strictly confidential to unwrap keys and sign files.\n"
            "• Key storage location: users/user_a/ and users/user_b/ subdirectories."
        )
        lbl_info = tk.Label(frame, text=info_txt, justify="left", bg="#313244", fg="#cdd6f4", font=("Segoe UI", 9), padx=10, pady=10)
        lbl_info.grid(row=4, column=0, columnspan=2, sticky="ew", padx=15, pady=15)

    def update_key_status(self):
        priv_a, pub_a = get_user_keys_paths("user_a")
        priv_b, pub_b = get_user_keys_paths("user_b")

        if os.path.exists(priv_a) and os.path.exists(pub_a):
            self.lbl_user_a_status.config(text="Status: ✅ Keys Active (RSA-4096)", fg="#a6e3a1")
        else:
            self.lbl_user_a_status.config(text="Status: ⚠️ Keys Not Found", fg="#f38ba8")

        if os.path.exists(priv_b) and os.path.exists(pub_b):
            self.lbl_user_b_status.config(text="Status: ✅ Keys Active (RSA-4096)", fg="#a6e3a1")
        else:
            self.lbl_user_b_status.config(text="Status: ⚠️ Keys Not Found", fg="#f38ba8")

    def generate_keys_for_user(self, user_name):
        def task():
            self.status_var.set(f"Generating 4096-bit RSA keys for {user_name}... Please wait.")
            create_user_keys(user_name, key_size=4096, force_overwrite=True)
            self.update_key_status()
            self.status_var.set(f"Keys generated successfully for {user_name}.")
            messagebox.showinfo("Success", f"4096-bit RSA Keys generated for {user_name}!")
            self.refresh_logs()
        threading.Thread(target=task, daemon=True).start()

    def generate_all_keys(self):
        def task():
            self.status_var.set("Generating 4096-bit RSA keys for User A and User B... Please wait.")
            initialize_default_users(key_size=4096)
            self.update_key_status()
            self.status_var.set("Keys generated successfully for User A & User B.")
            messagebox.showinfo("Success", "Keys initialized for User A & User B!")
            self.refresh_logs()
        threading.Thread(target=task, daemon=True).start()

    # ================= TAB 2: ENCRYPT & SIGN =================
    def _build_encrypt_tab(self):
        frame = ttk.LabelFrame(self.tab_encrypt, text=" Hybrid File Encryption & Digital Signature ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        # Dynamic User Selection: Sender and Recipient
        tk.Label(frame, text="Sender User (Signs Payload):", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky="w", padx=15, pady=8)
        self.combo_enc_sender = ttk.Combobox(frame, values=["User A", "User B"], state="readonly", width=18)
        self.combo_enc_sender.set("User A")
        self.combo_enc_sender.grid(row=0, column=1, sticky="w", padx=5, pady=8)
        self.combo_enc_sender.bind("<<ComboboxSelected>>", self._on_enc_role_changed)

        tk.Label(frame, text="Recipient User (Encrypts For):", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, sticky="w", padx=15, pady=8)
        self.combo_enc_recipient = ttk.Combobox(frame, values=["User B", "User A"], state="readonly", width=18)
        self.combo_enc_recipient.set("User B")
        self.combo_enc_recipient.grid(row=1, column=1, sticky="w", padx=5, pady=8)
        self.combo_enc_recipient.bind("<<ComboboxSelected>>", self._on_enc_role_changed)

        # File Selection
        tk.Label(frame, text="Target File to Encrypt:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky="w", padx=15, pady=8)
        self.entry_enc_file = ttk.Entry(frame, width=50)
        self.entry_enc_file.insert(0, os.path.join(FILES_DIR, "sample.txt"))
        self.entry_enc_file.grid(row=2, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_enc_file).grid(row=2, column=2, padx=5, pady=8)

        # Recipient Public Key Path
        tk.Label(frame, text="Recipient Public Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=3, column=0, sticky="w", padx=15, pady=8)
        self.entry_rec_pubkey = ttk.Entry(frame, width=50)
        self.entry_rec_pubkey.insert(0, get_user_keys_paths("user_b")[1])
        self.entry_rec_pubkey.grid(row=3, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_rec_pubkey).grid(row=3, column=2, padx=5, pady=8)

        # Sender Private Key Path
        tk.Label(frame, text="Sender Private Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=4, column=0, sticky="w", padx=15, pady=8)
        self.entry_snd_privkey = ttk.Entry(frame, width=50)
        self.entry_snd_privkey.insert(0, get_user_keys_paths("user_a")[0])
        self.entry_snd_privkey.grid(row=4, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_snd_privkey).grid(row=4, column=2, padx=5, pady=8)

        # Submit Action
        btn_encrypt = ttk.Button(frame, text="🔒 Encrypt & Sign File", command=self.perform_encryption)
        btn_encrypt.grid(row=5, column=0, columnspan=3, pady=20)

    def _on_enc_role_changed(self, event=None):
        sender = self.combo_enc_sender.get().lower().replace(" ", "_")
        recipient = self.combo_enc_recipient.get().lower().replace(" ", "_")

        snd_priv, _ = get_user_keys_paths(sender)
        _, rec_pub = get_user_keys_paths(recipient)

        self.entry_snd_privkey.delete(0, tk.END)
        self.entry_snd_privkey.insert(0, snd_priv)

        self.entry_rec_pubkey.delete(0, tk.END)
        self.entry_rec_pubkey.insert(0, rec_pub)

    def browse_enc_file(self):
        f = filedialog.askopenfilename(initialdir=FILES_DIR)
        if f:
            self.entry_enc_file.delete(0, tk.END)
            self.entry_enc_file.insert(0, f)

    def browse_rec_pubkey(self):
        f = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if f:
            self.entry_rec_pubkey.delete(0, tk.END)
            self.entry_rec_pubkey.insert(0, f)

    def browse_snd_privkey(self):
        f = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if f:
            self.entry_snd_privkey.delete(0, tk.END)
            self.entry_snd_privkey.insert(0, f)

    def perform_encryption(self):
        in_file = self.entry_enc_file.get()
        rec_pub = self.entry_rec_pubkey.get()
        snd_priv = self.entry_snd_privkey.get()

        sender_name = self.combo_enc_sender.get()
        recipient_name = self.combo_enc_recipient.get()

        out_bin = os.path.join(FILES_DIR, "encrypted.bin")
        out_sig = os.path.join(FILES_DIR, "signature.sig")

        if not os.path.exists(in_file):
            messagebox.showerror("Error", "Target input file does not exist!")
            return
        if not os.path.exists(rec_pub):
            messagebox.showerror("Error", f"Recipient ({recipient_name}) public key PEM file not found!")
            return
        if not os.path.exists(snd_priv):
            messagebox.showerror("Error", f"Sender ({sender_name}) private key PEM file not found!")
            return

        def task():
            try:
                self.status_var.set(f"Encrypting file from {sender_name} to {recipient_name}...")
                encrypt_file(in_file, out_bin, rec_pub)
                
                self.status_var.set(f"Signing file with {sender_name}'s private key...")
                sign_file(in_file, snd_priv, out_sig)

                self.status_var.set("Encryption & Signature Complete.")
                msg = (
                    f"✅ File Encrypted & Signed Successfully!\n\n"
                    f"Sender: {sender_name}\n"
                    f"Recipient: {recipient_name}\n"
                    f"Encrypted File: {out_bin}\n"
                    f"Digital Signature: {out_sig}"
                )
                messagebox.showinfo("Success", msg)
                self.refresh_logs()
            except Exception as e:
                logger.error(f"Encryption failed: {e}")
                messagebox.showerror("Error", f"Encryption failed: {e}")
                self.status_var.set("Encryption failed.")
        threading.Thread(target=task, daemon=True).start()

    # ================= TAB 3: DECRYPT & VERIFY =================
    def _build_decrypt_tab(self):
        frame = ttk.LabelFrame(self.tab_decrypt, text=" File Decryption & Signature Verification ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        # Dynamic User Selection: Recipient and Sender
        tk.Label(frame, text="Recipient User (Decryptor):", bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky="w", padx=15, pady=8)
        self.combo_dec_recipient = ttk.Combobox(frame, values=["User B", "User A"], state="readonly", width=18)
        self.combo_dec_recipient.set("User B")
        self.combo_dec_recipient.grid(row=0, column=1, sticky="w", padx=5, pady=8)
        self.combo_dec_recipient.bind("<<ComboboxSelected>>", self._on_dec_role_changed)

        tk.Label(frame, text="Sender User (Signer to Verify):", bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, sticky="w", padx=15, pady=8)
        self.combo_dec_sender = ttk.Combobox(frame, values=["User A", "User B"], state="readonly", width=18)
        self.combo_dec_sender.set("User A")
        self.combo_dec_sender.grid(row=1, column=1, sticky="w", padx=5, pady=8)
        self.combo_dec_sender.bind("<<ComboboxSelected>>", self._on_dec_role_changed)

        # Encrypted File
        tk.Label(frame, text="Encrypted File (.bin):", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky="w", padx=15, pady=8)
        self.entry_dec_file = ttk.Entry(frame, width=50)
        self.entry_dec_file.insert(0, os.path.join(FILES_DIR, "encrypted.bin"))
        self.entry_dec_file.grid(row=2, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_dec_file).grid(row=2, column=2, padx=5, pady=8)

        # Signature File
        tk.Label(frame, text="Digital Signature (.sig):", bg=self.bg_color, fg=self.fg_color).grid(row=3, column=0, sticky="w", padx=15, pady=8)
        self.entry_sig_file = ttk.Entry(frame, width=50)
        self.entry_sig_file.insert(0, os.path.join(FILES_DIR, "signature.sig"))
        self.entry_sig_file.grid(row=3, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_sig_file).grid(row=3, column=2, padx=5, pady=8)

        # Recipient Private Key
        tk.Label(frame, text="Recipient Private Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=4, column=0, sticky="w", padx=15, pady=8)
        self.entry_rec_privkey = ttk.Entry(frame, width=50)
        self.entry_rec_privkey.insert(0, get_user_keys_paths("user_b")[0])
        self.entry_rec_privkey.grid(row=4, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_rec_privkey).grid(row=4, column=2, padx=5, pady=8)

        # Sender Public Key
        tk.Label(frame, text="Sender Public Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=5, column=0, sticky="w", padx=15, pady=8)
        self.entry_snd_pubkey = ttk.Entry(frame, width=50)
        self.entry_snd_pubkey.insert(0, get_user_keys_paths("user_a")[1])
        self.entry_snd_pubkey.grid(row=5, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_snd_pubkey).grid(row=5, column=2, padx=5, pady=8)

        # Submit Action
        btn_decrypt = ttk.Button(frame, text="🔓 Decrypt & Verify Signature", command=self.perform_decryption)
        btn_decrypt.grid(row=6, column=0, columnspan=3, pady=15)

    def _on_dec_role_changed(self, event=None):
        recipient = self.combo_dec_recipient.get().lower().replace(" ", "_")
        sender = self.combo_dec_sender.get().lower().replace(" ", "_")

        rec_priv, _ = get_user_keys_paths(recipient)
        _, snd_pub = get_user_keys_paths(sender)

        self.entry_rec_privkey.delete(0, tk.END)
        self.entry_rec_privkey.insert(0, rec_priv)

        self.entry_snd_pubkey.delete(0, tk.END)
        self.entry_snd_pubkey.insert(0, snd_pub)

    def browse_dec_file(self):
        f = filedialog.askopenfilename(filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")])
        if f:
            self.entry_dec_file.delete(0, tk.END)
            self.entry_dec_file.insert(0, f)

    def browse_sig_file(self):
        f = filedialog.askopenfilename(filetypes=[("Signature Files", "*.sig"), ("All Files", "*.*")])
        if f:
            self.entry_sig_file.delete(0, tk.END)
            self.entry_sig_file.insert(0, f)

    def browse_rec_privkey(self):
        f = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if f:
            self.entry_rec_privkey.delete(0, tk.END)
            self.entry_rec_privkey.insert(0, f)

    def browse_snd_pubkey(self):
        f = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if f:
            self.entry_snd_pubkey.delete(0, tk.END)
            self.entry_snd_pubkey.insert(0, f)

    def perform_decryption(self):
        enc_file = self.entry_dec_file.get()
        sig_file = self.entry_sig_file.get()
        rec_priv = self.entry_rec_privkey.get()
        snd_pub = self.entry_snd_pubkey.get()

        recipient_name = self.combo_dec_recipient.get()
        sender_name = self.combo_dec_sender.get()

        out_dec = os.path.join(FILES_DIR, "decrypted.txt")

        if not os.path.exists(enc_file):
            messagebox.showerror("Error", "Encrypted file (.bin) not found!")
            return
        if not os.path.exists(rec_priv):
            messagebox.showerror("Error", f"Recipient ({recipient_name}) private key PEM file not found!")
            return

        def task():
            try:
                self.status_var.set(f"Decrypting AES-256 payload as {recipient_name}...")
                decrypt_file(enc_file, out_dec, rec_priv)

                sig_verified = False
                if os.path.exists(sig_file) and os.path.exists(snd_pub):
                    self.status_var.set(f"Verifying signature against {sender_name}'s public key...")
                    sig_verified = verify_signature(out_dec, sig_file, snd_pub)

                self.status_var.set("Decryption complete.")

                status_msg = f"✅ Signature Verified: Authentic file from {sender_name}" if sig_verified else f"⚠️ Signature Verification Failed for {sender_name} or file missing!"
                
                # Preview text content
                preview = ""
                if os.path.exists(out_dec):
                    with open(out_dec, "r", encoding="utf-8", errors="ignore") as f:
                        preview = f.read(300)

                msg = (
                    f"🔓 File Decrypted Successfully by {recipient_name}!\n\n"
                    f"Saved to: {out_dec}\n"
                    f"Status: {status_msg}\n\n"
                    f"Content Preview:\n----------------\n{preview}"
                )
                if sig_verified:
                    messagebox.showinfo("Decryption & Signature Success", msg)
                else:
                    messagebox.showwarning("Decryption Warning", msg)
                self.refresh_logs()
            except Exception as e:
                logger.error(f"Decryption error: {e}")
                messagebox.showerror("Decryption Failed", f"Failed to decrypt file:\n{e}")
                self.status_var.set("Decryption failed.")
        threading.Thread(target=task, daemon=True).start()

    # ================= TAB 4: LOGS =================
    def _build_logs_tab(self):
        frame = ttk.LabelFrame(self.tab_logs, text=" Real-time Security Event Audit Log ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.log_text = scrolledtext.ScrolledText(frame, bg="#11111b", fg="#a6adc8", font=("Consolas", 10), wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)

        btn_refresh = ttk.Button(frame, text="🔄 Refresh Log View", command=self.refresh_logs)
        btn_refresh.pack(pady=5)
        self.refresh_logs()

    def refresh_logs(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            # Format lines to ensure every entry is on a distinct separate line
            clean_content = "".join([line.strip() + "\n" for line in lines if line.strip()])
            
            self.log_text.delete("1.0", tk.END)
            self.log_text.insert(tk.END, clean_content)
            self.log_text.see(tk.END)

def launch_gui():
    root = tk.Tk()
    app = SecureFileSharingGUI(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
