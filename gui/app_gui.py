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
        self.root.title("Digital Secure File Sharing (RSA-4096 + AES-256 Dual User Edition)")
        self.root.geometry("950x750")
        self.root.minsize(850, 650)

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
            text="🔐 Digital Secure File Sharing (RSA-4096 + AES-256 Dual User View)", 
            font=("Segoe UI", 14, "bold"), 
            bg="#11111b", 
            fg=self.accent_color
        )
        title_label.pack(pady=12)

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=15)

        self.tab_split = ttk.Frame(self.notebook)
        self.tab_keys = ttk.Frame(self.notebook)
        self.tab_encrypt = ttk.Frame(self.notebook)
        self.tab_decrypt = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_split, text="⚡ Split-Screen Dual User View")
        self.notebook.add(self.tab_keys, text="🔑 Key Management")
        self.notebook.add(self.tab_encrypt, text="🔒 Manual Encrypt & Sign")
        self.notebook.add(self.tab_decrypt, text="🔓 Manual Decrypt & Verify")
        self.notebook.add(self.tab_logs, text="📜 Security Audit Logs")

        # Build Tab Interfaces
        self._build_split_tab()
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

    # ================= TAB 1: SPLIT-SCREEN DUAL USER VIEW =================
    def _build_split_tab(self):
        container = ttk.Frame(self.tab_split)
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # Left Side: User A (Sender)
        left_frame = ttk.LabelFrame(container, text=" 👤 User A (Sender Panel) ")
        left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        tk.Label(left_frame, text="Payload to Send to User B:", bg=self.bg_color, fg=self.fg_color, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10, 2))
        
        self.txt_split_send = scrolledtext.ScrolledText(left_frame, height=8, bg="#11111b", fg="#cdd6f4", font=("Consolas", 10), wrap="word")
        self.txt_split_send.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt_split_send.insert(tk.END, "CONFIDENTIAL INTERNSHIP DEMO: Secure file payload sent from User A to User B using AES-256-GCM encryption and RSA-4096 digital signatures.")

        btn_send = ttk.Button(left_frame, text="🔒 Encrypt & Send to User B ➔", command=self.perform_split_send)
        btn_send.pack(fill="x", padx=10, pady=10)

        self.lbl_split_send_status = tk.Label(left_frame, text="", bg=self.bg_color, fg="#a6e3a1", font=("Segoe UI", 9))
        self.lbl_split_send_status.pack(padx=10, pady=5)

        # Right Side: User B (Recipient Inbox)
        right_frame = ttk.LabelFrame(container, text=" 👤 User B (Recipient Inbox) ")
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        tk.Label(right_frame, text="Incoming Encrypted Package Queue:", bg=self.bg_color, fg=self.fg_color, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10, 2))

        self.txt_split_inbox = scrolledtext.ScrolledText(right_frame, height=5, bg="#0d1117", fg="#a5d6ff", font=("Consolas", 9), wrap="word")
        self.txt_split_inbox.pack(fill="x", padx=10, pady=5)
        self.txt_split_inbox.insert(tk.END, "[No incoming package received yet. Click 'Encrypt & Send' on left panel]")

        self.btn_split_decrypt = ttk.Button(right_frame, text="🔓 Decrypt & Verify Signature", command=self.perform_split_decrypt, state="disabled")
        self.btn_split_decrypt.pack(fill="x", padx=10, pady=10)

        tk.Label(right_frame, text="Decrypted Plaintext Output:", bg=self.bg_color, fg=self.fg_color, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(5, 2))
        
        self.txt_split_decrypted = scrolledtext.ScrolledText(right_frame, height=6, bg="#11111b", fg="#a6e3a1", font=("Consolas", 10), wrap="word")
        self.txt_split_decrypted.pack(fill="both", expand=True, padx=10, pady=5)

    def perform_split_send(self):
        text_payload = self.txt_split_send.get("1.0", tk.END).strip()
        if not text_payload:
            messagebox.showwarning("Warning", "Please enter payload text to send!")
            return

        priv_a, _ = get_user_keys_paths("user_a")
        _, pub_b = get_user_keys_paths("user_b")

        if not os.path.exists(priv_a) or not os.path.exists(pub_b):
            messagebox.showerror("Error", "User A or User B keys missing! Please generate keys first.")
            return

        temp_input = os.path.join(FILES_DIR, "split_temp.txt")
        out_bin = os.path.join(FILES_DIR, "encrypted.bin")
        out_sig = os.path.join(FILES_DIR, "signature.sig")

        with open(temp_input, "w", encoding="utf-8") as f:
            f.write(text_payload)

        def task():
            try:
                self.status_var.set("User A encrypting payload for User B...")
                encrypt_file(temp_input, out_bin, pub_b)
                
                self.status_var.set("User A signing payload with RSA-4096 private key...")
                sign_file(temp_input, priv_a, out_sig)

                self.status_var.set("Transmission complete. Received in User B inbox.")
                
                self.lbl_split_send_status.config(text="✅ Sent Encrypted Package to User B!")
                
                # Update User B Inbox
                inbox_msg = f"📦 INCOMING ENCRYPTED PACKAGE (User A → User B)\n• Binary File: {out_bin}\n• Signature File: {out_sig}\n• Status: Ready for Decryption"
                self.txt_split_inbox.delete("1.0", tk.END)
                self.txt_split_inbox.insert(tk.END, inbox_msg)
                
                self.btn_split_decrypt.config(state="normal")
                self.refresh_logs()
            except Exception as e:
                logger.error(f"Split send error: {e}")
                messagebox.showerror("Error", f"Failed to send package: {e}")
        threading.Thread(target=task, daemon=True).start()

    def perform_split_decrypt(self):
        priv_b, _ = get_user_keys_paths("user_b")
        _, pub_a = get_user_keys_paths("user_a")

        out_bin = os.path.join(FILES_DIR, "encrypted.bin")
        out_sig = os.path.join(FILES_DIR, "signature.sig")
        out_dec = os.path.join(FILES_DIR, "decrypted.txt")

        def task():
            try:
                self.status_var.set("User B unwrapping AES key & decrypting payload...")
                decrypt_file(out_bin, out_dec, priv_b)

                self.status_var.set("User B verifying User A's RSA-PSS digital signature...")
                verified = verify_signature(out_dec, out_sig, pub_a)

                with open(out_dec, "r", encoding="utf-8", errors="ignore") as f:
                    decrypted_text = f.read()

                self.txt_split_decrypted.delete("1.0", tk.END)
                status_header = "✅ SIGNATURE VERIFIED (Authentic File from User A)\n------------------------------------------------\n" if verified else "⚠️ SIGNATURE VERIFICATION FAILED!\n------------------------------------------------\n"
                self.txt_split_decrypted.insert(tk.END, status_header + decrypted_text)

                self.status_var.set("User B decryption & verification successful!")
                self.refresh_logs()
            except Exception as e:
                logger.error(f"Split decrypt error: {e}")
                messagebox.showerror("Error", f"Failed to decrypt package: {e}")
        threading.Thread(target=task, daemon=True).start()

    # ================= TAB 2: KEY MANAGEMENT =================
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

    # ================= TAB 3: MANUAL ENCRYPT & SIGN =================
    def _build_encrypt_tab(self):
        frame = ttk.LabelFrame(self.tab_encrypt, text=" Hybrid File Encryption & Digital Signature ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

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

        tk.Label(frame, text="Target File to Encrypt:", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky="w", padx=15, pady=8)
        self.entry_enc_file = ttk.Entry(frame, width=50)
        self.entry_enc_file.insert(0, os.path.join(FILES_DIR, "sample.txt"))
        self.entry_enc_file.grid(row=2, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_enc_file).grid(row=2, column=2, padx=5, pady=8)

        tk.Label(frame, text="Recipient Public Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=3, column=0, sticky="w", padx=15, pady=8)
        self.entry_rec_pubkey = ttk.Entry(frame, width=50)
        self.entry_rec_pubkey.insert(0, get_user_keys_paths("user_b")[1])
        self.entry_rec_pubkey.grid(row=3, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_rec_pubkey).grid(row=3, column=2, padx=5, pady=8)

        tk.Label(frame, text="Sender Private Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=4, column=0, sticky="w", padx=15, pady=8)
        self.entry_snd_privkey = ttk.Entry(frame, width=50)
        self.entry_snd_privkey.insert(0, get_user_keys_paths("user_a")[0])
        self.entry_snd_privkey.grid(row=4, column=1, padx=5, pady=8)
        ttk.Button(frame, text="Browse...", command=self.browse_snd_privkey).grid(row=4, column=2, padx=5, pady=8)

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

        out_bin = os.path.join(FILES_DIR, "encrypted.bin")
        out_sig = os.path.join(FILES_DIR, "signature.sig")

        if not os.path.exists(in_file):
            messagebox.showerror("Error", "Target input file does not exist!")
            return

        def task():
            try:
                encrypt_file(in_file, out_bin, rec_pub)
                sign_file(in_file, snd_priv, out_sig)
                messagebox.showinfo("Success", f"File Encrypted & Signed!\n\nEncrypted: {out_bin}\nSignature: {out_sig}")
                self.refresh_logs()
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")
        threading.Thread(target=task, daemon=True).start()

    # ================= TAB 4: MANUAL DECRYPT & VERIFY =================
    def _build_decrypt_tab(self):
        frame = ttk.LabelFrame(self.tab_decrypt, text=" File Decryption & Signature Verification ")
        frame.pack(fill="both", expand=True, padx=15, pady=15)

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

        tk.Label(frame, text="Encrypted File (.bin):", bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky="w", padx=15, pady=8)
        self.entry_dec_file = ttk.Entry(frame, width=50)
        self.entry_dec_file.insert(0, os.path.join(FILES_DIR, "encrypted.bin"))
        self.entry_dec_file.grid(row=2, column=1, padx=5, pady=8)

        tk.Label(frame, text="Digital Signature (.sig):", bg=self.bg_color, fg=self.fg_color).grid(row=3, column=0, sticky="w", padx=15, pady=8)
        self.entry_sig_file = ttk.Entry(frame, width=50)
        self.entry_sig_file.insert(0, os.path.join(FILES_DIR, "signature.sig"))
        self.entry_sig_file.grid(row=3, column=1, padx=5, pady=8)

        tk.Label(frame, text="Recipient Private Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=4, column=0, sticky="w", padx=15, pady=8)
        self.entry_rec_privkey = ttk.Entry(frame, width=50)
        self.entry_rec_privkey.insert(0, get_user_keys_paths("user_b")[0])
        self.entry_rec_privkey.grid(row=4, column=1, padx=5, pady=8)

        tk.Label(frame, text="Sender Public Key (.pem):", bg=self.bg_color, fg=self.fg_color).grid(row=5, column=0, sticky="w", padx=15, pady=8)
        self.entry_snd_pubkey = ttk.Entry(frame, width=50)
        self.entry_snd_pubkey.insert(0, get_user_keys_paths("user_a")[1])
        self.entry_snd_pubkey.grid(row=5, column=1, padx=5, pady=8)

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

    def perform_decryption(self):
        enc_file = self.entry_dec_file.get()
        sig_file = self.entry_sig_file.get()
        rec_priv = self.entry_rec_privkey.get()
        snd_pub = self.entry_snd_pubkey.get()
        out_dec = os.path.join(FILES_DIR, "decrypted.txt")

        def task():
            try:
                decrypt_file(enc_file, out_dec, rec_priv)
                verified = verify_signature(out_dec, sig_file, snd_pub)
                messagebox.showinfo("Decryption Success", f"File Decrypted!\n\nSignature Verified: {verified}")
                self.refresh_logs()
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        threading.Thread(target=task, daemon=True).start()

    # ================= TAB 5: LOGS =================
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
