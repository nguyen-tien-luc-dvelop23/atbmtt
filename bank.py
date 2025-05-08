import tkinter as tk
from tkinter import messagebox, ttk
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import random
import json
import base64
import os
from PIL import Image, ImageTk

class BankEncryptionGame:
    def __init__(self, root):
        self.root = root
        self.users_file = "users.txt"
        self.language = "vi"
        self.root.title("Hệ thống mã hóa ngân hàng" if self.language == "vi" else "Bank Encryption System")
        
        self.texts = {
            "vi": {
                "loading": "Đang mở ứng dụng ngân hàng...",
                "bank_greeting": "Ngân hàng Nguyễn Tiến Lực xin chào",
                "welcome": "Chào mừng đến với Hệ thống mã hóa ngân hàng",
                "login": "Đăng nhập",
                "register": "Đăng ký",
                "username": "Tên đăng nhập:",
                "password": "Mật khẩu:",
                "new_username": "Tên đăng nhập mới:",
                "new_password": "Mật khẩu mới:",
                "confirm_password": "Xác nhận mật khẩu:",
                "back_to_register": "Quay lại đăng ký",
                "back_to_login": "Quay lại đăng nhập",
                "empty_fields": "Tên đăng nhập và mật khẩu không được để trống!",
                "password_mismatch": "Mật khẩu không khớp!",
                "username_exists": "Tên đăng nhập đã tồn tại!",
                "register_success": "Đăng ký thành công! Vui lòng đăng nhập.",
                "invalid_login": "Tên đăng nhập hoặc mật khẩu không đúng!",
                "score": "Điểm thưởng: {}",
                "account": "Tài khoản: {}",
                "amount": "Số tiền: {:,} VND",
                "timestamp": "Thời gian: {}",
                "encrypt_button": "Mã hóa (AES)",
                "verify_button": "Xác thực (RSA)",
                "check_sha_button": "Kiểm tra toàn vẹn (SHA)",
                "redeem_button": "Đổi điểm thưởng",
                "already_encrypted": "Giao dịch đã được mã hóa!",
                "encrypt_first": "Hãy mã hóa giao dịch trước!",
                "already_verified": "Giao dịch đã được xác thực!",
                "already_checked": "Đã kiểm tra toàn vẹn!",
                "encrypt_success": "Giao dịch được mã hóa thành công!",
                "rsa_success": "Xác thực RSA thành công!",
                "rsa_failed": "Xác thực RSA thất bại!",
                "sha_intact": "Toàn vẹn giao dịch được xác nhận!",
                "sha_tampered": "Giao dịch đã bị thay đổi!",
                "transaction_success": "Giao dịch được xử lý thành công!",
                "transaction_failed": "Giao dịch thất bại do bị thay đổi!",
                "language_label": "Ngôn ngữ:",
                "redeem_success": "Đổi {} điểm thành {:,} VND thành công!",
                "insufficient_points": "Điểm thưởng không đủ!"
            },
            "en": {
                "loading": "Opening the banking application...",
                "bank_greeting": "Nguyen Tien Luc Bank Welcomes You",
                "welcome": "Welcome to Bank Encryption System",
                "login": "Login",
                "register": "Register",
                "username": "Username:",
                "password": "Password:",
                "new_username": "New Username:",
                "new_password": "New Password:",
                "confirm_password": "Confirm Password:",
                "back_to_register": "Back to Register",
                "back_to_login": "Back to Login",
                "empty_fields": "Username and password cannot be empty!",
                "password_mismatch": "Passwords do not match!",
                "username_exists": "Username already exists!",
                "register_success": "Registration successful! Please login.",
                "invalid_login": "Invalid username or password!",
                "score": "Reward Points: {}",
                "account": "Account: {}",
                "amount": "Amount: {:,} VND",
                "timestamp": "Timestamp: {}",
                "encrypt_button": "Encrypt (AES)",
                "verify_button": "Verify (RSA)",
                "check_sha_button": "Check Integrity (SHA)",
                "redeem_button": "Redeem Points",
                "already_encrypted": "Transaction already encrypted!",
                "encrypt_first": "Encrypt the transaction first!",
                "already_verified": "Transaction already verified!",
                "already_checked": "Integrity already checked!",
                "encrypt_success": "Transaction encrypted successfully!",
                "rsa_success": "RSA verification successful!",
                "rsa_failed": "RSA verification failed!",
                "sha_intact": "Transaction integrity verified!",
                "sha_tampered": "Transaction was tampered!",
                "transaction_success": "Transaction processed successfully!",
                "transaction_failed": "Transaction failed due to tampering!",
                "language_label": "Language:",
                "redeem_success": "Redeemed {} points for {:,} VND successfully!",
                "insufficient_points": "Insufficient reward points!"
            }
        }
        
        self.score = 0
        self.current_user = None
        self.transactions_processed = 0
        self.current_transaction = None
        self.aes_encrypted = False
        self.rsa_verified = False
        self.sha_checked = False
        self.pulse_after_id = None
        
        self.rsa_key = RSA.generate(2048)
        self.signer = pkcs1_15.new(self.rsa_key)
        self.verifier = pkcs1_15.new(self.rsa_key.publickey())
        
        try:
            image = Image.open("background.png")
            image = image.resize((800, 600), Image.LANCZOS)
            self.background_image = ImageTk.PhotoImage(image)
        except Exception as e:
            print(f"Error loading background image: {e}")
            self.background_image = None
        
        self.show_loading_screen()

    def show_loading_screen(self):
        self.loading_frame = tk.Frame(self.root)
        self.loading_frame.pack(fill="both", expand=True)
        
        if self.background_image:
            background_label = tk.Label(self.loading_frame, image=self.background_image)
            background_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Updated color to neon orange
        self.loading_label = tk.Label(self.loading_frame, text=self.texts[self.language]["loading"], font=("Arial", 16, "bold"), fg="#FFA500", bg=None, highlightbackground="black", highlightthickness=1)
        self.loading_label.place(relx=0.5, rely=0.5, anchor="center")
        
        self.pulse_animation()
        
        delay = random.randint(2000, 4000)
        self.root.after(delay, self.start_main_gui)

    def pulse_animation(self):
        if not self.loading_label.winfo_exists():
            return
        
        current_font_size = 16
        try:
            font_config = self.loading_label.cget("font")
            current_font_size = int(font_config.split()[1])
        except (IndexError, ValueError):
            pass
        
        new_font_size = 18 if current_font_size == 16 else 16
        self.loading_label.configure(font=("Arial", new_font_size, "bold"))
        
        if self.loading_frame.winfo_exists():
            self.pulse_after_id = self.root.after(300, self.pulse_animation)

    def start_main_gui(self):
        if self.pulse_after_id is not None:
            self.root.after_cancel(self.pulse_after_id)
            self.pulse_after_id = None
        
        self.loading_frame.destroy()
        self.setup_initial_gui()

    def get_language(self):
        return self.language

    def set_language(self, lang):
        self.language = lang
        if hasattr(self, 'initial_frame'):
            self.setup_initial_gui()
        elif hasattr(self, 'login_frame'):
            self.setup_login_gui()
        elif hasattr(self, 'register_frame'):
            self.setup_register_gui()
        elif hasattr(self, 'game_frame'):
            self.setup_game_gui()
            self.update_transaction_display()

    def load_users(self):
        users = {}
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(':')
                        username = parts[0]
                        hashed_password = parts[1]
                        points = int(parts[3]) if len(parts) > 3 else (int(parts[2]) if len(parts) == 3 else 0)
                        users[username] = {
                            'password': hashed_password,
                            'points': points
                        }
            self.update_users_file(users)
        return users

    def update_users_file(self, users):
        with open(self.users_file, 'w') as f:
            for user, data in users.items():
                f.write(f"{user}:{data['password']}:{data['points']}\n")

    def save_user(self, username, hashed_password, points=0):
        with open(self.users_file, 'a') as f:
            f.write(f"{username}:{hashed_password}:{points}\n")

    def update_user_points(self, username, points):
        users = self.load_users()
        if username in users:
            users[username]['points'] = points
            self.update_users_file(users)

    def setup_initial_gui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.initial_frame = tk.Frame(self.root)
        self.initial_frame.pack(fill="both", expand=True)
        
        if self.background_image:
            background_label = tk.Label(self.initial_frame, image=self.background_image)
            background_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        tk.Label(self.initial_frame, text=self.texts[self.language]["bank_greeting"], font=("Arial", 20, "bold"), fg="white", bg=None, highlightbackground="black", highlightthickness=1).place(relx=0.5, rely=0.3, anchor="center")
        tk.Label(self.initial_frame, text=self.texts[self.language]["welcome"], font=("Arial", 16, "bold"), fg="white", bg=None, highlightbackground="black", highlightthickness=1).place(relx=0.5, rely=0.4, anchor="center")
        tk.Button(self.initial_frame, text=self.texts[self.language]["login"], command=self.setup_login_gui, font=("Arial", 12), bg="#FF00FF", fg="white", relief="flat", padx=20, pady=10).place(relx=0.5, rely=0.5, anchor="center")
        tk.Button(self.initial_frame, text=self.texts[self.language]["register"], command=self.setup_register_gui, font=("Arial", 12), bg="#00FF00", fg="white", relief="flat", padx=20, pady=10).place(relx=0.5, rely=0.6, anchor="center")

    def setup_login_gui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(fill="both", expand=True)
        
        if self.background_image:
            background_label = tk.Label(self.login_frame, image=self.background_image)
            background_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        tk.Label(self.login_frame, text=self.texts[self.language]["username"], font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1).place(relx=0.4, rely=0.3, anchor="e")
        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12), width=25)
        self.username_entry.place(relx=0.6, rely=0.3, anchor="center")
        
        tk.Label(self.login_frame, text=self.texts[self.language]["password"], font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1).place(relx=0.4, rely=0.4, anchor="e")
        self.password_entry = tk.Entry(self.login_frame, show="*", font=("Arial", 12), width=25)
        self.password_entry.place(relx=0.6, rely=0.4, anchor="center")
        
        tk.Button(self.login_frame, text=self.texts[self.language]["login"], command=self.authenticate, font=("Arial", 12), bg="#FF00FF", fg="white", relief="flat", padx=20, pady=10).place(relx=0.5, rely=0.5, anchor="center")
        tk.Button(self.login_frame, text=self.texts[self.language]["back_to_register"], command=self.setup_initial_gui, font=("Arial", 12), bg="#FFFF00", fg="black", relief="flat", padx=20, pady=10).place(relx=0.5, rely=0.6, anchor="center")
        
        self.login_feedback = tk.Label(self.login_frame, text="", font=("Arial", 12), fg="#FF0000", bg=None)
        self.login_feedback.place(relx=0.5, rely=0.7, anchor="center")

    def setup_register_gui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.register_frame = tk.Frame(self.root)
        self.register_frame.pack(fill="both", expand=True)
        
        if self.background_image:
            background_label = tk.Label(self.register_frame, image=self.background_image)
            background_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        tk.Label(self.register_frame, text=self.texts[self.language]["new_username"], font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1).place(relx=0.4, rely=0.3, anchor="e")
        self.new_username_entry = tk.Entry(self.register_frame, font=("Arial", 12), width=25)
        self.new_username_entry.place(relx=0.6, rely=0.3, anchor="center")
        
        tk.Label(self.register_frame, text=self.texts[self.language]["new_password"], font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1).place(relx=0.4, rely=0.4, anchor="e")
        self.new_password_entry = tk.Entry(self.register_frame, show="*", font=("Arial", 12), width=25)
        self.new_password_entry.place(relx=0.6, rely=0.4, anchor="center")
        
        tk.Label(self.register_frame, text=self.texts[self.language]["confirm_password"], font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1).place(relx=0.4, rely=0.5, anchor="e")
        self.confirm_password_entry = tk.Entry(self.register_frame, show="*", font=("Arial", 12), width=25)
        self.confirm_password_entry.place(relx=0.6, rely=0.5, anchor="center")
        
        tk.Button(self.register_frame, text=self.texts[self.language]["register"], command=self.register, font=("Arial", 12), bg="#00FF00", fg="white", relief="flat", padx=20, pady=10).place(relx=0.5, rely=0.6, anchor="center")
        tk.Button(self.register_frame, text=self.texts[self.language]["back_to_login"], command=self.setup_initial_gui, font=("Arial", 12), bg="#FFFF00", fg="black", relief="flat", padx=20, pady=10).place(relx=0.5, rely=0.7, anchor="center")
        
        self.register_feedback = tk.Label(self.register_frame, text="", font=("Arial", 12), fg="#FF0000", bg=None)
        self.register_feedback.place(relx=0.5, rely=0.8, anchor="center")

    def redeem_points(self):
        if self.score < 100:
            self.feedback_label.config(text=self.texts[self.language]["insufficient_points"], fg="#FF0000")
            return
        
        points_to_redeem = 100
        vnd_added = 10000
        self.score -= points_to_redeem
        self.update_user_points(self.current_user, self.score)
        self.feedback_label.config(text=self.texts[self.language]["redeem_success"].format(points_to_redeem, vnd_added), fg="#00FF00")
        self.setup_game_gui()
        self.update_transaction_display()

    def register(self):
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not username or not password:
            self.register_feedback.config(text=self.texts[self.language]["empty_fields"])
            return
        if password != confirm_password:
            self.register_feedback.config(text=self.texts[self.language]["password_mismatch"])
            return
        
        users = self.load_users()
        if username in users:
            self.register_feedback.config(text=self.texts[self.language]["username_exists"])
            return
        
        hashed_password = SHA512.new(password.encode()).hexdigest()
        self.save_user(username, hashed_password)
        self.register_feedback.config(text=self.texts[self.language]["register_success"], fg="#00FF00")
        self.root.after(1000, self.setup_login_gui)

    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        hashed_password = SHA512.new(password.encode()).hexdigest()
        
        users = self.load_users()
        if username in users and users[username]['password'] == hashed_password:
            self.current_user = username
            self.score = users[username]['points']
            self.login_frame.destroy()
            self.setup_game_gui()
            self.generate_transaction()
            self.update_transaction_display()
        else:
            self.login_feedback.config(text=self.texts[self.language]["invalid_login"])

    def setup_game_gui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.game_frame = tk.Frame(self.root)
        self.game_frame.pack(fill="both", expand=True)
        
        if self.background_image:
            background_label = tk.Label(self.game_frame, image=self.background_image)
            background_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        lang_frame = tk.Frame(self.game_frame, bg=None)
        lang_frame.place(relx=0.5, rely=0.05, anchor="n")
        tk.Label(lang_frame, text=self.texts[self.language]["language_label"], font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1).pack(side=tk.LEFT)
        self.lang_combo = ttk.Combobox(lang_frame, values=["Tiếng Việt", "English"], state="readonly", font=("Arial", 12))
        self.lang_combo.set("Tiếng Việt" if self.language == "vi" else "English")
        self.lang_combo.bind("<<ComboboxSelected>>", self.change_language)
        self.lang_combo.pack(side=tk.LEFT, padx=5)
        
        self.score_label = tk.Label(self.game_frame, text=self.texts[self.language]["score"].format(self.score), font=("Arial", 14, "bold"), fg="#FF00FF", bg=None, highlightbackground="black", highlightthickness=1)
        self.score_label.place(relx=0.5, rely=0.15, anchor="center")

        self.account_label = tk.Label(self.game_frame, text="", font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1)
        self.account_label.place(relx=0.5, rely=0.25, anchor="center")
        self.amount_label = tk.Label(self.game_frame, text="", font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1)
        self.amount_label.place(relx=0.5, rely=0.30, anchor="center")
        self.timestamp_label = tk.Label(self.game_frame, text="", font=("Arial", 12, "bold"), fg="#00FFFF", bg=None, highlightbackground="black", highlightthickness=1)
        self.timestamp_label.place(relx=0.5, rely=0.35, anchor="center")

        self.button_frame = tk.Frame(self.game_frame, bg=None)
        self.button_frame.place(relx=0.5, rely=0.45, anchor="center")
        tk.Button(self.button_frame, text=self.texts[self.language]["encrypt_button"], command=self.encrypt_aes, font=("Arial", 12), bg="#FF00FF", fg="white", relief="flat", padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text=self.texts[self.language]["verify_button"], command=self.verify_rsa, font=("Arial", 12), bg="#FF00FF", fg="white", relief="flat", padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text=self.texts[self.language]["check_sha_button"], command=self.check_sha, font=("Arial", 12), bg="#FF00FF", fg="white", relief="flat", padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        tk.Button(self.button_frame, text=self.texts[self.language]["redeem_button"], command=self.redeem_points, font=("Arial", 12), bg="#00FF00", fg="white", relief="flat", padx=20, pady=10).pack(side=tk.LEFT, padx=5)

        self.result_text = tk.Text(self.game_frame, height=4, width=50, font=("Arial", 12))
        self.result_text.place(relx=0.5, rely=0.65, anchor="center")
        self.feedback_label = tk.Label(self.game_frame, text="", font=("Arial", 12), fg="#FF0000", bg=None)
        self.feedback_label.place(relx=0.5, rely=0.85, anchor="center")

    def change_language(self, event):
        selected = self.lang_combo.get()
        self.language = "vi" if selected == "Tiếng Việt" else "en"
        self.setup_game_gui()
        self.update_transaction_display()

    def generate_transaction(self):
        amounts = [100000, 500000, 1000000, 5000000]
        amount = random.choice(amounts)
        self.current_transaction = {
            "account": self.current_user,
            "amount": amount,
            "timestamp": str(amount * 1000),
            "tampered": random.random() > 0.7
        }
        data = json.dumps({
            "account": self.current_transaction["account"],
            "amount": self.current_transaction["amount"],
            "timestamp": self.current_transaction["timestamp"]
        }).encode()
        self.current_transaction["hash"] = SHA512.new(data).hexdigest()
        self.aes_encrypted = False
        self.rsa_verified = False
        self.sha_checked = False

    def update_transaction_display(self):
        self.account_label.config(text=self.texts[self.language]["account"].format(self.current_transaction["account"]))
        self.amount_label.config(text=self.texts[self.language]["amount"].format(self.current_transaction["amount"]))
        self.timestamp_label.config(text=self.texts[self.language]["timestamp"].format(self.current_transaction["timestamp"]))
        self.result_text.delete(1.0, tk.END)
        self.feedback_label.config(text="")
        self.score_label.config(text=self.texts[self.language]["score"].format(self.score))

    def encrypt_aes(self):
        if self.aes_encrypted:
            self.feedback_label.config(text=self.texts[self.language]["already_encrypted"], fg="#FF0000")
            return
        key = b'Sixteen byte key'
        cipher = AES.new(key, AES.MODE_EAX)
        data = json.dumps({
            "account": self.current_transaction["account"],
            "amount": self.current_transaction["amount"]
        }).encode()
        ciphertext, tag = cipher.encrypt_and_digest(data)
        encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
        self.aes_encrypted = True
        self.result_text.insert(tk.END, f"AES Encryption: {encrypted[:20]}...\n")
        self.feedback_label.config(text=self.texts[self.language]["encrypt_success"], fg="#00FF00")
        self.check_completion()

    def verify_rsa(self):
        if not self.aes_encrypted:
            self.feedback_label.config(text=self.texts[self.language]["encrypt_first"], fg="#FF0000")
            return
        if self.rsa_verified:
            self.feedback_label.config(text=self.texts[self.language]["already_verified"], fg="#FF0000")
            return
        data = (self.current_transaction["account"] + str(self.current_transaction["amount"])).encode()
        hash_obj = SHA512.new(data)
        try:
            signature = self.signer.sign(hash_obj)
            self.verifier.verify(hash_obj, signature)
            self.rsa_verified = True
            self.result_text.insert(tk.END, "RSA Verification: Valid\n")
            self.feedback_label.config(text=self.texts[self.language]["rsa_success"], fg="#00FF00")
        except ValueError:
            self.result_text.insert(tk.END, "RSA Verification: Invalid\n")
            self.feedback_label.config(text=self.texts[self.language]["rsa_failed"], fg="#FF0000")
        self.check_completion()

    def check_sha(self):
        if not self.rsa_verified:
            self.feedback_label.config(text=self.texts[self.language]["encrypt_first"], fg="#FF0000")
            return
        if self.sha_checked:
            self.feedback_label.config(text=self.texts[self.language]["already_checked"], fg="#FF0000")
            return
        current_data = {
            "account": self.current_transaction["account"],
            "amount": self.current_transaction["amount"] + (1 if self.current_transaction["tampered"] else 0),
            "timestamp": str((self.current_transaction["amount"] + (1 if self.current_transaction["tampered"] else 0)) * 1000)
        }
        current_hash = SHA512.new(json.dumps(current_data).encode()).hexdigest()
        is_intact = current_hash == self.current_transaction["hash"]
        self.sha_checked = True
        self.result_text.insert(tk.END, f"SHA Integrity: {'Intact' if is_intact else 'Tampered'}\n")
        self.feedback_label.config(text=self.texts[self.language]["sha_intact"] if is_intact else self.texts[self.language]["sha_tampered"], fg="#00FF00" if is_intact else "#FF0000")
        self.check_completion()

    def check_completion(self):
        if self.aes_encrypted and self.rsa_verified and self.sha_checked:
            is_success = not self.current_transaction["tampered"]
            points_earned = 100 if is_success else -50
            self.score = max(0, self.score + points_earned)
            self.transactions_processed += 1
            self.feedback_label.config(text=self.texts[self.language]["transaction_success"] if is_success else self.texts[self.language]["transaction_failed"], fg="#00FF00" if is_success else "#FF0000")
            
            self.update_user_points(self.current_user, self.score)
            self.root.after(1000, self.next_transaction)

    def next_transaction(self):
        self.generate_transaction()
        self.update_transaction_display()

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("800x600")
    app = BankEncryptionGame(root)
    root.mainloop()