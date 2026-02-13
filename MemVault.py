import os, json, uuid, base64, tkinter as tk
from tkinter import messagebox, ttk
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from bit import PrivateKeyTestnet

# --- SECURITY CONFIG ---
DATA_FILE = "wallet_data.json"
ITERATIONS = 600000 

class MemVaultPro:
    def __init__(self, root):
        self.root = root
        self.root.title("MemVault Testnet ")
        self.root.geometry("480x720")
        
        self.cipher = None
        self.wallets = []
        self.salt = self._get_salt()
        self.show_login_screen()

    def _get_salt(self):
        if Path("salt.bin").exists(): return open("salt.bin", "rb").read()
        salt = os.urandom(16)
        with open("salt.bin", "wb") as f: f.write(salt)
        return salt

    def derive_key(self, password):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.salt, iterations=ITERATIONS)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher = Fernet(key)

    def show_login_screen(self):
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(expand=True)
        tk.Label(self.login_frame, text="🔒 MemVault Login", font=("Arial", 16, "bold")).pack(pady=10)
        self.pass_entry = tk.Entry(self.login_frame, show="*", width=30, justify='center')
        self.pass_entry.pack(pady=5)
        self.pass_entry.focus()
        tk.Button(self.login_frame, text="Unlock Wallets", command=self.attempt_login, bg="#007bff", fg="white", width=20).pack(pady=20)

    def attempt_login(self):
        password = self.pass_entry.get()
        if not password: return
        self.derive_key(password)
        if Path(DATA_FILE).exists():
            try:
                with open(DATA_FILE, "r") as f: self.wallets = json.load(f)
                if self.wallets: self.cipher.decrypt(self.wallets[0]['wif_enc'].encode())
            except InvalidToken:
                messagebox.showerror("Security Error", "Wrong Password!")
                return
        self.login_frame.destroy()
        self.show_main_wallet()

    def show_main_wallet(self):
        self.main_frame = tk.Frame(self.root, padx=20, pady=20)
        self.main_frame.pack(fill="both", expand=True)

        # 1. WALLET SELECTION
        tk.Label(self.main_frame, text="Select Wallet:", font=("Arial", 9, "bold")).pack(anchor="w")
        self.wallet_box = ttk.Combobox(self.main_frame, state="readonly")
        self.wallet_box.pack(fill="x", pady=(0, 10))
        self.wallet_box.bind("<<ComboboxSelected>>", self.on_wallet_change)

        # 2. ADDRESS DISPLAY (Now with a clearer placeholder)
        addr_frame = tk.LabelFrame(self.main_frame, text="Current Wallet Address", padx=10, pady=10)
        addr_frame.pack(fill="x", pady=5)
        
        self.addr_var = tk.StringVar(value="PLEASE CREATE OR SELECT A WALLET")
        self.addr_label = tk.Label(addr_frame, textvariable=self.addr_var, font=("Courier", 10), fg="#333", wraplength=350)
        self.addr_label.pack(side="left", expand=True)
        
        tk.Button(addr_frame, text="📋 Copy", command=self.copy_address).pack(side="right")

        # 3. BALANCE
        self.balance_var = tk.StringVar(value="Balance: --- BTC")
        tk.Label(self.main_frame, textvariable=self.balance_var, font=("Arial", 18, "bold"), fg="#28a745").pack(pady=15)

        # 4. TRANSACTIONS
        tk.Label(self.main_frame, text="Recent Transactions:", font=("Arial", 9, "bold")).pack(anchor="w")
        self.tx_list = tk.Listbox(self.main_frame, height=5, font=("Courier", 9), bg="#f9f9f9")
        self.tx_list.pack(fill="x", pady=5)

        # 5. ACTIONS
        btn_frame = tk.Frame(self.main_frame)
        btn_frame.pack(fill="x", pady=10)
        tk.Button(btn_frame, text="+ Create New", command=self.create_wallet, bg="#6c757d", fg="white").pack(side="left", expand=True, fill="x", padx=2)
        tk.Button(btn_frame, text="↻ Refresh", command=self.refresh_data, bg="#007bff", fg="white").pack(side="left", expand=True, fill="x", padx=2)

        # 6. SEND SECTION
        send_f = tk.LabelFrame(self.main_frame, text="Quick Send", padx=10, pady=10)
        send_f.pack(fill="x", pady=10)
        tk.Label(send_f, text="Recipient Address:").pack(anchor="w")
        self.to_addr = tk.Entry(send_f); self.to_addr.pack(fill="x", pady=2)
        tk.Label(send_f, text="Amount (BTC):").pack(anchor="w")
        self.amount = tk.Entry(send_f); self.amount.pack(fill="x", pady=2)
        tk.Button(send_f, text="SEND TESTNET BTC", bg="#f39c12", fg="white", font=("bold"), command=self.send_tx).pack(pady=10, fill="x")

        # AUTO-LOAD DATA ON STARTUP
        if self.wallets:
            self.update_dropdown()

    # --- CORE LOGIC ---
    def update_dropdown(self):
        addresses = [w['address'] for w in self.wallets]
        self.wallet_box['values'] = addresses
        if addresses:
            self.wallet_box.current(0)
            # CRITICAL: Force the text into the combobox and trigger update
            self.wallet_box.set(addresses[0]) 
            self.on_wallet_change()

    def copy_address(self):
        addr = self.addr_var.get()
        if len(addr) > 25: # Minimal BTC address length check
            self.root.clipboard_clear()
            self.root.clipboard_append(addr)
            messagebox.showinfo("Copied", "Address copied to clipboard!")
        else:
            messagebox.showwarning("Empty", "No valid address to copy yet.")

    def on_wallet_change(self, event=None):
        idx = self.wallet_box.current()
        if idx >= 0:
            selected_addr = self.wallets[idx]['address']
            self.addr_var.set(selected_addr)
            self.refresh_data()

    def create_wallet(self):
        k = PrivateKeyTestnet()
        self.wallets.append({
            "address": k.address,
            "wif_enc": self.cipher.encrypt(k.to_wif().encode()).decode()
        })
        self.save_data()
        self.update_dropdown()
        # Ensure we select the absolute last one added
        self.wallet_box.current(len(self.wallets)-1)
        self.on_wallet_change()

    def refresh_data(self):
        idx = self.wallet_box.current()
        if idx < 0: return
        self.balance_var.set("Syncing...")
        self.tx_list.delete(0, tk.END)
        self.root.update_idletasks()
        try:
            wif = self.cipher.decrypt(self.wallets[idx]['wif_enc'].encode()).decode()
            key = PrivateKeyTestnet(wif)
            self.balance_var.set(f"Balance: {key.get_balance('btc')} BTC")
            txs = key.get_transactions()
            if not txs:
                self.tx_list.insert(tk.END, " No transactions found.")
            else:
                for tx in txs[:5]: self.tx_list.insert(tk.END, f" TX: {tx[:25]}...")
        except Exception as e:
            messagebox.showerror("Sync Failed", f"Network error or bad key: {e}")

    def send_tx(self):
        idx = self.wallet_box.current()
        if idx < 0: return
        try:
            wif = self.cipher.decrypt(self.wallets[idx]['wif_enc'].encode()).decode()
            key = PrivateKeyTestnet(wif)
            tx_hash = key.send([(self.to_addr.get(), float(self.amount.get()), 'btc')])
            messagebox.showinfo("Success", f"Sent!\nTXID: {tx_hash}")
            self.refresh_data()
        except Exception as e:
            messagebox.showerror("TX Error", str(e))

    def save_data(self):
        with open(DATA_FILE, "w") as f: json.dump(self.wallets, f, indent=4)

if __name__ == "__main__":
    root = tk.Tk()
    app = MemVaultPro(root)
    root.mainloop()