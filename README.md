# ⚠️⚠️⚠️ Security Warning ⚠️⚠️⚠️ #

MemVault is for Bitcoin Testnet use only. 
This wallet is in a beta state, no guarantees whatsoever of any kind. Use at your own risk.
This software has not been audited for fund storage. 
Whatever the wallet, always keep a backup of your password: if you lose it, the data are mathematically unrecoverable.

# MemVault-btc-testnet
MemVault is a lightweight, Bitcoin Testnet wallet designed with **Zero-Knowledge security philosophy**. MemVault derives your encryption key mathematically from your password every time you log in.

When the app is closed, the key to your vault ceases to exist in your system's memory.

# Key Features:
**Zero-Knowledge Architecture**: Encryption keys are derived using PBKDF2 with 600,000 iterations and a unique local salt.
**Serverless & Private**: No backend, no API, no complexity. All data is managed locally in an encrypted file.
**UTXO Management**: Powered by the bit library to handle real Testnet transactions, fee estimation, and UTXO fetching.
**Lightweight GUI**: A clean, native Tkinter interface for address management and transaction broadcasting.
**Secure Storage**: use AES-128 encryption.

# Installation
Clone the repository:
 -- cd MemVault
Install dependencies:
 --pip install bit cryptography python-dotenv
Run the application:
 --python memvault.py

# Usage
1) **First Run**: Enter a strong master password. This will initialize your salt.bin and create your local vault.
2) **Create Wallet**: Click "+ Create New" to generate a new Testnet address.
3) **Fund it**: Copy your address and use a Testnet Faucet to receive some coins.
4) **Sync**: Use the "Sync" button to update your balance and view recent transaction history.

