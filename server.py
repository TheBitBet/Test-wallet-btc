import os, uuid, logging, hashlib, httpx
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, APIRouter, HTTPException
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from cryptography.fernet import Fernet
from bit import PrivateKeyTestnet

# --- SETUP & SECURITY ---
load_dotenv(Path(__file__).parent / '.env')
MASTER_KEY = os.getenv("ENCRYPTION_KEY", "your-fallback-key-for-dev-only").encode()
cipher_suite = Fernet(MASTER_KEY)

def encrypt_key(plain_text: str) -> str:
    return cipher_suite.encrypt(plain_text.encode()).decode()

def decrypt_key(encrypted_text: str) -> str:
    return cipher_suite.decrypt(encrypted_text.encode()).decode()

app = FastAPI(title="Bitcoin Testnet Wallet V2")
api_router = APIRouter(prefix="/api")

# MongoDB
client = AsyncIOMotorClient(os.environ['MONGO_URL'])
db = client[os.environ['DB_NAME']]

# --- MODELS ---
class WalletCreate(BaseModel):
    name: str

class TransactionCreate(BaseModel):
    wallet_id: str  # Send from this internal wallet
    to_address: str
    amount: float

# --- LOGIC ---
@api_router.post("/wallet/create")
async def create_wallet(data: WalletCreate):
    # bit handles key generation and WIF internally
    k = PrivateKeyTestnet()
    
    wallet_doc = {
        "_id": str(uuid.uuid4()),
        "name": data.name,
        "address": k.address,
        "encrypted_wif": encrypt_key(k.to_wif()), # Store encrypted!
        "created_at": datetime.utcnow()
    }
    await db.wallets.insert_one(wallet_doc)
    return {"id": wallet_doc["_id"], "address": k.address}

@api_router.get("/wallet/{wallet_id}/balance")
async def get_balance(wallet_id: str):
    wallet = await db.wallets.find_one({"_id": wallet_id})
    if not wallet: raise HTTPException(404, "Wallet not found")
    
    # Use bit to fetch live balance (Satoshi to BTC)
    k = PrivateKeyTestnet(decrypt_key(wallet["encrypted_wif"]))
    return {"address": wallet["address"], "balance": k.get_balance('btc')}

@api_router.post("/transaction/send")
async def send_btc(tx_data: TransactionCreate):
    wallet = await db.wallets.find_one({"_id": tx_data.wallet_id})
    if not wallet: raise HTTPException(404, "Wallet not found")

    try:
        # 1. Decrypt WIF
        wif = decrypt_key(wallet["encrypted_wif"])
        key = PrivateKeyTestnet(wif)
        
        # 2. bit automatically: 
        # - Fetches UTXOs
        # - Calculates network fees
        # - Signs and Broadcasts
        tx_hash = key.send([(tx_data.to_address, tx_data.amount, 'btc')])
        
        return {"tx_id": tx_hash, "status": "sent"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Transaction failed: {str(e)}")

@api_router.get("/wallets")
async def list_wallets():
    return await db.wallets.find({}, {"encrypted_wif": 0}).to_list(length=100)

app.include_router(api_router)
