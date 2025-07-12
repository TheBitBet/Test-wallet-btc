from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime
import hashlib
import ecdsa
import base58
import bech32
import secrets
import requests
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="Bitcoin Testnet Wallet API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Bitcoin Testnet Configuration
TESTNET_PRIVATE_KEY_PREFIX = 0xef
TESTNET_ADDRESS_PREFIX = 0x6f
TESTNET_P2SH_PREFIX = 0xc4

# Pydantic Models
class WalletCreate(BaseModel):
    name: str

class WalletResponse(BaseModel):
    id: str
    name: str
    address: str
    balance: float
    private_key: Optional[str] = None

class TransactionCreate(BaseModel):
    from_address: str
    to_address: str
    amount: float
    private_key: str

class TransactionResponse(BaseModel):
    tx_id: str
    status: str
    message: Optional[str] = None

class BalanceResponse(BaseModel):
    balance: float
    address: str

# Bitcoin Wallet Service
class BitcoinTestnetWallet:
    def __init__(self):
        self.network = 'testnet'
    
    def generate_wallet(self, name: str):
        """Generate new Bitcoin testnet wallet"""
        try:
            # Generate random private key (32 bytes)
            private_key_bytes = secrets.token_bytes(32)
            private_key_hex = private_key_bytes.hex()
            
            # Create ECDSA signing key
            signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
            verifying_key = signing_key.verifying_key
            
            # Get uncompressed public key
            public_key_bytes = b'\x04' + verifying_key.to_string()
            
            # Create Bitcoin testnet address
            address = self._create_testnet_address(public_key_bytes)
            
            # Create WIF (Wallet Import Format) for testnet
            wif = self._private_key_to_wif(private_key_bytes)
            
            return {
                "name": name,
                "address": address,
                "private_key": private_key_hex,
                "wif": wif,
                "public_key": public_key_bytes.hex()
            }
        except Exception as e:
            raise Exception(f"Failed to generate wallet: {str(e)}")
    
    def _create_testnet_address(self, public_key_bytes):
        """Create Bitcoin testnet address from public key"""
        # SHA256 hash of public key
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        # RIPEMD160 hash of SHA256 hash
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        
        # Add testnet prefix
        versioned_payload = bytes([TESTNET_ADDRESS_PREFIX]) + ripemd160_hash
        
        # Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        
        # Create final address
        address_bytes = versioned_payload + checksum
        address = base58.b58encode(address_bytes).decode('utf-8')
        
        return address
    
    def _private_key_to_wif(self, private_key_bytes):
        """Convert private key to WIF format for testnet"""
        # Add testnet prefix
        extended_key = bytes([TESTNET_PRIVATE_KEY_PREFIX]) + private_key_bytes
        
        # Calculate checksum
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        
        # Create WIF
        wif_bytes = extended_key + checksum
        wif = base58.b58encode(wif_bytes).decode('utf-8')
        
        return wif
    
    async def get_balance(self, address: str):
        """Get balance for testnet address using BlockCypher API"""
        try:
            url = f"https://api.blockcypher.com/v1/btc/test3/addrs/{address}/balance"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                balance_satoshi = data.get('balance', 0)
                balance_btc = balance_satoshi / 100000000  # Convert to BTC
                return balance_btc
            else:
                logging.warning(f"Failed to fetch balance for {address}: {response.status_code}")
                return 0.0
        except Exception as e:
            logging.error(f"Error fetching balance: {str(e)}")
            return 0.0
    
    def validate_address(self, address: str):
        """Validate Bitcoin testnet address"""
        try:
            if not address or len(address) < 26 or len(address) > 35:
                return False
            
            # Decode base58
            decoded = base58.b58decode(address)
            
            if len(decoded) != 25:
                return False
            
            # Check prefix (testnet addresses start with m, n, or 2)
            prefix = decoded[0]
            if prefix not in [TESTNET_ADDRESS_PREFIX, TESTNET_P2SH_PREFIX]:
                return False
            
            # Verify checksum
            payload = decoded[:-4]
            checksum = decoded[-4:]
            calculated_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            
            return checksum == calculated_checksum
        except Exception:
            return False

# Initialize wallet service
wallet_service = BitcoinTestnetWallet()

# API Endpoints
@api_router.get("/")
async def root():
    return {"message": "Bitcoin Testnet Wallet API", "version": "1.0.0"}

@api_router.post("/wallet/create", response_model=WalletResponse)
async def create_wallet(wallet_data: WalletCreate):
    """Create new Bitcoin testnet wallet"""
    try:
        # Generate wallet
        wallet_info = wallet_service.generate_wallet(wallet_data.name)
        
        # Get initial balance
        balance = await wallet_service.get_balance(wallet_info["address"])
        
        # Store in database
        wallet_doc = {
            "_id": str(uuid.uuid4()),
            "name": wallet_info["name"],
            "address": wallet_info["address"],
            "private_key": wallet_info["private_key"],
            "wif": wallet_info["wif"],
            "public_key": wallet_info["public_key"],
            "balance": balance,
            "created_at": datetime.utcnow()
        }
        
        await db.wallets.insert_one(wallet_doc)
        
        return WalletResponse(
            id=wallet_doc["_id"],
            name=wallet_doc["name"],
            address=wallet_doc["address"],
            balance=balance,
            private_key=wallet_info["private_key"]  # Include for demo purposes
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/wallet/{wallet_id}/balance", response_model=BalanceResponse)
async def get_wallet_balance(wallet_id: str):
    """Get current balance for wallet"""
    try:
        wallet = await db.wallets.find_one({"_id": wallet_id})
        if not wallet:
            raise HTTPException(status_code=404, detail="Wallet not found")
        
        # Get live balance
        balance = await wallet_service.get_balance(wallet["address"])
        
        # Update stored balance
        await db.wallets.update_one(
            {"_id": wallet_id},
            {"$set": {"balance": balance, "updated_at": datetime.utcnow()}}
        )
        
        return BalanceResponse(balance=balance, address=wallet["address"])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/transaction/send", response_model=TransactionResponse)
async def send_transaction(tx_data: TransactionCreate):
    """Send Bitcoin testnet transaction (placeholder - actual implementation needs more work)"""
    try:
        # Validate addresses
        if not wallet_service.validate_address(tx_data.to_address):
            raise HTTPException(status_code=400, detail="Invalid recipient address")
        
        # For demo purposes, we'll simulate a transaction
        # In a real implementation, you'd need to:
        # 1. Get UTXOs for the from_address
        # 2. Create transaction inputs and outputs
        # 3. Sign the transaction
        # 4. Broadcast to the network
        
        # Simulate transaction ID
        tx_id = hashlib.sha256(
            f"{tx_data.from_address}{tx_data.to_address}{tx_data.amount}{datetime.utcnow()}".encode()
        ).hexdigest()
        
        # Store transaction record
        tx_doc = {
            "_id": str(uuid.uuid4()),
            "tx_hash": tx_id,
            "from_address": tx_data.from_address,
            "to_address": tx_data.to_address,
            "amount": tx_data.amount,
            "status": "simulated",  # In real implementation: "pending"
            "created_at": datetime.utcnow()
        }
        
        await db.transactions.insert_one(tx_doc)
        
        return TransactionResponse(
            tx_id=tx_id, 
            status="simulated",
            message="Transaction simulated - real broadcasting requires additional UTXO handling"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/wallets")
async def list_wallets():
    """List all wallets"""
    wallets = []
    async for wallet in db.wallets.find({}, {"private_key": 0, "wif": 0}):  # Exclude sensitive data
        wallets.append(wallet)
    return wallets

@api_router.get("/transaction/{tx_id}/status")
async def get_transaction_status(tx_id: str):
    """Get transaction status"""
    tx = await db.transactions.find_one({"tx_hash": tx_id})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return {"tx_id": tx_id, "status": tx["status"], "created_at": tx["created_at"]}

@api_router.get("/faucet-info")
async def get_faucet_info():
    """Get testnet faucet information"""
    return {
        "message": "Use these testnet faucets to fund your wallets",
        "faucets": [
            {
                "name": "Bitcoin Testnet Faucet",
                "url": "https://testnet-faucet.com/btc-testnet/",
                "description": "Free testnet bitcoins"
            },
            {
                "name": "BlockCypher Testnet Faucet", 
                "url": "https://live.blockcypher.com/btc-testnet/faucet/",
                "description": "Another reliable testnet faucet"
            }
        ]
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
