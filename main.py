from fastapi import FastAPI, Request, Query, BackgroundTasks, HTTPException, UploadFile, File, Depends, Header, Form
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from midtransclient import Snap
import httpx
from selectolax.parser import HTMLParser
from bs4 import BeautifulSoup
import yt_dlp
import os
import uuid
import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, unquote, urlencode
from youtube_search import YoutubeSearch
from Crypto.Cipher import AES
from base64 import b64decode
import io
import logging
from typing import Optional
import subprocess
import math
import base64
import requests
from collections import defaultdict
import json
import psutil
import platform
import time
import random
from websockets.client import connect
from playwright.async_api import async_playwright
import re
import string 
import pysrt
import cpuinfo
import socket
import qrcode
from typing import Literal
import aiohttp
from rembg import remove
from PIL import Image
import calendar
import numpy as np
import cv2
from collections import Counter
import pytz
import hashlib
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from pathlib import Path
import phonenumbers

# Security setup
SECRET_KEY = "your-secret-key-here-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# User folder setup
USER_DIR = Path("user")
USER_DIR.mkdir(exist_ok=True)

def get_user_file_path(username: str) -> Path:
    """Get the file path for a user's JSON file"""
    return USER_DIR / f"{username}.json"

def load_user_data(username: str) -> dict:
    """Load user data from JSON file"""
    user_file = get_user_file_path(username)
    if not user_file.exists():
        return None
    
    try:
        with open(user_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading user data for {username}: {e}")
        return None

def save_user_data(username: str, data: dict) -> bool:
    """Save user data to JSON file"""
    user_file = get_user_file_path(username)
    try:
        with open(user_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Error saving user data for {username}: {e}")
        return False

def create_user_structure(username: str, email: str, password_hash: str, phone_number: str) -> dict:
    """Create initial user data structure"""
    return {
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "phone_number": phone_number,
        "created_at": datetime.now().isoformat(),
        "is_active": True,
        "roles": [],
        "api_keys": [],
        "ip_addresses": []
    }

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    phone_number: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    email: str
    phone_number: str
    is_active: bool

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.PyJWTError:
        return None

def get_user_by_username(username: str):
    """Get user data by username from JSON file"""
    return load_user_data(username)

def create_user(user_data: UserCreate):
    """Create a new user with JSON file"""
    # Check if user already exists
    if get_user_by_username(user_data.username):
        return False
    
    # Check if email already exists
    for user_file in USER_DIR.glob("*.json"):
        try:
            with open(user_file, 'r', encoding='utf-8') as f:
                existing_user = json.load(f)
                if existing_user.get("email") == user_data.email:
                    return False
        except:
            continue
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    user_structure = create_user_structure(
        user_data.username, 
        user_data.email, 
        hashed_password, 
        user_data.phone_number
    )
    
    return save_user_data(user_data.username, user_structure)

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user:
        return False
    if not verify_password(password, user["password_hash"]):
        return False
    return user

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    username = verify_token(token)
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Modified role management functions
def get_user_role_by_username(username: str):
    """Get user role based on username from JSON file"""
    user_data = load_user_data(username)
    if not user_data:
        return {"role": "petualang_gratis", "expired": None}
    
    now = datetime.now()
    active_roles = []
    
    for role in user_data.get("roles", []):
        try:
            expired_time = datetime.fromisoformat(role["expired_at"])
            if expired_time > now:
                active_roles.append(role)
        except:
            continue
    
    if active_roles:
        # Return the most recent active role
        latest_role = max(active_roles, key=lambda x: x["expired_at"])
        return {
            "role": latest_role["role_name"],
            "expired": latest_role["expired_at"]
        }
    else:
        return {
            "role": "petualang_gratis",
            "expired": None
        }

def add_user_role(username: str, role_name: str, days: int):
    """Add role to user in JSON file"""
    user_data = load_user_data(username)
    if not user_data:
        return False
    
    now = datetime.now()
    expired_at = now + timedelta(days=days)
    
    new_role = {
        "role_name": role_name,
        "expired_at": expired_at.isoformat(),
        "created_at": now.isoformat()
    }
    
    user_data["roles"].append(new_role)
    return save_user_data(username, user_data)

def generate_api_key(username: str):
    """Generate new API key for user in JSON file"""
    user_data = load_user_data(username)
    if not user_data:
        return None
    
    # Deactivate old API keys
    for api_key in user_data.get("api_keys", []):
        api_key["is_active"] = False
    
    # Generate new API key
    api_key = f"api_{username}_{uuid.uuid4().hex[:16]}"
    new_api_key = {
        "api_key": api_key,
        "created_at": datetime.now().isoformat(),
        "is_active": True
    }
    
    user_data["api_keys"].append(new_api_key)
    save_user_data(username, user_data)
    
    return api_key

def get_user_by_api_key(api_key: str):
    """Get user by API key from JSON files"""
    for user_file in USER_DIR.glob("*.json"):
        try:
            with open(user_file, 'r', encoding='utf-8') as f:
                user_data = json.load(f)
                for key_data in user_data.get("api_keys", []):
                    if key_data.get("api_key") == api_key and key_data.get("is_active", False):
                        return user_data["username"]
        except:
            continue
    return None

def add_user_ip(username: str, ip_address: str):
    """Add IP address to user in JSON file"""
    user_data = load_user_data(username)
    if not user_data:
        return False
    
    # Check if IP already exists
    for ip_data in user_data.get("ip_addresses", []):
        if ip_data.get("ip_address") == ip_address:
            ip_data["is_active"] = True
            ip_data["updated_at"] = datetime.now().isoformat()
            return save_user_data(username, user_data)
    
    # Add new IP
    new_ip = {
        "ip_address": ip_address,
        "created_at": datetime.now().isoformat(),
        "is_active": True
    }
    
    user_data["ip_addresses"].append(new_ip)
    return save_user_data(username, user_data)

def get_user_by_ip(ip_address: str):
    """Get user by IP address from JSON files"""
    for user_file in USER_DIR.glob("*.json"):
        try:
            with open(user_file, 'r', encoding='utf-8') as f:
                user_data = json.load(f)
                for ip_data in user_data.get("ip_addresses", []):
                    if ip_data.get("ip_address") == ip_address and ip_data.get("is_active", False):
                        return user_data["username"]
        except:
            continue
    return None

async def api_key_header(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    
    return x_api_key
    

# WhatsApp notification function
async def kirim_invoice_ke_wa(wa: str, idpay: str, role: str, nominal: int, konten: str = None):
    if not konten:
        konten = (
            f"*INVOICE TOPUP ROLE*\n"
            f"ID Payment : `{idpay}`\n"
            f"Role       : `{role}`\n"
            f"Total Bayar: *Rp {nominal:,}*\n"
            f"QRIS       : https://ytdlpyton.nvlgroup.my.id/download/file/qris-{idpay}-{nominal}.png\n\n"
            f"Silakan bayar dalam 5 menit."
        )

    headers = {
        "Authorization": "h7krK6GBboEEZnZEWURb"
    }

    try:
        # Deteksi kode negara otomatis
        if wa.startswith("+"):
            parsed_number = phonenumbers.parse(wa, None)
        else:
            parsed_number = phonenumbers.parse(f"+{wa}", None)

        if parsed_number and phonenumbers.is_valid_number(parsed_number):
            country_code = parsed_number.country_code
        else:
            print(f"Nomor tidak valid: {wa}")
            return

        payload = {
            "target": wa,
            "message": konten,
            "countryCode": str(country_code)
        }

        print("Payload yang dikirim:", payload)

        async with httpx.AsyncClient() as client:
            response = await client.post("https://api.fonnte.com/send", json=payload, headers=headers)
            print("Response API:", response.text)
            response.raise_for_status()

    except phonenumbers.phonenumberutil.NumberParseException:
        print(f"Nomor WhatsApp tidak valid: {wa}")
    except httpx.HTTPStatusError as http_err:
        print(f"Error HTTP: {http_err.response.status_code} - {http_err.response.text}")
    except Exception as e:
        print(f"Gagal kirim WA: {e}")

YOUR_SERVER_KEY = "Mid-server-TC3DixU3cxpuWXdejEbBDuFh"
YOUR_CLIENT_KEY = "Mid-client-sduT_6RoVKBbuXtJ"

snap = Snap(
    is_production=True,
    server_key=YOUR_SERVER_KEY,
    client_key=YOUR_CLIENT_KEY
)


# Add missing directory definitions
PAYMENTS_DIR = "payments"
os.makedirs(PAYMENTS_DIR, exist_ok=True)

os.makedirs("tmp_brat", exist_ok=True)

SPOTIFY_CLIENT_ID = "e9176d2a48704b3089a9a58806d7c922"
SPOTIFY_CLIENT_SECRET = "241435c87ae746afa4c6b6f799e11fe1"

SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token"
SPOTIFY_API_URL = "https://api.spotify.com/v1"

server_start_time = time.time()
total_request_count = 0  # Counter global untuk semua request masuk

otp_store = {}
OTP_EXPIRE_MINUTES = 5  # waktu aktif OTP

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

request_counter = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 35
BANNED_IP_FILE = 'bannedip.json'

KEY_UNESA = "sada2024f"
AUTO_TOOL_AGENTS = [
    "wget", "curl", "html2zip", "python-requests", "axios", "postman", "fetch",
    "httpclient", "java-http-client", "okhttp", "go-http-client", "libwww-perl",
    "mechanize", "scrapy", "selenium", "phantomjs", "headless", "node-fetch",
    "WhatsApp/", "unknown"
]

total_request_count = 0
total_request_all_time = 0
latest_endpoint = None
endpoint_counter = Counter()
request_counter = defaultdict(list)

ALL_TIME_FILE = "total_requests.json"


    

def validate_key(key: str):
    if key != KEY_UNESA:
        raise HTTPException(status_code=401, detail="Kunci tidak valid")

# Load banned IPs from the JSON file
def load_banned_ips():
    try:
        with open(BANNED_IP_FILE, 'r') as f:
            banned_ips = json.load(f)
        return set(banned_ips)
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

# Save banned IPs to the JSON file
def save_banned_ips(banned_ips):
    with open(BANNED_IP_FILE, 'w') as f:
        json.dump(list(banned_ips), f)

# Block IP using UFW
def block_ip_with_ufw(ip: str):
    try:
        subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
        logger.warning(f"IP {ip} diblokir karena spam request.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Gagal memblokir IP {ip} dengan ufw: {e}")

OUTPUT_DIR = "output"
SPOTIFY_OUTPUT_DIR = "spotify_output"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(SPOTIFY_OUTPUT_DIR, exist_ok=True)


import hashlib

KEY_PATH = ".secretkey"  # file tersembunyi yang menyimpan key enkripsi

def load_or_create_secret_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = os.urandom(32)  # 256-bit random key
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

SECRET_KEY = load_or_create_secret_key()

def xor_encrypt(text: str, key: bytes = SECRET_KEY) -> str:
    key_str = hashlib.sha256(key).digest()
    xored = bytes([ord(c) ^ key_str[i % len(key_str)] for i, c in enumerate(text)])
    return base64.urlsafe_b64encode(xored).decode()

def xor_decrypt(encoded: str, key: bytes = SECRET_KEY) -> str:
    try:
        data = base64.urlsafe_b64decode(encoded.encode())
        key_str = hashlib.sha256(key).digest()
        decrypted = ''.join(chr(b ^ key_str[i % len(key_str)]) for i, b in enumerate(data))
        return decrypted
    except:
        return ""

    

# 🔀 Gunakan cookies random dari 3 file berbeda
COOKIES_LIST = [        
    "yt3.txt"
]
COOKIES_FILE = random.choice(COOKIES_LIST)
print(f"🔑 Menggunakan file cookies: {COOKIES_FILE}")

ADMIN_WA = "6285336580720"
ROLES_DIR = "roles"
os.makedirs(ROLES_DIR, exist_ok=True)

ROLE_FILES = {
    "pencariawal": "pencariawal.json",
    "penjelajahmuda": "penjelajahmuda.json",
    "masterpro": "masterpro.json",
    "strategiselit": "strategiselit.json",
    "visionerlegendaris": "visionerlegendaris.json",
    "penguasa": "penguasa.json",
    "liburanpackages": "events.json",
    "dirgahayuri": "dirgahayu.json"
}


# Pastikan semua file role tersedia
for filename in ROLE_FILES.values():
    path = os.path.join(ROLES_DIR, filename)
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump({}, f)

ROLE_LIMITS = {
    "petualang_gratis": {"resolution": 720, "max_size_mb": 100, "rpm": 10},
    "pencariawal": {"resolution": 720, "max_size_mb": 300, "rpm": 20},
    "penjelajahmuda": {"resolution": 1080, "max_size_mb": 600, "rpm": 30},
    "masterpro": {"resolution": 1440, "max_size_mb": 1000, "rpm": 45},
    "strategiselit": {"resolution": 2160, "max_size_mb": 1500, "rpm": 60},
    "visionerlegendaris": {"resolution": 2160, "max_size_mb": 2000, "rpm": 85},
    "penguasa": {"resolution": 4320, "max_size_mb": 4000, "rpm": 99999},
    "liburanpackages": {"resolution": 2160,"max_size_mb":1750, "rpm": 100},
    "dirgahayuri": {"resolution" : 2160,"max_size_mb":1945, "rpm": 80}
}

TOPUP_ROLE_PRICING = [
    (100,  "pencariawal1", 1),
    (300,  "pencariawal3", 3),
    (500,  "pencariawal7", 7),
    (1000, "pencariawal14", 14),
    (2000, "pencariawal30", 30),

    (250,  "penjelajahmuda1", 1),
    (700,  "penjelajahmuda3", 3),
    (1000, "penjelajahmuda7", 7),
    (1500, "penjelajahmuda14", 14),
    (3000, "penjelajahmuda30", 30),

    (500,  "masterpro1", 1),
    (1000, "masterpro3", 3),
    (2000, "masterpro7", 7),
    (3000, "masterpro14", 14),
    (5000, "masterpro30", 30),

    (750,  "strategiselit1", 1),
    (1500, "strategiselit3", 3),
    (2500, "strategiselit7", 7),
    (5000, "strategiselit14", 14),
    (7500, "strategiselit30", 30),

    (1000,  "visionerlegendaris1", 1),
    (2000,  "visionerlegendaris3", 3),
    (4000,  "visionerlegendaris7", 7),
    (6500,  "visionerlegendaris14", 14),
    (11000, "visionerlegendaris30", 30),

    (1500,  "penguasa1", 1),
    (3000,  "penguasa3", 3),
    (6000,  "penguasa7", 7),
    (10000, "penguasa14", 14),
    (15000, "penguasa30", 30),
    
    (850,  "liburanpackages1", 1),
    (2000,  "liburanpackages3", 3),
    (3500,  "liburanpackages7", 7),
    (5000, "liburanpackages10", 10),
    (6500, "liburanpackages14", 14),
    (8500, "liburanpackages21", 21),
    (10000, "liburanpackages30", 30),
    (15000, "liburanpackages45", 45),
    
    (800,  "dirgahayuri1", 1),
    (1600,  "dirgahayuri3", 3),
    (2400,  "dirgahayuri7", 7),
    (3200, "dirgahayuri10", 10),
    (4000, "dirgahayuri14", 14),
    (5600, "dirgahayuri21", 21),
    (6400, "dirgahayuri30", 30),
    (8000, "dirgahayuri45", 45),
]
from apscheduler.schedulers.background import BackgroundScheduler

def clean_expired_roles():
    now = datetime.now()
    total_deleted = 0

    for role_name, filename in ROLE_FILES.items():
        file_path = os.path.join(ROLES_DIR, filename)
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                continue

            to_delete = []
            for key, expired_str in data.items():
                try:
                    expired_time = datetime.fromisoformat(expired_str)
                    if expired_time < now:
                        to_delete.append(key)
                except Exception as e:
                    logger.warning(f"[CLEAN] Format waktu tidak valid: {expired_str}")

            if to_delete:
                for key in to_delete:
                    del data[key]
                    total_deleted += 1
                with open(file_path, "w") as f:
                    json.dump(data, f)
                logger.info(f"[CLEAN] Dihapus {len(to_delete)} item expired dari {role_name}")

        except Exception as e:
            logger.error(f"[CLEAN] Gagal memproses {file_path}: {e}")

    if total_deleted:
        logger.info(f"[CLEAN] Total role expired yang dihapus: {total_deleted}")
    else:
        logger.info("[CLEAN] Tidak ada role expired yang ditemukan.")
        

from itertools import combinations_with_replacement

def get_total_price_by_composed_days(role: str, target_days: int) -> int:
    options = sorted([p for p in TOPUP_ROLE_PRICING if p[1].startswith(role)], key=lambda x: -x[2])
    day_values = [p[2] for p in options]

    for count in range(1, 6):
        for combo in combinations_with_replacement(day_values, count):
            if sum(combo) == target_days:
                total_price = 0
                remaining = list(combo)
                for price, _, days in options:
                    while days in remaining:
                        total_price += price
                        remaining.remove(days)
                return total_price
    raise ValueError(f"Tidak bisa menyusun {target_days} hari dari kombinasi {role}")

def convert_days_from_total_price(total_price: int, role: str) -> int:
    options = sorted([p for p in TOPUP_ROLE_PRICING if p[1].startswith(role)], key=lambda x: -x[0])
    prices_days = [(p[0], p[2]) for p in options]
    max_days = 0
    def backtrack(index, current_price, current_days):
        nonlocal max_days
        if current_price > total_price or index >= len(prices_days):
            return
        max_days = max(max_days, current_days)
        price, days = prices_days[index]
        backtrack(index, current_price + price, current_days + days)
        backtrack(index + 1, current_price, current_days)
    backtrack(0, 0, 0)
    return max_days if max_days > 0 else 1


    
def load_role_data(role_name):
    path = os.path.join(ROLES_DIR, ROLE_FILES[role_name])
    try:
        with open(path) as f:
            data = json.load(f)
            # Ensure we return a dictionary, not a list
            if isinstance(data, list):
                logger.warning(f"Role data for {role_name} is a list, converting to empty dict")
                return {}
            return data
    except Exception as e:
        logger.error(f"Error loading role data for {role_name}: {e}")
        return {}

def is_ip_format(s):
    return s.count(".") == 3 and all(part.isdigit() and 0 <= int(part) <= 255 for part in s.split("."))

def get_user_role(ip_address=None, api_key=None):
    now = datetime.now()

    # Blokir jika API key berupa IP address
    if api_key and is_ip_format(api_key):
        logger.warning(f"Blocked attempt using IP as API key: {api_key}")
        return {"role": "petualang_gratis", "expired": None}

    # 1. Cek berdasarkan API Key dari user files
    if api_key:
        username = get_user_by_api_key(api_key)
        if username:
            role_info = get_user_role_by_username(username)
            if role_info["expired"]:
                return role_info

    # 2. Cek berdasarkan IP dari user files
    if ip_address:
        username = get_user_by_ip(ip_address)
        if username:
            role_info = get_user_role_by_username(username)
            if role_info["expired"]:
                return role_info

    # 3. Fallback ke sistem role lama (file JSON)
    if api_key:
        for role_name, file_name in ROLE_FILES.items():
            try:
                with open(os.path.join(ROLES_DIR, file_name), "r") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    continue
                if api_key in data:
                    expired_str = data[api_key]
                    try:
                        expired_time = datetime.fromisoformat(expired_str)
                        if expired_time > now:
                            return {"role": role_name, "expired": expired_str}
                    except:
                        logger.warning(f"Invalid expired format for API key in role {role_name}")
            except Exception as e:
                logger.error(f"Error reading {file_name}: {e}")

    if ip_address:
        for role_name, file_name in ROLE_FILES.items():
            try:
                with open(os.path.join(ROLES_DIR, file_name), "r") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    continue
                if ip_address in data:
                    expired_str = data[ip_address]
                    try:
                        expired_time = datetime.fromisoformat(expired_str)
                        if expired_time > now:
                            return {"role": role_name, "expired": expired_str}
                    except:
                        logger.warning(f"Invalid expired format for IP in role {role_name}")
            except Exception as e:
                logger.error(f"Error reading {file_name}: {e}")

    return {"role": "petualang_gratis", "expired": None}

app = FastAPI(
    title="YouTube dan Spotify Downloader API dengan User Authentication",
    description="API dengan sistem autentikasi berbasis username menggunakan file JSON",
    version="5.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
os.makedirs("output", exist_ok=True)
app.mount("/output", StaticFiles(directory="output"), name="output")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Authentication endpoints
@app.post("/auth/signup", summary="Daftar akun baru", tags=["Authentication"])
async def signup(user_data: UserCreate):
    # Validate input
    if len(user_data.username) < 3:
        raise HTTPException(status_code=400, detail="Username minimal 3 karakter")
    if len(user_data.password) < 6:
        raise HTTPException(status_code=400, detail="Password minimal 6 karakter")
    
    # Create user
    if create_user(user_data):
        return {"message": "Akun berhasil dibuat", "username": user_data.username}
    else:
        raise HTTPException(status_code=400, detail="Username atau email sudah digunakan")

@app.post("/auth/signin", summary="Login ke akun", tags=["Authentication"])
async def signin(user_data: UserLogin):
    user = authenticate_user(user_data.username, user_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Username atau password salah")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "email": user["email"],
            "phone_number": user["phone_number"]
        }
    }

@app.get("/auth/me", summary="Info user saat ini", tags=["Authentication"])
async def get_me(current_user: dict = Depends(get_current_user)):
    role_info = get_user_role_by_username(current_user["username"])
    
    return {
        "username": current_user["username"],
        "email": current_user["email"],
        "phone_number": current_user["phone_number"],
        "role": role_info["role"],
        "role_expired": role_info["expired"],
        "limits": ROLE_LIMITS.get(role_info["role"], ROLE_LIMITS["petualang_gratis"])
    }

# User dashboard endpoints
@app.get("/user/dashboard", summary="Dashboard pengguna", tags=["User Dashboard"])
async def user_dashboard(current_user: dict = Depends(get_current_user)):
    role_info = get_user_role_by_username(current_user["username"])
    
    # Get user's API keys and IPs from JSON file
    api_keys = []
    ips = []
    
    for api_key_data in current_user.get("api_keys", []):
        if api_key_data.get("is_active", False):
            api_keys.append({
                "api_key": api_key_data["api_key"],
                "created_at": api_key_data["created_at"]
            })
    
    for ip_data in current_user.get("ip_addresses", []):
        if ip_data.get("is_active", False):
            ips.append({
                "ip_address": ip_data["ip_address"],
                "created_at": ip_data["created_at"]
            })
    
    return {
        "user_info": {
            "username": current_user["username"],
            "email": current_user["email"],
            "phone_number": current_user["phone_number"]
        },
        "role_info": {
            "current_role": role_info["role"],
            "expired_at": role_info["expired"],
            "limits": ROLE_LIMITS.get(role_info["role"], ROLE_LIMITS["petualang_gratis"])
        },
        "api_keys": api_keys,
        "registered_ips": ips
    }

@app.post("/user/generate-api-key", summary="Generate API key baru", tags=["User Dashboard"])
async def generate_new_api_key(current_user: dict = Depends(get_current_user)):
    api_key = generate_api_key(current_user["username"])
    return {"api_key": api_key, "message": "API key baru berhasil dibuat"}

@app.post("/user/add-ip", summary="Tambah IP address", tags=["User Dashboard"])
async def add_ip_address(
    ip_address: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    add_user_ip(current_user["username"], ip_address)
    return {"message": f"IP {ip_address} berhasil ditambahkan"}

@app.get("/user/topup", summary="Halaman topup role (harus login)", tags=["User Dashboard"])
async def user_topup_page(current_user: dict = Depends(get_current_user)):
    """Halaman topup yang hanya bisa diakses setelah login"""
    role_info = get_user_role_by_username(current_user["username"])
    
    # Group roles by base name
    roles = defaultdict(list)
    for price, role_name, days in TOPUP_ROLE_PRICING:
        match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role_name)
        if match:
            base = match.group(1)
            limit_info = ROLE_LIMITS.get(base, {})
            roles[base].append({
                "role": role_name,
                "price": price,
                "days": days,
                "limit": limit_info
            })
    
    for r in roles:
        roles[r] = sorted(roles[r], key=lambda x: x["days"])
    
    return {
        "current_user": current_user["username"],
        "current_role": role_info,
        "available_roles": dict(roles)
    }

@app.post("/user/topup/create-payment", summary="Buat pembayaran topup (harus login)", tags=["User Dashboard"])
async def create_topup_payment(
    role: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Buat pembayaran topup untuk user yang sudah login"""
    price_entry = next((p for p in TOPUP_ROLE_PRICING if p[1] == role), None)
    if not price_entry:
        raise HTTPException(status_code=400, detail="Role tidak tersedia")

    harga, _, days = price_entry
    unique = random.randint(1, 99)
    nominal_total = harga + unique

    idpay = f"PAY-{current_user['username']}-{int(time.time())}"
    order_id = idpay

    # Get base role name
    match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role)
    base_role = match.group(1) if match else role

    params = {
        "transaction_details": {
            "order_id": order_id,
            "gross_amount": nominal_total
        },
        "item_details": [{
            "id": base_role,
            "price": nominal_total,
            "quantity": 1,
            "name": f"Topup Role {base_role}",
        }],
        "customer_details": {
            "first_name": current_user["username"],
            "email": current_user["email"],
            "phone": current_user["phone_number"]
        },
        "expiry": {
            "duration": 10,
            "unit": "minutes"
        }
    }

    try:
        transaction = snap.create_transaction(params)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    payment_info = {
        "idpay": idpay,
        "order_id": order_id,
        "username": current_user["username"],
        "role": base_role,
        "days": days,
        "nominal_total": nominal_total,
        "created_at": datetime.now().isoformat(),
        "status": "pending"
    }

    # Save transaction
    os.makedirs(PAYMENTS_DIR, exist_ok=True)
    with open(os.path.join(PAYMENTS_DIR, f"{idpay}.json"), "w") as f:
        json.dump(payment_info, f, indent=2)

    return {
        "idpay": idpay,
        "order_id": order_id,
        "token": transaction["token"],
        "redirect_url": transaction["redirect_url"]
    }

# Add these new endpoints after the existing user dashboard endpoints:

@app.post("/admin/give-role", summary="Admin berikan role ke user", tags=["Admin"])
async def admin_give_role(
    target_username: str = Form(...),
    role_name: str = Form(...),
    days: int = Form(...),
    current_user: dict = Depends(get_current_user)
):
    if current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Akses ditolak. Hanya admin yang bisa mengakses.")

    # Validasi role
    if role_name not in ROLE_LIMITS:
        raise HTTPException(status_code=400, detail="Role tidak valid")

    # Load target user data
    target_user = load_user_data(target_username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")

    # Add new role
    success = add_user_role(target_username, role_name, days)
    if not success:
        raise HTTPException(status_code=500, detail="Gagal menambahkan role")

    return {
        "message": f"Role {role_name} berhasil diberikan ke {target_username}",
        "role": role_name,
        "days": days,
        "expired_at": (datetime.now() + timedelta(days=days)).isoformat()
    }

@app.get("/admin/role-packages", summary="Get role packages for admin", tags=["Admin"])
async def get_admin_role_packages(current_user: dict = Depends(get_current_user)):
    if current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Akses ditolak. Hanya admin yang bisa mengakses.")
    
    # Group roles by base name for admin
    roles = defaultdict(list)
    for price, role_name, days in TOPUP_ROLE_PRICING:
        match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role_name)
        if match:
            base = match.group(1)
            limit_info = ROLE_LIMITS.get(base, {})
            roles[base].append({
                "role": role_name,
                "price": price,
                "days": days,
                "limit": limit_info
            })
    
    for r in roles:
        roles[r] = sorted(roles[r], key=lambda x: x["days"])
    
    return dict(roles)

# ===== TOPUP ENDPOINTS =====

@app.get("/topup/roles", summary="List semua role, harga, dan limit", tags=["topup"])
async def list_role_pricing():
    roles = defaultdict(list)
    for price, role_name, days in TOPUP_ROLE_PRICING:
        match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role_name)
        if match:
            base = match.group(1)
            limit_info = ROLE_LIMITS.get(base, {})
            roles[base].append({
                "role": role_name,
                "price": price,
                "days": days,
                "limit": limit_info
            })
    for r in roles:
        roles[r] = sorted(roles[r], key=lambda x: x["days"])
    return roles

@app.post("/topup/createkupon", tags=["topup"])
async def create_kupon(
    keykhusus: str = Query(...),
    nama: str = Query(...),
    tipe: str = Query(..., regex="^(diskon|bonus)$"),
    jumlah: int = Query(...),
    maks: int = Query(...)
):
    if keykhusus != "nauval01":
        return JSONResponse(status_code=403, content={"error": "Akses ditolak."})

    if jumlah <= 0 or maks <= 0:
        return JSONResponse(status_code=400, content={"error": "Jumlah dan maksimal harus lebih dari 0."})

    if tipe == "diskon" and jumlah > 90:
        return JSONResponse(status_code=400, content={"error": "Diskon tidak boleh lebih dari 90%"})
    if tipe == "bonus" and jumlah > 300:
        return JSONResponse(status_code=400, content={"error": "Bonus hari tidak boleh lebih dari 300%"})

    path = "kupons.json"

    try:
        if os.path.exists(path):
            with open(path) as f:
                db = json.load(f)
        else:
            db = {}
    except:
        db = {}

    kode = nama.upper()
    if kode in db:
        return JSONResponse(status_code=400, content={"error": f"Kupon '{kode}' sudah ada."})

    db[kode] = {
        "tipe": tipe,
        "jumlah": jumlah,
        "maks": maks,
        "pakai": 0
    }

    with open(path, "w") as f:
        json.dump(db, f, indent=2)

    return {
        "status": True,
        "message": f"Kupon '{kode}' berhasil dibuat.",
        "kupon": db[kode]
    }

@app.post("/topup/qris", tags=["topup"])
async def topup_qris(
    ip: str = Query(...),
    role: str = Query(...),
    wa: str = Query(...),
    idpay: str = Query(None),
    kupon: str = Query(None)
):
    price_entry = next((p for p in TOPUP_ROLE_PRICING if p[1] == role), None)
    if not price_entry:
        return JSONResponse(status_code=400, content={"error": "Role tidak tersedia."})

    harga, _, days = price_entry
    harga_asli = harga
    kupon_bonus = 0
    kupon_used = None

    if kupon:
        try:
            path = "kupons.json"
            with open(path) as f:
                kupon_db = json.load(f)
            data_kupon = kupon_db.get(kupon.upper())
            if data_kupon:
                if data_kupon["pakai"] < data_kupon["maks"]:
                    kupon_used = kupon.upper()
                    if data_kupon["tipe"] == "diskon":
                        potongan = round(harga * data_kupon["jumlah"] / 100)
                        harga -= potongan
                    elif data_kupon["tipe"] == "bonus":
                        kupon_bonus = data_kupon["jumlah"]
                    data_kupon["pakai"] += 1
                    with open(path, "w") as f:
                        json.dump(kupon_db, f, indent=2)
        except:
            kupon_used = None

    if kupon_bonus > 0:
        extra_days = round(days * (kupon_bonus / 100))
        days += extra_days

    unique = random.randint(1, 99)
    nominal_total = harga + unique

    if not idpay:
        idpay = f"PAY-{ip.replace('.', '')}-{int(time.time())}"
    order_id = idpay

    match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role)
    base_role = match.group(1) if match else role

    params = {
        "transaction_details": {
            "order_id": order_id,
            "gross_amount": nominal_total
        },
        "item_details": [{
            "id": base_role,
            "price": nominal_total,
            "quantity": 1,
            "name": f"Topup Role {base_role}",
        }],
        "customer_details": {
            "first_name": ip,
            "email": f"{ip}@mail.local"
        },
        "expiry": {
            "duration": 10,
            "unit": "minutes"
        },
        "custom_field1": wa
    }

    try:
        transaction = snap.create_transaction(params)
    except Exception as e:
        return {"status": False, "error": str(e)}

    payment_info = {
        "idpay": idpay,
        "order_id": order_id,
        "ip": ip,
        "role": base_role,
        "days": days,
        "nominal_total": nominal_total,
        "created_at": datetime.now().isoformat(),
        "status": "pending",
        "wa": wa,
        "kupon": kupon_used
    }

    os.makedirs(PAYMENTS_DIR, exist_ok=True)
    with open(os.path.join(PAYMENTS_DIR, f"{idpay}.json"), "w") as f:
        json.dump(payment_info, f, indent=2)

    return {
        "idpay": idpay,
        "order_id": order_id,
        "token": transaction["token"],
        "redirect_url": transaction["redirect_url"],
        "kupon": kupon_used or "-"
    }

@app.get("/topup/check/{idpay}", tags=["topup"])
async def check_payment(idpay: str):
    try:
        path = os.path.join(PAYMENTS_DIR, f"{idpay}.json")
        if not os.path.exists(path):
            return JSONResponse(status_code=404, content={"status": False, "error": "ID pembayaran tidak ditemukan."})

        with open(path, "r") as f:
            trx = json.load(f)

        if trx.get("status") == "paid":
            return {"status": True, "data": trx}

        order_id = trx["order_id"]
        encoded_auth = base64.b64encode(f"{YOUR_SERVER_KEY}:".encode()).decode()
        headers = {
            "Authorization": f"Basic {encoded_auth}",
            "Accept": "application/json"
        }
        url = f"https://api.midtrans.com/v2/{order_id}/status"

        result = None
        for _ in range(3):
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    res = await client.get(url, headers=headers)
                    if res.status_code == 200:
                        result = res.json()
                        break
            except:
                await asyncio.sleep(1)

        if not result:
            return JSONResponse(status_code=503, content={"status": False, "error": "Gagal menghubungi Midtrans."})

        status = result.get("transaction_status", "")
        if status not in ["settlement", "capture"]:
            return {"status": False, "message": f"Status: {status}", "data": trx}

        now = datetime.now()
        
        # Check if this is a username-based payment or IP-based payment
        if "username" in trx:
            # Username-based payment (from logged in user)
            username = trx["username"]
            role = trx["role"]
            days = trx.get("days", 1)
            
            # Add role to user
            add_user_role(username, role, days)
            
        else:
            # IP-based payment (legacy system)
            ip = trx["ip"]
            wa = trx["wa"]
            role = trx["role"]
            days = trx.get("days", 1)
            nominal = trx.get("nominal_total", 0)

            try:
                price = get_total_price_by_composed_days(role, days)
            except Exception as e:
                return JSONResponse(status_code=400, content={"status": False, "error": str(e)})

            active_role = None
            active_exp = None
            for rname, rfile in ROLE_FILES.items():
                rpath = os.path.join(ROLES_DIR, rfile)
                try:
                    with open(rpath, "r") as f:
                        rdata = json.load(f)
                    if ip in rdata:
                        active_role = rname
                        active_exp = datetime.fromisoformat(rdata[ip])
                        break
                except:
                    continue

            if active_role:
                role_target = active_role
                converted_days = convert_days_from_total_price(price, role_target)
                base_exp = active_exp if active_exp > now else now
                new_exp = base_exp + timedelta(days=converted_days)
            else:
                role_target = role
                converted_days = days
                new_exp = now + timedelta(days=converted_days)

            role_file = ROLE_FILES.get(role_target)
            if not role_file:
                return JSONResponse(status_code=400, content={"status": False, "error": "File role tidak ditemukan."})

            role_path = os.path.join(ROLES_DIR, role_file)
            try:
                with open(role_path, "r") as f:
                    db = json.load(f)
            except:
                db = {}

            db[ip] = new_exp.isoformat(timespec="microseconds")
            with open(role_path, "w") as f:
                json.dump(db, f, indent=2)

            link_cek = f"https://ytdlpyton.nvlgroup.my.id/topup/check/{idpay}"
            pesan_user = (
                "✅ *PEMBAYARAN BERHASIL*\n"
                f"ID Payment : `{idpay}`\n"
                f"Role       : `{role}`\n"
                f"Masa aktif : {converted_days} hari\n\n"
                f"Role kamu sudah aktif.\nCek status: {link_cek}"
            )
            await kirim_invoice_ke_wa(wa, idpay, role, nominal, pesan_user)

        trx.update({
            "status": "paid",
            "paid_at": now.isoformat(),
            "expired_at": (now + timedelta(days=days)).isoformat()
        })
        with open(path, "w") as f:
            json.dump(trx, f, indent=2)

        return {"status": True, "data": trx}

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": False, "error": f"Gagal memproses: {str(e)}"})

@app.post("/topup/otpvc", summary="Kirim OTP ke WA admin", tags=["topup"])
async def generate_otpvc():
    otp = ''.join(random.choices(string.digits, k=6))
    expired = datetime.now() + timedelta(minutes=OTP_EXPIRE_MINUTES)
    otp_store[otp] = {"expires": expired, "count": 0}

    message = f"*OTP Voucher Baru*\nKode: `{otp}`\nBerlaku sampai {expired.strftime('%H:%M:%S')} WIB."
    await kirim_invoice_ke_wa("6285336580720", "otpvc", "-", 0, message)

    return {"status": "OTP berhasil dikirim ke WA admin"}

@app.post("/topup/createvoucher", summary="Buat kode voucher manual", tags=["topup"])
async def create_voucher(
    otp: str = Query(...),
    role: str = Query(...),
    days: int = Query(...)
):
    otp_entry = otp_store.get(otp)
    if not otp_entry:
        return JSONResponse(status_code=403, content={"error": "OTP tidak ditemukan."})
    if datetime.now() > otp_entry["expires"]:
        return JSONResponse(status_code=403, content={"error": "OTP sudah kedaluwarsa."})
    otp_entry["count"] += 1

    role = role.lower()
    if role not in ROLE_FILES:
        return JSONResponse(status_code=400, content={"error": "Role tidak dikenali."})

    voucher_code = f"VOUCHER-{uuid.uuid4().hex[:8].upper()}"
    voucher_data = {
        "role": role,
        "days": days,
        "created_at": datetime.now().isoformat(),
        "status": "pending"
    }

    file_path = os.path.join(PAYMENTS_DIR, f"{voucher_code}.json")
    with open(file_path, "w") as f:
        json.dump(voucher_data, f, indent=2)

    msg = (
        f"*✅ Voucher Baru Dibuat*\n\n"
        f"Kode: `{voucher_code}`\n"
        f"Role: `{role}`\n"
        f"Hari Aktif: {days}\n\n"
        f"Gunakan via:\n`/topup/claimvoucher/{voucher_code}`"
    )
    await kirim_invoice_ke_wa("6285336580720", "createvoucher", "-", 0, msg)

    return {
        "message": "Voucher berhasil dibuat & dikirim ke WA admin"
    }

@app.get("/topup/claimvoucher/{voucher}", tags=["topup"])
async def claim_voucher(voucher: str, ip: str = Query(...)):
    payment_file = os.path.join(PAYMENTS_DIR, f"{voucher}.json")
    if not os.path.exists(payment_file):
        return JSONResponse(status_code=404, content={"error": "Voucher tidak ditemukan."})

    try:
        with open(payment_file, "r", encoding="utf-8") as f:
            payment_info = json.load(f)

        if payment_info.get("status") == "paid":
            return {
                "message": "Voucher sudah digunakan sebelumnya.",
                "status": "already_claimed",
                "role": payment_info.get("role"),
                "ip": payment_info.get("ip"),
                "days": payment_info.get("days"),
            }

        role_voucher = payment_info.get("role")
        days_voucher = payment_info.get("days", 1)
        now = datetime.now().replace(tzinfo=None)

        match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role_voucher)
        if not match:
            return JSONResponse(status_code=400, content={"error": "Role dari voucher tidak dikenali."})
        role_base = match.group(1)

        try:
            price = get_total_price_by_composed_days(role_base, days_voucher)
        except ValueError as e:
            return JSONResponse(status_code=400, content={"error": str(e)})

        active_role = None
        active_exp = None
        for rname, rfile in ROLE_FILES.items():
            rpath = os.path.join(ROLES_DIR, rfile)
            try:
                with open(rpath, "r") as f:
                    rdata = json.load(f)
                if ip in rdata:
                    active_role = rname
                    active_exp = datetime.fromisoformat(rdata[ip])
                    break
            except:
                continue

        if active_role:
            role_target = active_role
            converted_days = convert_days_from_total_price(price, role_target)
            base_exp = active_exp if active_exp > now else now
            new_exp = base_exp + timedelta(days=converted_days)
        else:
            role_target = role_base
            converted_days = days_voucher
            new_exp = now + timedelta(days=converted_days)

        role_file = ROLE_FILES.get(role_target)
        if not role_file:
            return JSONResponse(status_code=400, content={"error": f"File role {role_target} tidak ditemukan."})
        role_path = os.path.join(ROLES_DIR, role_file)

        try:
            with open(role_path, "r") as f:
                db = json.load(f)
        except:
            db = {}

        db[ip] = new_exp.isoformat(timespec="microseconds")
        with open(role_path, "w") as f:
            json.dump(db, f, indent=2)

        payment_info["status"] = "paid"
        payment_info["ip"] = ip
        with open(payment_file, "w") as f:
            json.dump(payment_info, f, indent=2)

        return {
            "message": "Voucher berhasil diklaim.",
            "voucher": voucher,
            "role": role_target,
            "converted_days": converted_days,
            "ip": ip,
            "new_expired": db[ip],
            "note": "Konversi hari berdasarkan role aktif jika sudah ada."
        }

    except Exception as e:
        logger.error(f"claim_voucher error | {voucher} | {e}")
        return JSONResponse(status_code=500, content={"error": f"Gagal memproses voucher: {str(e)}"})

@app.post("/topup/upgrade-role", summary="Upgrade/Downgrade role berdasarkan IP dan ID pembayaran", tags=["topup"])
async def upgrade_role(
    ip: str = Query(...),
    role_lama: str = Query(...),
    role_baru: str = Query(...),
    idpay: str = Query(...)
):
    pay_file = os.path.join(PAYMENTS_DIR, f"{idpay}.json")
    if not os.path.exists(pay_file):
        return JSONResponse(status_code=404, content={"error": f"Payment ID '{idpay}' tidak ditemukan."})

    with open(pay_file) as f:
        data = json.load(f)

    if data.get("ip") != ip or data.get("role") != role_lama or data.get("status") != "paid":
        return JSONResponse(status_code=403, content={"error": "Validasi gagal. IP atau Role tidak sesuai database pembayaran."})

    rolelama_path = os.path.join(ROLES_DIR, ROLE_FILES.get(role_lama))
    if not os.path.exists(rolelama_path):
        return JSONResponse(status_code=404, content={"error": "File role lama tidak ditemukan."})

    try:
        with open(rolelama_path) as f:
            db_lama = json.load(f)
    except:
        db_lama = {}

    if ip not in db_lama:
        return JSONResponse(status_code=404, content={"error": f"IP {ip} tidak ditemukan dalam role lama."})

    now = datetime.now().replace(tzinfo=None)
    try:
        exp_lama = datetime.fromisoformat(db_lama[ip])
        sisa_hari = max((exp_lama - now).days, 0)
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Format tanggal role lama tidak valid."})

    if sisa_hari == 0:
        return JSONResponse(status_code=400, content={"error": "Role lama sudah expired, tidak bisa dikonversi."})

    try:
        harga_total = get_total_price_by_composed_days(role_lama, sisa_hari)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "Tidak ditemukan harga untuk role lama dengan sisa hari."})

    try:
        hari_baru = convert_days_from_total_price(harga_total, role_baru)
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

    del db_lama[ip]
    with open(rolelama_path, "w") as f:
        json.dump(db_lama, f, indent=2)

    rolebaru_path = os.path.join(ROLES_DIR, ROLE_FILES.get(role_baru))
    try:
        with open(rolebaru_path) as f:
            db_baru = json.load(f)
    except:
        db_baru = {}

    new_exp = now + timedelta(days=hari_baru)
    db_baru[ip] = new_exp.isoformat(timespec="microseconds")
    with open(rolebaru_path, "w") as f:
        json.dump(db_baru, f, indent=2)

    return {
        "message": "Role berhasil di-upgrade/downgrade.",
        "ip": ip,
        "dari": role_lama,
        "ke": role_baru,
        "sisa_hari_lama": sisa_hari,
        "harga_terkira_lama": harga_total,
        "konversi_ke_hari_baru": hari_baru,
        "expired_baru": new_exp.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.get("/role/check", summary="Check user role based on IP address", tags=["topup"])
async def check_role(ip: str = Query(..., description="IP address to check")):
    try:
        role_info = get_user_role(ip)
        role_name = role_info["role"]
        
        # Get limits for the role
        limits = ROLE_LIMITS.get(role_name, ROLE_LIMITS["petualang_gratis"]).copy()
        
        # Handle infinity value for JSON serialization
        if isinstance(limits.get("rpm"), float) and math.isinf(limits["rpm"]):
            limits["rpm"] = -1  # Use -1 to represent infinity

        if role_info.get("expired"):
            try:
                exp_time = datetime.fromisoformat(role_info["expired"])
                now = datetime.now()
                time_left = exp_time - now
                total_seconds = max(int(time_left.total_seconds()), 0)
                days_left = total_seconds // 86400
                hours_left = (total_seconds % 86400) // 3600
                minutes_left = (total_seconds % 3600) // 60

                return {
                    "ip": ip,
                    "role": role_name,
                    "expired": exp_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "active" if total_seconds > 0 else "expired",
                    "time_remaining": {
                        "days": days_left,
                        "hours": hours_left,
                        "minutes": minutes_left
                    },
                    "limits": limits
                }
            except Exception as e:
                logger.error(f"Error parsing expiration time: {e}")
                return {
                    "ip": ip,
                    "role": role_name,
                    "expired": role_info["expired"],
                    "status": "unknown",
                    "limits": limits
                }
        else:
            # Free user or unlimited
            return {
                "ip": ip,
                "role": role_name,
                "expired": None,
                "status": "unlimited",
                "limits": limits
            }
    except Exception as e:
        logger.error(f"Error checking role for IP {ip}: {e}")
        return JSONResponse(status_code=500, content={"error": f"Error checking role: {str(e)}"})

@app.get("/checkme", summary="Cek role, batasan, dan waktu kadaluarsa berdasarkan IP/API key", tags=["topup"])
async def check_my_role(request: Request):
    # Ambil IP dari header atau koneksi
    ip = request.headers.get("X-Forwarded-For")
    if ip:
        ip = ip.split(",")[0].strip()
    else:
        ip = request.client.host

    # Ambil API key dari header
    api_key = request.headers.get("X-API-Key")

    # Deteksi role berdasarkan API key atau IP
    role_info = get_user_role(ip_address=ip, api_key=api_key)
    role_name = role_info["role"]
    expired_str = role_info["expired"]
    limits = ROLE_LIMITS.get(role_name, ROLE_LIMITS["petualang_gratis"])

    # Tentukan asal autentikasi
    auth_by = "apikey" if (api_key and expired_str) else "ip"
    auth_value = api_key if auth_by == "apikey" else ip

    # Hitung waktu kadaluarsa
    expired_in = None
    if expired_str:
        try:
            exp_time = datetime.fromisoformat(expired_str)
            now = datetime.now()
            if exp_time > now:
                delta = exp_time - now
                days = delta.days
                hours, remainder = divmod(delta.seconds, 3600)
                minutes = remainder // 60
                expired_in = f"{days} hari, {hours} jam, {minutes} menit"
            else:
                expired_in = "Sudah kadaluarsa"
        except:
            expired_in = "Format tanggal tidak valid"

    return {
        "auth_by": auth_by,
        "auth_value": auth_value,
        "role": role_name,
        "expired": expired_str,
        "expired_in": expired_in,
        "limits": limits
    }

@app.post("/topup/change-ip", summary="Ganti IP berdasarkan username", tags=["topup"])
async def change_ip_by_username(
    username: str = Query(..., description="Username yang akan diganti IP-nya"),
    ip_lama: str = Query(..., description="IP lama pengguna (opsional untuk validasi)"),
    ip_baru: str = Query(..., description="IP baru yang akan digunakan")
):
    # Load user data
    user_data = load_user_data(username)
    if not user_data:
        return JSONResponse(status_code=404, content={
            "error": f"User '{username}' tidak ditemukan."
        })

    # Validasi IP lama jika disediakan
    if ip_lama:
        ip_found = False
        for ip_data in user_data.get("ip_addresses", []):
            if ip_data.get("ip_address") == ip_lama and ip_data.get("is_active", False):
                ip_found = True
                # Nonaktifkan IP lama
                ip_data["is_active"] = False
                ip_data["updated_at"] = datetime.now().isoformat()
                break
        
        if not ip_found:
            return JSONResponse(status_code=404, content={
                "error": f"IP lama '{ip_lama}' tidak ditemukan untuk user '{username}'."
            })

    # Tambah IP baru
    add_user_ip(username, ip_baru)

    # Update juga di sistem role lama untuk kompatibilitas
    updated_roles = []
    if ip_lama:
        for role_name, file_name in ROLE_FILES.items():
            path = os.path.join("roles", file_name)
            try:
                with open(path, "r") as f:
                    role_data = json.load(f)

                if ip_lama in role_data:
                    role_data[ip_baru] = role_data.pop(ip_lama)
                    with open(path, "w") as f:
                        json.dump(role_data, f)
                    updated_roles.append(role_name)

            except Exception as e:
                logger.error(f"change-ip roles | {role_name} | {e}")

    return {
        "message": "IP berhasil diganti.",
        "username": username,
        "ip_lama": ip_lama or "tidak ada",
        "ip_baru": ip_baru,
        "roles_terupdate": updated_roles
    }

@app.post("/user/change-role", summary="Ganti role berdasarkan username", tags=["User Dashboard"])
async def change_user_role(
    target_username: str = Form(..., description="Username yang akan diganti role-nya"),
    new_role: str = Form(..., description="Role baru"),
    days: int = Form(..., description="Jumlah hari"),
    current_user: dict = Depends(get_current_user)
):
    # Hanya admin atau user sendiri yang bisa ganti role
    if current_user["username"] != target_username and current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Tidak memiliki akses untuk mengubah role user lain")

    # Validasi role
    if new_role not in ROLE_LIMITS:
        raise HTTPException(status_code=400, detail="Role tidak valid")

    # Load target user data
    target_user = load_user_data(target_username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")

    # Add new role
    success = add_user_role(target_username, new_role, days)
    if not success:
        raise HTTPException(status_code=500, detail="Gagal menambahkan role")

    return {
        "message": f"Role berhasil diubah untuk user {target_username}",
        "new_role": new_role,
        "days": days,
        "expired_at": (datetime.now() + timedelta(days=days)).isoformat()
    }

@app.post("/user/buy-role", summary="Beli role langsung dari dashboard", tags=["User Dashboard"])
async def buy_role_direct(
    role_code: str = Form(..., description="Kode role yang akan dibeli"),
    current_user: dict = Depends(get_current_user)
):
    # Cari role di pricing
    price_entry = next((p for p in TOPUP_ROLE_PRICING if p[1] == role_code), None)
    if not price_entry:
        raise HTTPException(status_code=400, detail="Role tidak tersedia")

    harga, _, days = price_entry
    
    # Get base role name
    match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role_code)
    base_role = match.group(1) if match else role_code

    # Langsung tambahkan role (untuk demo/testing)
    # Dalam implementasi nyata, ini harus melalui pembayaran
    success = add_user_role(current_user["username"], base_role, days)
    if not success:
        raise HTTPException(status_code=500, detail="Gagal menambahkan role")

    return {
        "message": f"Role {base_role} berhasil ditambahkan",
        "role": base_role,
        "days": days,
        "expired_at": (datetime.now() + timedelta(days=days)).isoformat()
    }

@app.get("/admin/users", summary="List semua user (admin only)", tags=["Admin"])
async def list_all_users(current_user: dict = Depends(get_current_user)):
    if current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Akses ditolak. Hanya admin yang bisa mengakses.")

    users = []
    for user_file in USER_DIR.glob("*.json"):
        try:
            with open(user_file, 'r', encoding='utf-8') as f:
                user_data = json.load(f)
                role_info = get_user_role_by_username(user_data["username"])
                users.append({
                    "username": user_data["username"],
                    "email": user_data["email"],
                    "phone_number": user_data["phone_number"],
                    "created_at": user_data["created_at"],
                    "current_role": role_info["role"],
                    "role_expired": role_info["expired"],
                    "api_keys_count": len([k for k in user_data.get("api_keys", []) if k.get("is_active", False)]),
                    "ip_addresses_count": len([ip for ip in user_data.get("ip_addresses", []) if ip.get("is_active", False)])
                })
        except Exception as e:
            logger.error(f"Error loading user file {user_file}: {e}")
            continue

    return {"users": users, "total": len(users)}

@app.post("/admin/change-user-role", summary="Admin ganti role user", tags=["Admin"])
async def admin_change_user_role(
    target_username: str = Form(...),
    new_role: str = Form(...),
    days: int = Form(...),
    current_user: dict = Depends(get_current_user)
):
    if current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Akses ditolak. Hanya admin yang bisa mengakses.")

    # Validasi role
    if new_role not in ROLE_LIMITS:
        raise HTTPException(status_code=400, detail="Role tidak valid")

    # Load target user data
    target_user = load_user_data(target_username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")

    # Add new role
    success = add_user_role(target_username, new_role, days)
    if not success:
        raise HTTPException(status_code=500, detail="Gagal menambahkan role")

    return {
        "message": f"Role berhasil diubah untuk user {target_username}",
        "new_role": new_role,
        "days": days,
        "expired_at": (datetime.now() + timedelta(days=days)).isoformat()
    }

@app.post("/admin/give-role", summary="Admin berikan role ke user", tags=["Admin"])
async def admin_give_role(
    target_username: str = Form(...),
    role_name: str = Form(...),
    days: int = Form(...),
    current_user: dict = Depends(get_current_user)
):
    if current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Akses ditolak. Hanya admin yang bisa mengakses.")

    # Validasi role
    if role_name not in ROLE_LIMITS:
        raise HTTPException(status_code=400, detail="Role tidak valid")

    # Load target user data
    target_user = load_user_data(target_username)
    if not target_user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")

    # Add new role
    success = add_user_role(target_username, role_name, days)
    if not success:
        raise HTTPException(status_code=500, detail="Gagal menambahkan role")

    return {
        "message": f"Role {role_name} berhasil diberikan ke {target_username}",
        "role": role_name,
        "days": days,
        "expired_at": (datetime.now() + timedelta(days=days)).isoformat()
    }

@app.get("/admin/role-packages", summary="Get role packages for admin", tags=["Admin"])
async def get_admin_role_packages(current_user: dict = Depends(get_current_user)):
    if current_user["username"] != "admin":
        raise HTTPException(status_code=403, detail="Akses ditolak. Hanya admin yang bisa mengakses.")
    
    # Group roles by base name for admin
    roles = defaultdict(list)
    for price, role_name, days in TOPUP_ROLE_PRICING:
        match = re.match(r"^(pencariawal|penjelajahmuda|masterpro|strategiselit|visionerlegendaris|penguasa|liburanpackages|dirgahayuri)", role_name)
        if match:
            base = match.group(1)
            limit_info = ROLE_LIMITS.get(base, {})
            roles[base].append({
                "role": role_name,
                "price": price,
                "days": days,
                "limit": limit_info
            })
    
    for r in roles:
        roles[r] = sorted(roles[r], key=lambda x: x["days"])
    
    return dict(roles)

# HTML Pages
@app.get("/", summary="Root Endpoint")
async def root():
    return FileResponse("static/index.html") if os.path.exists("static/index.html") else {"message": "API is running"}

@app.get("/signup", summary="Halaman Signup")
async def signup_page():
    return FileResponse("static/signup.html")

@app.get("/login", summary="Halaman Login")
async def login_page():
    return FileResponse("static/login.html")

@app.get("/dashboard", summary="Halaman Dashboard")
async def dashboard_page():
    return FileResponse("static/dashboard.html")

# Keep your existing endpoints but modify them to use the new auth system
@app.get("/search/", summary="Pencarian Video YouTube", tags=["YouTube"])
async def search_video(
    query: str = Query(..., description="Kata kunci pencarian"),
    request: Request = None
):
    try:
        max_results = 15
        raw_results = YoutubeSearch(query, max_results=max_results).to_dict()
        results = []
        for result in raw_results:
            try:
                url = f"https://youtu.be/{result['id']}" if "id" in result else None
                thumbnail = result["thumbnails"][0] if result.get("thumbnails") else None
                results.append({
                    "title": result["title"],
                    "url": url,
                    "id": result["id"],
                    "thumbnail": thumbnail,
                })
            except Exception as e:
                logging.warning(f"Error processing result: {e}")

        return {"results": results}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/download/file/{filename}", summary="Mengunduh file hasil")
async def download_file(filename: str):
    file_path = os.path.join(OUTPUT_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, filename=filename)
    return JSONResponse(status_code=404, content={"error": "File tidak ditemukan"})

# Initialize scheduler
scheduler = BackgroundScheduler(timezone="Asia/Jakarta")
scheduler.add_job(clean_expired_roles, 'cron', hour=0, minute=0)  # Jam 12 malam WIB
scheduler.start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
