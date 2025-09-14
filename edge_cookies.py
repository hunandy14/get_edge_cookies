#!/usr/bin/env python3
import os
import json
import base64
import sqlite3
import argparse
import tempfile
import shutil
from pathlib import Path
from urllib.parse import urlparse

try:
    import win32crypt
    from Cryptodome.Cipher import AES
    import psutil
except ImportError as e:
    print(f"Error: Missing required packages - {e}")
    print("Please run: pip install -r requirements.txt")
    exit(1)


def get_edge_path():
    appdata = Path(os.getenv("LOCALAPPDATA", ""))
    return next((appdata / "Microsoft" / name / "User Data" for name in ["Edge", "Edge Beta", "Edge Dev", "Edge Canary"] if (appdata / "Microsoft" / name / "User Data").exists()), None)


def get_key(local_state_path):
    with open(local_state_path, 'r', encoding='utf-8') as f:
        key = base64.b64decode(json.load(f)['os_crypt']['encrypted_key'])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt(encrypted_value, key):
    try:
        if encrypted_value.startswith(b'v10'):
            nonce, ciphertext, tag = encrypted_value[3:15], encrypted_value[15:-16], encrypted_value[-16:]
            return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag).decode('utf-8')
        return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode('utf-8')
    except:
        return ""


def webkit_to_unix(webkit_time):
    return (webkit_time - 11644473600000000) / 1000000.0 if webkit_time > 0 else None


def create_cookie(row, key, exact_match=False):
    host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite = row
    
    if exact_match and name not in ['AEC', 'NID']:
        return None
    
    decrypted = decrypt(encrypted_value, key) if encrypted_value else value or ""
    if not decrypted:
        decrypted = "[ENCRYPTED]" if encrypted_value else ""
    if not decrypted:
        return None
    
    return {
        "domain": host_key,
        "expirationDate": webkit_to_unix(expires_utc),
        "hostOnly": not host_key.startswith('.'),
        "httpOnly": bool(is_httponly),
        "name": name,
        "path": path or "/",
        "sameSite": {0: "no_restriction", 1: "lax", 2: "strict"}.get(samesite, "no_restriction"),
        "secure": bool(is_secure),
        "session": expires_utc <= 0,
        "storeId": None,
        "value": decrypted
    }


def extract_cookies(target_domain):
    edge_path = get_edge_path()
    if not edge_path:
        raise Exception("Edge path not found")
    
    local_state, cookies_db = edge_path / "Local State", edge_path / "Default" / "Network" / "Cookies"
    if not local_state.exists() or not cookies_db.exists():
        raise Exception("Required files not found")
    
    if any(proc.info['name'] == 'msedge.exe' for proc in psutil.process_iter(['name'])):
        print("⚠️  Edge is running, some cookies may not be decrypted")
    
    key = get_key(local_state)
    
    temp_dir = tempfile.mkdtemp()
    try:
        shutil.copy2(cookies_db, temp_db := Path(temp_dir) / "cookies")
        
        with sqlite3.connect(str(temp_db)) as conn:
            cursor = conn.cursor()
            patterns = [f"%{target_domain}%", f"%.{target_domain}", target_domain]
            exact_match = target_domain in ['google.com', 'www.google.com']
            cookies = []
            
            for pattern in patterns:
                cursor.execute("""
                    SELECT host_key, name, value, encrypted_value, path, expires_utc, 
                           is_secure, is_httponly, samesite
                    FROM cookies WHERE host_key LIKE ?
                """, (pattern,))
                
                for row in cursor.fetchall():
                    host_key = row[0]
                    if not (host_key == target_domain or host_key.endswith('.' + target_domain) or target_domain.endswith('.' + host_key)):
                        continue
                    
                    cookie = create_cookie(row, key, exact_match)
                    if cookie and not any(c["name"] == cookie["name"] and c["domain"] == cookie["domain"] for c in cookies):
                        cookies.append(cookie)
            
            return cookies
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Edge Cookies Extractor")
    parser.add_argument("target", help="Target URL or domain")
    
    args = parser.parse_args()
    
    try:
        target_domain = urlparse(args.target).netloc.lower().strip() if args.target.startswith(('http://', 'https://')) else args.target.lower().strip()
        if target_domain.startswith("www."):
            target_domain = target_domain[4:]
        
        cookies = extract_cookies(target_domain)
        
        if not cookies:
            print(f"No cookies found for {target_domain}")
            return
        
        print(json.dumps(cookies, ensure_ascii=False, indent=2, sort_keys=True))
    
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()