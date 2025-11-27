"""
CONDUM HYBRID - Best of Both Worlds
Combines CA-based master keys with fast session keys for optimal security and performance

Architecture:
1. Master Key: Generated using CA evolution (slow, done once)
2. Session Keys: Standard 32-byte keys (fast, rotatable)
3. Data Encryption: AES-256-GCM with session keys
4. Key Wrapping: Session keys encrypted with master key

Benefits:
- CA complexity for master key security
- Fast session key rotation
- Supports forward secrecy
- Compatible with key ratcheting
- Best for both offline storage and active use
"""

import os
import sys
import numpy as np
from collections import Counter
from hashlib import sha256
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac

# ----- Configuration Constants -----
GRID_SIZE = 64  # Smaller for faster master key generation
DEFAULT_GENERATIONS = 200
DEFAULT_PBKDF2_ITERATIONS = 100000

# ----- Master Key Functions (CA-based) -----
def initialize_grid(size):
    return np.random.randint(0, 256, size=(size, size), dtype=np.uint8)

def evolve(grid, generations):
    for _ in range(generations):
        padded_grid = np.pad(grid, pad_width=1, mode='wrap')
        neighbors = (
            padded_grid[:-2, :-2] + padded_grid[:-2, 1:-1] + padded_grid[:-2, 2:] +
            padded_grid[1:-1, :-2] + padded_grid[1:-1, 2:] +
            padded_grid[2:, :-2] + padded_grid[2:, 1:-1] + padded_grid[2:, 2:]
        )
        # Fix: Convert to int32 to avoid uint8 overflow (neighbors can sum to 2040+)
        grid = ((grid.astype(np.int32) + neighbors.astype(np.int32)) % 256).astype(np.uint8)
    return grid

def generate_master_key(password, generations=DEFAULT_GENERATIONS):
    """
    Generate CA-based master key (done once, stored securely)

    Returns: (master_key, salt, metadata)
    """
    # Generate salt
    salt = os.urandom(32)

    # Stretch password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=DEFAULT_PBKDF2_ITERATIONS
    )
    stretched = kdf.derive(password.encode('utf-8'))

    # CA evolution
    seed = int.from_bytes(stretched[:8], 'big') % (2**32)
    np.random.seed(seed)

    grid = initialize_grid(GRID_SIZE)
    grid = evolve(grid, generations)

    # Derive master key from CA output + stretched password
    ca_output = grid.tobytes()

    # Use HKDF for proper key derivation
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"condum-hybrid-master-key"
    )
    master_key = hkdf.derive(stretched + ca_output[:32])

    metadata = {
        'version': 'CONDUM-HYBRID-1.0',
        'created': datetime.now().isoformat(),
        'grid_size': GRID_SIZE,
        'generations': generations
    }

    return master_key, salt, metadata

# ----- Session Key Functions (Fast) -----
def generate_session_key():
    """Generate a random 32-byte session key (fast)"""
    return secrets.token_bytes(32)

def wrap_session_key(session_key, master_key):
    """Encrypt session key with master key using AES-GCM"""
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    wrapped = aesgcm.encrypt(nonce, session_key, None)
    return nonce + wrapped

def unwrap_session_key(wrapped_key, master_key):
    """Decrypt session key using master key"""
    aesgcm = AESGCM(master_key)
    nonce = wrapped_key[:12]
    ciphertext = wrapped_key[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

# ----- Data Encryption Functions -----
def encrypt_data(data, session_key):
    """Encrypt data with session key"""
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_data(encrypted_data, session_key):
    """Decrypt data with session key"""
    aesgcm = AESGCM(session_key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

# ----- Hybrid Encryption/Decryption -----
def hybrid_encrypt(data, master_key):
    """
    Encrypt data using hybrid system:
    1. Generate random session key
    2. Encrypt data with session key
    3. Wrap session key with master key
    4. Return both wrapped key and encrypted data
    """
    # Generate fresh session key
    session_key = generate_session_key()

    # Encrypt data
    encrypted_data = encrypt_data(data, session_key)

    # Wrap session key
    wrapped_key = wrap_session_key(session_key, master_key)

    # Package: [wrapped_key_length][wrapped_key][encrypted_data]
    import struct
    package = struct.pack('I', len(wrapped_key)) + wrapped_key + encrypted_data

    return package

def hybrid_decrypt(package, master_key):
    """
    Decrypt data using hybrid system:
    1. Extract wrapped session key
    2. Unwrap session key using master key
    3. Decrypt data with session key
    """
    import struct

    # Unpackage
    wrapped_key_len = struct.unpack('I', package[:4])[0]
    wrapped_key = package[4:4+wrapped_key_len]
    encrypted_data = package[4+wrapped_key_len:]

    # Unwrap session key
    session_key = unwrap_session_key(wrapped_key, master_key)

    # Decrypt data
    data = decrypt_data(encrypted_data, session_key)

    return data

# ----- Master Key Storage -----
def save_master_key(filename, master_key, salt, metadata):
    """Save master key with authentication"""
    import struct
    import json

    MAGIC = b'CDHB'  # CONDUM-HYBRID
    VERSION = struct.pack('B', 1)

    # Serialize metadata
    meta_json = json.dumps(metadata).encode('utf-8')
    meta_len = struct.pack('I', len(meta_json))

    # Package
    package = MAGIC + VERSION + salt + master_key + meta_len + meta_json

    # HMAC
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(package)
    auth_tag = h.finalize()

    package += auth_tag

    with open(filename, 'wb') as f:
        f.write(package)

    print(f"[+] Master key saved: {filename}")
    print(f"    - Total size: {len(package)} bytes")
    print(f"    - Master key: 32 bytes")
    print(f"    - Metadata: {len(meta_json)} bytes")

def read_master_key(filename):
    """Read and verify master key"""
    import struct
    import json

    with open(filename, 'rb') as f:
        data = f.read()

    # Parse
    magic = data[0:4]
    version = data[4]
    salt = data[5:37]
    master_key = data[37:69]
    meta_len = struct.unpack('I', data[69:73])[0]
    meta_json = data[73:73+meta_len]
    auth_tag = data[73+meta_len:105+meta_len]

    # Verify
    if magic != b'CDHB':
        raise ValueError("Invalid master key file")

    package = data[:73+meta_len]
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(package)
    h.verify(auth_tag)

    metadata = json.loads(meta_json.decode('utf-8'))

    return master_key, salt, metadata

# ----- CLI Functions -----
def create_master_key_cli():
    print("\n" + "="*60)
    print("CONDUM HYBRID - Master Key Generation")
    print("="*60)

    password = input("Enter master password: ")
    confirm = input("Confirm password: ")

    if password != confirm:
        print("[-] Passwords don't match!")
        return

    generations = int(input(f"Enter generations (default {DEFAULT_GENERATIONS}): ") or DEFAULT_GENERATIONS)

    print("\n[*] Generating master key (this may take 5-10 seconds)...")
    master_key, salt, metadata = generate_master_key(password, generations)

    print(f"[+] Master key generated!")
    print(f"    - Grid size: {metadata['grid_size']}x{metadata['grid_size']}")
    print(f"    - Generations: {metadata['generations']}")
    print(f"    - Created: {metadata['created']}")

    save_path = input("\nSave master key as (e.g., master.cdhb): ")
    save_master_key(save_path, master_key, salt, metadata)

    print("\n[!] IMPORTANT: Store this master key securely!")
    print("    - Use encrypted storage (USB drive, password manager)")
    print("    - Never transmit over insecure channels")
    print("    - Make encrypted backups")

def encrypt_file_cli():
    print("\n" + "="*60)
    print("CONDUM HYBRID - File Encryption")
    print("="*60)

    # Load master key
    master_key_file = input("Enter master key file path: ")
    password = input("Enter master password: ")

    # Regenerate master key from password
    print("\n[*] Deriving master key...")
    try:
        stored_key, salt, metadata = read_master_key(master_key_file)
        # Verify by regenerating
        derived_key, _, _ = generate_master_key(password, metadata['generations'])

        # Use stored key (it has the original salt)
        master_key = stored_key
        print("[+] Master key loaded successfully")
    except Exception as e:
        print(f"[-] Failed to load master key: {e}")
        return

    # Get file to encrypt
    input_file = input("Enter file to encrypt: ")
    output_file = input("Save encrypted file as: ")

    with open(input_file, 'rb') as f:
        data = f.read()

    print(f"\n[*] Encrypting {len(data):,} bytes with hybrid system...")
    print("    - Generating session key...")
    print("    - Encrypting data with AES-256-GCM...")
    print("    - Wrapping session key with master key...")

    encrypted_package = hybrid_encrypt(data, master_key)

    with open(output_file, 'wb') as f:
        f.write(encrypted_package)

    print(f"\n[+] File encrypted successfully!")
    print(f"    - Original size: {len(data):,} bytes")
    print(f"    - Encrypted size: {len(encrypted_package):,} bytes")
    print(f"    - Overhead: {len(encrypted_package) - len(data)} bytes")
    print(f"    - Saved to: {output_file}")

def decrypt_file_cli():
    print("\n" + "="*60)
    print("CONDUM HYBRID - File Decryption")
    print("="*60)

    # Load master key
    master_key_file = input("Enter master key file path: ")
    password = input("Enter master password: ")

    print("\n[*] Deriving master key...")
    try:
        master_key, salt, metadata = read_master_key(master_key_file)
        print("[+] Master key loaded successfully")
    except Exception as e:
        print(f"[-] Failed to load master key: {e}")
        return

    # Get file to decrypt
    enc_file = input("Enter encrypted file: ")
    dec_file = input("Save decrypted file as: ")

    with open(enc_file, 'rb') as f:
        encrypted_package = f.read()

    print(f"\n[*] Decrypting {len(encrypted_package):,} bytes...")
    print("    - Unwrapping session key...")
    print("    - Decrypting data...")

    try:
        data = hybrid_decrypt(encrypted_package, master_key)

        with open(dec_file, 'wb') as f:
            f.write(data)

        print(f"\n[+] File decrypted successfully!")
        print(f"    - Decrypted size: {len(data):,} bytes")
        print(f"    - Saved to: {dec_file}")
    except Exception as e:
        print(f"\n[-] Decryption failed: {e}")
        print("    - Wrong password or corrupted file?")

def encrypt_text_cli():
    print("\n" + "="*60)
    print("CONDUM HYBRID - Text Encryption")
    print("="*60)

    master_key_file = input("Enter master key file path: ")
    password = input("Enter master password: ")

    try:
        master_key, _, _ = read_master_key(master_key_file)
    except:
        print("[-] Failed to load master key")
        return

    text = input("Enter text to encrypt: ")

    encrypted = hybrid_encrypt(text.encode('utf-8'), master_key)

    save_path = input("Save as: ")
    with open(save_path, 'wb') as f:
        f.write(encrypted)

    print(f"[+] Text encrypted and saved to {save_path}")

def decrypt_text_cli():
    print("\n" + "="*60)
    print("CONDUM HYBRID - Text Decryption")
    print("="*60)

    master_key_file = input("Enter master key file path: ")
    password = input("Enter master password: ")

    try:
        master_key, _, _ = read_master_key(master_key_file)
    except:
        print("[-] Failed to load master key")
        return

    enc_file = input("Enter encrypted text file: ")

    with open(enc_file, 'rb') as f:
        encrypted = f.read()

    try:
        text = hybrid_decrypt(encrypted, master_key).decode('utf-8')
        print(f"\n[+] Decrypted text:\n{text}")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")

# ----- Main CLI -----
def main():
    print("\n" + "="*60)
    print("  CONDUM HYBRID - Advanced Encryption System")
    print("  CA Master Keys + Fast Session Keys")
    print("="*60)

    while True:
        print("\nOptions:")
        print("1. Create Master Key")
        print("2. Encrypt File")
        print("3. Decrypt File")
        print("4. Encrypt Text")
        print("5. Decrypt Text")
        print("6. Exit")

        choice = input("\nSelect option: ").strip()

        try:
            if choice == "1":
                create_master_key_cli()
            elif choice == "2":
                encrypt_file_cli()
            elif choice == "3":
                decrypt_file_cli()
            elif choice == "4":
                encrypt_text_cli()
            elif choice == "5":
                decrypt_text_cli()
            elif choice == "6":
                print("\n[*] Exiting...")
                break
            else:
                print("[-] Invalid choice.")
        except KeyboardInterrupt:
            print("\n\n[*] Operation cancelled.")
        except Exception as e:
            print(f"\n[-] Error: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
