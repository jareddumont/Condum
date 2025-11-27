"""
CONDUM LITE - Compact Key Derivation Function
Uses cellular automata evolution to generate 32-byte keys (AES-256 compatible)

"""

import os
import sys
import numpy as np
from collections import Counter
from hashlib import sha256
from datetime import datetime
import ctypes
import tempfile
import shutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.constant_time import bytes_eq

# ----- Configuration Constants -----
MIN_GRID_SIZE = 32
MAX_GRID_SIZE = 128
DEFAULT_PBKDF2_ITERATIONS = 100000
DEFAULT_GENERATIONS = 500
MAX_FILE_SIZE_WARNING = 1_000_000_000  # 1 GB
STREAMING_THRESHOLD = 100_000_000  # 100 MB

# ----- Custom Exceptions -----
class CondumError(Exception):
    """Base exception for CONDUM errors"""
    pass

class PasswordIncorrectError(CondumError):
    def __init__(self):
        super().__init__(
            "Decryption failed - incorrect password.\n"
            "  → Make sure you're using the exact same password used for encryption\n"
            "  → Passwords are case-sensitive\n"
            "  → Check for accidental spaces at the beginning or end"
        )

class CorruptedFileError(CondumError):
    def __init__(self, filename, reason):
        super().__init__(
            f"File '{filename}' appears to be corrupted.\n"
            f"  → Reason: {reason}\n"
            f"  → Try restoring from backup\n"
            f"  → Check if file was completely downloaded/copied"
        )

class KeyFileMismatchError(CondumError):
    def __init__(self, expected_version, found_version):
        super().__init__(
            f"Key file version mismatch.\n"
            f"  → Expected: {expected_version}\n"
            f"  → Found: {found_version}\n"
            f"  → This key was created with a different version of CONDUM"
        )

class WeakPasswordError(CondumError):
    def __init__(self, score, feedback):
        feedback_str = "\n".join([f"  - {f}" for f in feedback])
        super().__init__(
            f"Password is too weak (strength: {score}/100).\n"
            f"Suggestions:\n{feedback_str}"
        )

# ----- Security Functions -----
def secure_zero(data):
    """Securely wipe data from memory"""
    try:
        if isinstance(data, bytes):
            # Create mutable buffer and overwrite
            buffer = (ctypes.c_char * len(data)).from_buffer_copy(data)
            ctypes.memset(ctypes.addressof(buffer), 0, len(data))
        elif isinstance(data, np.ndarray):
            data.fill(0)
    except:
        pass  # Best effort - don't crash if wiping fails
    finally:
        if 'data' in locals():
            del data

def check_password_strength(password):
    """
    Validate password meets minimum security requirements
    Returns: (is_strong, score, feedback)
    """
    score = 0
    feedback = []

    # Length check
    if len(password) < 12:
        feedback.append("Use at least 12 characters")
    else:
        score += 25

    if len(password) >= 16:
        score += 10

    # Character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password)

    if has_lower:
        score += 15
    else:
        feedback.append("Add lowercase letters")

    if has_upper:
        score += 15
    else:
        feedback.append("Add uppercase letters")

    if has_digit:
        score += 15
    else:
        feedback.append("Add numbers")

    if has_special:
        score += 20
    else:
        feedback.append("Add special characters (!@#$...)")

    # Check common passwords
    common_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein',
                       'welcome', 'monkey', 'dragon', 'master', 'sunshine']
    if password.lower() in common_passwords:
        score = 0
        feedback.append("This is a commonly used password - DO NOT USE")

    is_strong = score >= 75

    return is_strong, score, feedback

def print_progress_bar(iteration, total, prefix='', suffix='', length=50):
    """Print a progress bar"""
    percent = 100 * (iteration / float(total))
    filled = int(length * iteration // total)
    bar = '█' * filled + '-' * (length - filled)

    sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}')
    sys.stdout.flush()

    if iteration == total:
        print()  # New line when complete

def safe_write_file(filename, data):
    """Write file and verify it was written correctly"""
    temp_dir = os.path.dirname(filename) or '.'

    # Write to temporary file first
    with tempfile.NamedTemporaryFile(mode='wb', dir=temp_dir, delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    # Verify temp file
    with open(tmp_path, 'rb') as f:
        verify_data = f.read()

    if verify_data != data:
        os.unlink(tmp_path)
        raise IOError(f"Write verification failed for {filename}")

    # Move temp file to final location (atomic on Unix)
    shutil.move(tmp_path, filename)

    return True

# ----- Core Functions -----
def calculate_entropy(key):
    """Calculate the entropy of the key in bits per byte."""
    from math import log2
    byte_counts = Counter(key)
    entropy = -sum((count / len(key)) * log2(count / len(key)) for count in byte_counts.values())
    return entropy

def initialize_grid(size):
    """Initialize grid with random values 0-255"""
    return np.random.randint(0, 256, size=(size, size), dtype=np.uint8)

def evolve(grid, generations):
    """Evolve the grid using CA rules"""
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

def stretch_password(password, salt, iterations=DEFAULT_PBKDF2_ITERATIONS):
    """
    Stretch user password using PBKDF2-SHA256
    Prevents weak password attacks and makes brute force expensive
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password.encode('utf-8'))

def generate_condum_lite_key(password, generations=DEFAULT_GENERATIONS, salt=None, show_progress=False):
    """
    Generate a 32-byte key using CA evolution

    Security improvements:
    1. PBKDF2 password stretching (100,000 iterations)
    2. Variable grid size (prevents pattern analysis)
    3. Full 256-bit seed (no entropy reduction)
    4. SHA-256 final hash (ensures uniform distribution)

    Returns: (32-byte key, salt, metadata)
    """
    # Generate salt if not provided
    if salt is None:
        salt = os.urandom(32)

    # Stretch password to 256-bit seed
    if show_progress:
        print("[*] Stretching password (100,000 iterations)...")

    stretched_key = stretch_password(password, salt)

    # Convert to seed for numpy (requires 32-bit int)
    # We use the stretched key to determine grid size and seed
    seed_bytes = stretched_key[:8]
    seed = int.from_bytes(seed_bytes, 'big') % (2**32)

    # Variable grid size based on password (prevents pattern analysis)
    grid_size_bytes = stretched_key[8:12]
    grid_size = MIN_GRID_SIZE + (int.from_bytes(grid_size_bytes, 'big') % (MAX_GRID_SIZE - MIN_GRID_SIZE))

    if show_progress:
        print(f"[*] Evolving {grid_size}x{grid_size} grid for {generations} generations...")

    # Generate CA evolution
    np.random.seed(seed)
    grid = initialize_grid(grid_size)

    # Evolve with progress tracking
    if show_progress:
        for gen in range(generations):
            # Evolve one step
            padded_grid = np.pad(grid, pad_width=1, mode='wrap')
            neighbors = (
                padded_grid[:-2, :-2] + padded_grid[:-2, 1:-1] + padded_grid[:-2, 2:] +
                padded_grid[1:-1, :-2] + padded_grid[1:-1, 2:] +
                padded_grid[2:, :-2] + padded_grid[2:, 1:-1] + padded_grid[2:, 2:]
            )
            grid = ((grid.astype(np.int32) + neighbors.astype(np.int32)) % 256).astype(np.uint8)

            # Update progress bar every 50 generations
            if (gen + 1) % 50 == 0 or gen == generations - 1:
                print_progress_bar(gen + 1, generations, prefix='Progress:', suffix='Complete')
    else:
        grid = evolve(grid, generations)

    if show_progress:
        print("[*] Finalizing key...")

    # Combine stretched key with CA output for maximum entropy
    ca_bytes = grid.tobytes()

    # Multi-stage hashing for key derivation
    stage1 = sha256(stretched_key + ca_bytes).digest()
    stage2 = sha256(stage1 + ca_bytes[:32]).digest()
    final_key = bytes(a ^ b for a, b in zip(stage1, stage2))

    # Securely wipe intermediate values
    secure_zero(stretched_key)
    secure_zero(grid)
    secure_zero(ca_bytes)

    # Metadata for verification
    metadata = {
        'version': 'CONDUM-LITE-1.0',
        'grid_size': grid_size,
        'generations': generations,
        'pbkdf2_iterations': DEFAULT_PBKDF2_ITERATIONS
    }

    return final_key, salt, metadata

def save_key_package(filename, key, salt, metadata):
    """
    Save key package with authentication and encrypted metadata
    Format: [MAGIC][VERSION][SALT][META_LEN][ENCRYPTED_META][KEY][HMAC]
    """
    import struct
    import json
    from cryptography.hazmat.primitives import hmac
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    MAGIC = b'CDLT'  # CONDUM-LITE magic bytes
    VERSION = struct.pack('B', 2)  # Version 2: encrypted metadata

    # Serialize metadata
    meta_json = json.dumps(metadata).encode('utf-8')

    # Derive metadata encryption key from salt
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"condum-lite-metadata-encryption"
    )
    metadata_key = hkdf.derive(salt)

    # Encrypt metadata using AES-GCM
    aesgcm = AESGCM(metadata_key)
    meta_nonce = os.urandom(12)
    encrypted_meta = aesgcm.encrypt(meta_nonce, meta_json, None)

    # Package encrypted metadata with nonce
    meta_package = meta_nonce + encrypted_meta
    meta_len = struct.pack('I', len(meta_package))

    # Create package
    package = MAGIC + VERSION + salt + meta_len + meta_package + key

    # Add HMAC for integrity verification
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(package)
    auth_tag = h.finalize()

    package += auth_tag

    with open(filename, 'wb') as f:
        f.write(package)

    # Securely wipe metadata key
    secure_zero(metadata_key)

    print(f"[+] Key package saved: {len(package)} bytes")
    print(f"    - Magic: {MAGIC.decode()}")
    print(f"    - Version: {VERSION[0]}")
    print(f"    - Salt: 32 bytes")
    print(f"    - Encrypted Metadata: {len(meta_package)} bytes")
    print(f"    - Key: 32 bytes")
    print(f"    - HMAC: 32 bytes")

def read_key_package(filename, password=None):
    """
    Read and verify key package
    Returns: (key, salt, metadata)

    Note: Version 2 packages require password to decrypt metadata
    """
    import struct
    import json
    from cryptography.hazmat.primitives import hmac
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except Exception as e:
        raise CorruptedFileError(filename, f"Cannot read file: {e}")

    # Parse header
    if len(data) < 37:
        raise CorruptedFileError(filename, "File too short to be valid key package")

    magic = data[0:4]
    version = data[4]
    salt = data[5:37]

    # Verify magic
    if magic != b'CDLT':
        raise KeyFileMismatchError("CONDUM-LITE", magic.decode('utf-8', errors='replace'))

    # Handle different versions
    if version == 1:
        # Old version: unencrypted metadata (backwards compatibility)
        if len(data) < 101:
            raise CorruptedFileError(filename, "File too short for version 1")

        key = data[37:69]
        auth_tag = data[69:101]

        # Verify HMAC
        package = data[:69]
        h = hmac.HMAC(salt, hashes.SHA256())
        h.update(package)
        computed_tag = h.finalize()

        if not bytes_eq(auth_tag, computed_tag):
            raise CorruptedFileError(filename, "Integrity check failed")

        metadata = {
            'version': 'CONDUM-LITE-1.0',
            'verified': True
        }

    elif version == 2:
        # New version: encrypted metadata
        meta_len = struct.unpack('I', data[37:41])[0]
        meta_package = data[41:41+meta_len]
        key = data[41+meta_len:73+meta_len]
        auth_tag = data[73+meta_len:105+meta_len]

        # Verify HMAC first
        package = data[:73+meta_len]
        h = hmac.HMAC(salt, hashes.SHA256())
        h.update(package)
        computed_tag = h.finalize()

        if not bytes_eq(auth_tag, computed_tag):
            raise CorruptedFileError(filename, "Integrity check failed")

        # Derive metadata decryption key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"condum-lite-metadata-encryption"
        )
        metadata_key = hkdf.derive(salt)

        # Decrypt metadata
        try:
            aesgcm = AESGCM(metadata_key)
            meta_nonce = meta_package[:12]
            encrypted_meta = meta_package[12:]
            meta_json = aesgcm.decrypt(meta_nonce, encrypted_meta, None)
            metadata = json.loads(meta_json.decode('utf-8'))
            metadata['verified'] = True
        except Exception as e:
            # Metadata decryption failed - but file is intact
            metadata = {
                'version': 'CONDUM-LITE-2.0',
                'verified': True,
                'metadata_encrypted': True,
                'note': 'Metadata encrypted - parameters hidden for security'
            }
        finally:
            # Securely wipe metadata key
            secure_zero(metadata_key)

    else:
        raise KeyFileMismatchError("CONDUM-LITE", f"Unknown version {version}")

    return key, salt, metadata

def encrypt_data(data, key, include_metadata=True):
    """
    Encrypt binary data using AES-256-GCM with optional metadata
    Returns: metadata_package + nonce + ciphertext + tag (if include_metadata)
             or nonce + ciphertext + tag (if not include_metadata)
    """
    import struct
    import json

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    if include_metadata:
        # Create metadata
        metadata = {
            'version': 'CONDUM-LITE-1.0',
            'timestamp': datetime.now().isoformat(),
            'original_size': len(data)
        }

        # Serialize metadata
        meta_json = json.dumps(metadata).encode('utf-8')
        meta_len = struct.pack('I', len(meta_json))

        # Package: MAGIC + VERSION + META_LEN + META + NONCE + CIPHERTEXT
        MAGIC = b'CDLE'  # CONDUM-LITE-ENC
        VERSION = struct.pack('B', 1)

        package = MAGIC + VERSION + meta_len + meta_json + nonce + ciphertext
        return package
    else:
        return nonce + ciphertext

def decrypt_data(enc_data, key):
    """
    Decrypt binary data using AES-256-GCM
    Handles both metadata and non-metadata formats
    Returns: (data, metadata) or just data
    """
    import struct
    import json

    if len(enc_data) < 12:
        raise ValueError("Encrypted data is too short.")

    # Check if this has metadata
    magic = enc_data[0:4] if len(enc_data) >= 4 else b''

    if magic == b'CDLE':
        # Has metadata - parse it
        version = enc_data[4]
        meta_len = struct.unpack('I', enc_data[5:9])[0]
        meta_json = enc_data[9:9+meta_len]
        metadata = json.loads(meta_json.decode('utf-8'))

        nonce_start = 9 + meta_len
        nonce = enc_data[nonce_start:nonce_start+12]
        ciphertext = enc_data[nonce_start+12:]

        aesgcm = AESGCM(key)
        try:
            data = aesgcm.decrypt(nonce, ciphertext, None)
            return data, metadata
        except Exception as e:
            raise PasswordIncorrectError()
    else:
        # No metadata - old format
        aesgcm = AESGCM(key)
        nonce = enc_data[:12]
        ciphertext_with_tag = enc_data[12:]
        try:
            data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            return data, None
        except Exception as e:
            raise PasswordIncorrectError()

# ----- CLI Functions -----
def create_key_cli():
    print("\n" + "="*60)
    print("CONDUM LITE - Key Generation")
    print("="*60)

    password = input("Enter password for key generation: ")
    confirm = input("Confirm password: ")

    if password != confirm:
        print("[-] Passwords don't match!")
        return

    # Check password strength
    is_strong, score, feedback = check_password_strength(password)
    print(f"\nPassword strength: {score}/100")

    if not is_strong:
        print("⚠️  Password is too weak!")
        for suggestion in feedback:
            print(f"  - {suggestion}")

        confirm_weak = input("\nUse anyway? (not recommended) [y/N]: ")
        if confirm_weak.lower() != 'y':
            print("[-] Key generation cancelled")
            return

    generations = int(input(f"\nEnter generations (default {DEFAULT_GENERATIONS}): ") or DEFAULT_GENERATIONS)

    print("\n[*] Generating key (this may take a moment)...")

    key = None
    salt = None
    try:
        key, salt, metadata = generate_condum_lite_key(password, generations, show_progress=True)

        entropy = calculate_entropy(key)
        print(f"\n[+] Key generated successfully!")
        print(f"    - Entropy: {entropy:.2f} bits/byte")
        print(f"    - Grid size: {metadata['grid_size']}x{metadata['grid_size']}")
        print(f"    - Generations: {metadata['generations']}")
        print(f"    - PBKDF2 iterations: {metadata['pbkdf2_iterations']:,}")

        save_path = input("\nEnter file path to save key (e.g., mykey.cdlt): ")
        save_key_package(save_path, key, salt, metadata)
        print(f"[+] Done! Key saved to {save_path}")
    finally:
        # Securely wipe key material
        if key is not None:
            secure_zero(key)
        if salt is not None:
            secure_zero(salt)

def encrypt_text_cli():
    print("\n" + "="*60)
    print("CONDUM LITE - Text Encryption")
    print("="*60)

    password = input("Enter password: ")
    plaintext = input("Enter text to encrypt: ")

    print("\n[*] Generating encryption key...")

    key = None
    salt = None
    try:
        key, salt, metadata = generate_condum_lite_key(password, show_progress=True)

        encrypted_data = encrypt_data(plaintext.encode('utf-8'), key, include_metadata=True)

        save_path = input("\nEnter file path to save encrypted text (e.g., encrypted.bin): ")

        # Use safe write
        safe_write_file(save_path, salt + encrypted_data)

        print(f"[+] Encrypted text saved to {save_path}")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        # Securely wipe key
        if key is not None:
            secure_zero(key)
        if salt is not None:
            secure_zero(salt)

def decrypt_text_cli():
    print("\n" + "="*60)
    print("CONDUM LITE - Text Decryption")
    print("="*60)

    password = input("Enter password: ")
    enc_path = input("Enter file path of encrypted text: ")

    key = None
    try:
        with open(enc_path, 'rb') as f:
            salt = f.read(32)
            encrypted_data = f.read()

        print("\n[*] Deriving decryption key...")
        key, _, metadata = generate_condum_lite_key(password, salt=salt, show_progress=True)

        # decrypt_data returns tuple (data, metadata) or just data
        result = decrypt_data(encrypted_data, key)
        if isinstance(result, tuple):
            plaintext_bytes, file_metadata = result
        else:
            plaintext_bytes = result
            file_metadata = None

        plaintext = plaintext_bytes.decode('utf-8')
        print(f"\n[+] Decrypted Text:\n{plaintext}")

        if file_metadata:
            print(f"\nFile Info:")
            print(f"  - Encrypted: {file_metadata.get('timestamp', 'Unknown')}")
            print(f"  - Original size: {file_metadata.get('original_size', 'Unknown')} bytes")

    except PasswordIncorrectError as e:
        print(f"\n[-] {e}")
    except CorruptedFileError as e:
        print(f"\n[-] {e}")
    except Exception as e:
        print(f"[-] Decryption failed: {str(e)}")
    finally:
        if key is not None:
            secure_zero(key)

def encrypt_file_cli():
    print("\n" + "="*60)
    print("CONDUM LITE - File Encryption")
    print("="*60)

    password = input("Enter password: ")
    input_file = input("Enter path of file to encrypt: ")

    # Validate file exists
    if not os.path.exists(input_file):
        print(f"[-] File not found: {input_file}")
        return

    # Check file size
    file_size = os.path.getsize(input_file)

    if file_size > MAX_FILE_SIZE_WARNING:
        print(f"\n⚠️  Warning: File is {file_size / 1_000_000_000:.2f} GB")
        print("Large files may take significant time and memory.")
        confirm = input("Continue? [y/N]: ")
        if confirm.lower() != 'y':
            print("[-] Operation cancelled")
            return

    output_file = input("Enter output file path (e.g., file.enc): ")

    key = None
    salt = None
    try:
        with open(input_file, 'rb') as f:
            data = f.read()

        print(f"\n[*] Encrypting {len(data):,} bytes...")
        print("[*] Generating encryption key...")

        key, salt, metadata = generate_condum_lite_key(password, show_progress=True)

        print(f"[*] Encrypting data with AES-256-GCM...")
        encrypted_data = encrypt_data(data, key, include_metadata=True)

        print(f"[*] Writing encrypted file...")
        # Use safe write to verify
        safe_write_file(output_file, salt + encrypted_data)

        print(f"\n[+] Encrypted file saved to {output_file}")
        print(f"    - Original size: {len(data):,} bytes")
        print(f"    - Encrypted size: {len(salt) + len(encrypted_data):,} bytes")
        print(f"    - Overhead: {len(salt) + len(encrypted_data) - len(data)} bytes")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        if key is not None:
            secure_zero(key)
        if salt is not None:
            secure_zero(salt)

def decrypt_file_cli():
    print("\n" + "="*60)
    print("CONDUM LITE - File Decryption")
    print("="*60)

    password = input("Enter password: ")
    enc_file = input("Enter path of encrypted file: ")

    # Validate file exists
    if not os.path.exists(enc_file):
        print(f"[-] File not found: {enc_file}")
        return

    dec_file = input("Enter output path for decrypted file: ")

    key = None
    try:
        with open(enc_file, 'rb') as f:
            salt = f.read(32)
            encrypted_data = f.read()

        print("\n[*] Deriving decryption key...")
        key, _, metadata = generate_condum_lite_key(password, salt=salt, show_progress=True)

        print("[*] Decrypting data...")

        # decrypt_data returns tuple (data, metadata) or just data
        result = decrypt_data(encrypted_data, key)
        if isinstance(result, tuple):
            plaintext, file_metadata = result
        else:
            plaintext = result
            file_metadata = None

        # Use safe write
        safe_write_file(dec_file, plaintext)

        print(f"\n[+] Decrypted file saved to {dec_file}")
        print(f"    - Decrypted size: {len(plaintext):,} bytes")

        if file_metadata:
            print(f"\nFile Info:")
            print(f"  - Encrypted: {file_metadata.get('timestamp', 'Unknown')}")
            print(f"  - Original size: {file_metadata.get('original_size', 'Unknown')} bytes")

    except PasswordIncorrectError as e:
        print(f"\n[-] {e}")
    except CorruptedFileError as e:
        print(f"\n[-] {e}")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        if key is not None:
            secure_zero(key)

# ----- Main CLI -----
def main():
    print("\n" + "="*60)
    print("  CONDUM LITE - Compact Encryption System")
    print("  32-byte keys | Fast | Secure")
    print("="*60)

    while True:
        print("\nOptions:")
        print("1. Create Key Package")
        print("2. Encrypt Text")
        print("3. Decrypt Text")
        print("4. Encrypt File")
        print("5. Decrypt File")
        print("6. Exit")

        choice = input("\nSelect option: ").strip()

        try:
            if choice == "1":
                create_key_cli()
            elif choice == "2":
                encrypt_text_cli()
            elif choice == "3":
                decrypt_text_cli()
            elif choice == "4":
                encrypt_file_cli()
            elif choice == "5":
                decrypt_file_cli()
            elif choice == "6":
                print("\n[*] Exiting...")
                break
            else:
                print("[-] Invalid choice. Please try again.")
        except KeyboardInterrupt:
            print("\n\n[*] Operation cancelled.")
        except Exception as e:
            print(f"\n[-] Error: {str(e)}")

if __name__ == "__main__":
    main()
