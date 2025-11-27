# CONDUM Usage Examples

This guide provides practical examples for using CONDUM LITE and CONDUM HYBRID.

## Table of Contents
- [CONDUM LITE Examples](#condum-lite-examples)
- [CONDUM HYBRID Examples](#condum-hybrid-examples)
- [Best Practices](#best-practices)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)

---

## CONDUM LITE Examples

CONDUM LITE is ideal for standalone encryption without managing separate key files.

### Example 1: Encrypting a Text File

**Scenario:** You want to encrypt a sensitive note.

```bash
# 1. Run CONDUM LITE
python condum_lite.py

# 2. Select option 2 (Encrypt Text)
# 3. Enter your password (e.g., "MySecureP@ssw0rd2024!")
# 4. Enter the text: "This is my secret note."
# 5. Save as: secret_note.bin
```

**Output:**
```
[*] Generating encryption key...
[*] Stretching password (100,000 iterations)...
[*] Evolving 64x64 grid for 500 generations...
Progress: |██████████████████████████████████████████████████| 100.0% Complete
[*] Finalizing key...
[+] Encrypted text saved to secret_note.bin
```

### Example 2: Encrypting a File

**Scenario:** Encrypt a confidential PDF document.

```bash
python condum_lite.py

# Select option 4 (Encrypt File)
# Enter password: Use a strong password
# Enter path of file to encrypt: C:\Documents\contract.pdf
# Enter output file path: C:\Documents\contract.pdf.enc
```

**Result:** Original file remains unchanged, encrypted version saved as `contract.pdf.enc`

### Example 3: Decrypting a File

**Scenario:** Decrypt the previously encrypted contract.

```bash
python condum_lite.py

# Select option 5 (Decrypt File)
# Enter password: [same password used for encryption]
# Enter path of encrypted file: C:\Documents\contract.pdf.enc
# Enter output path for decrypted file: C:\Documents\contract_decrypted.pdf
```

**Important:** Use the EXACT same password. Passwords are case-sensitive!

### Example 4: Creating a Reusable Key Package

**Scenario:** Generate a key that can be reused for multiple encryptions.

```bash
python condum_lite.py

# Select option 1 (Create Key Package)
# Enter password for key generation: MyMasterKey123!
# Confirm password: MyMasterKey123!
# Enter generations (default 500): [press Enter for default]
# Enter file path to save key: my_master_key.cdlt
```

**Use the key package:**
- Store `my_master_key.cdlt` securely (encrypted USB, password manager)
- Back up to multiple secure locations
- Never share over unsecured channels

---

## CONDUM HYBRID Examples

CONDUM HYBRID separates master key generation (slow, done once) from data encryption (fast).

### Example 1: Setting Up Master Key

**Scenario:** Create a master key for ongoing encryption needs.

```bash
python condum_hybrid.py

# Select option 1 (Create Master Key)
# Enter master password: UltraSecure#MasterKey2024
# Confirm password: UltraSecure#MasterKey2024
# Enter generations (default 200): [press Enter]
# Save master key as: master_encryption_key.cdhb
```

**Output:**
```
[*] Generating master key (this may take 5-10 seconds)...
[+] Master key generated!
    - Grid size: 64x64
    - Generations: 200
    - Created: 2025-11-27T10:30:00
[+] Master key saved: master_encryption_key.cdhb
    - Total size: 165 bytes
    - Master key: 32 bytes
    - Metadata: 75 bytes

[!] IMPORTANT: Store this master key securely!
    - Use encrypted storage (USB drive, password manager)
    - Never transmit over insecure channels
    - Make encrypted backups
```

### Example 2: Encrypting Files with Master Key

**Scenario:** Encrypt multiple files quickly using the master key.

```bash
python condum_hybrid.py

# Select option 2 (Encrypt File)
# Enter master key file path: master_encryption_key.cdhb
# Enter master password: UltraSecure#MasterKey2024
# Enter file to encrypt: financial_report_2024.xlsx
# Save encrypted file as: financial_report_2024.enc
```

**Advantages:**
- Session key generated fresh each time (different encryption for same file)
- Fast encryption (no CA evolution during encryption)
- Can encrypt many files with one master key

### Example 3: Encrypting Multiple Files

**Scenario:** Batch encrypt several files.

```bash
# File 1
python condum_hybrid.py
# Option 2, use same master key
# Encrypt: photo1.jpg -> photo1.jpg.enc

# File 2
python condum_hybrid.py
# Option 2, use same master key
# Encrypt: photo2.jpg -> photo2.jpg.enc

# File 3
python condum_hybrid.py
# Option 2, use same master key
# Encrypt: video.mp4 -> video.mp4.enc
```

Each file gets a unique session key, even with the same master key!

### Example 4: Decrypting Files

**Scenario:** Recover encrypted files.

```bash
python condum_hybrid.py

# Select option 3 (Decrypt File)
# Enter master key file path: master_encryption_key.cdhb
# Enter master password: UltraSecure#MasterKey2024
# Enter encrypted file: financial_report_2024.enc
# Save decrypted file as: financial_report_2024_recovered.xlsx
```

---

## Best Practices

### Password Management

**Good Passwords:**
```
✓ MyS3cur3P@ssw0rd!2024
✓ Tr0pic@l-Sunset-79!Beach
✓ C0ffee&D0nuts#Morning
✓ Quantum$Leap%42&Stars
```

**Bad Passwords:**
```
✗ password
✗ 123456
✗ admin
✗ letmein
✗ qwerty
```

### File Organization

**Recommended Structure:**
```
secure_documents/
├── master_keys/
│   ├── master_key_2024.cdhb (encrypted USB drive)
│   └── backup_master_key_2024.cdhb (encrypted backup)
├── encrypted/
│   ├── contract.pdf.enc
│   ├── financial_2024.xlsx.enc
│   └── personal_notes.txt.enc
└── originals/
    ├── contract.pdf (delete after encryption verified)
    ├── financial_2024.xlsx
    └── personal_notes.txt
```

### Workflow for Sensitive Files

1. **Encrypt:**
   ```bash
   python condum_lite.py
   # Encrypt: sensitive.doc -> sensitive.doc.enc
   ```

2. **Verify:**
   ```bash
   python condum_lite.py
   # Decrypt: sensitive.doc.enc -> sensitive_test.doc
   # Compare: sensitive.doc vs sensitive_test.doc
   ```

3. **Secure Deletion (Windows):**
   ```bash
   # Use secure delete tool
   cipher /w:C:\path\to\sensitive.doc
   ```

4. **Secure Deletion (Linux/Mac):**
   ```bash
   shred -vfz -n 7 sensitive.doc
   ```

---

## Common Use Cases

### Use Case 1: Protecting Personal Documents

**Goal:** Encrypt tax returns, passports, medical records.

**Recommended:** CONDUM LITE

**Steps:**
1. Create dedicated folder for encrypted files
2. Encrypt each document with strong password
3. Store encrypted versions in cloud backup
4. Securely delete originals
5. Keep password in password manager

### Use Case 2: Secure File Sharing

**Goal:** Share encrypted file with colleague.

**Steps:**
1. Encrypt file with CONDUM LITE
2. Share encrypted file via email/cloud
3. Share password via separate secure channel (phone, encrypted message)
4. Recipient decrypts with same password

**Security Note:** Password must be shared securely!

### Use Case 3: Long-term Archive Encryption

**Goal:** Encrypt years of photos/videos for archival.

**Recommended:** CONDUM HYBRID

**Steps:**
1. Create master key (keep extremely secure)
2. Encrypt all files using master key
3. Store encrypted files on external drives
4. Back up master key to multiple secure locations
5. Document master key location (encrypted note in password manager)

### Use Case 4: Regular Document Protection

**Goal:** Encrypt work documents daily.

**Recommended:** CONDUM HYBRID

**Steps:**
1. Create master key at start of project
2. Encrypt daily documents with master key
3. Fast encryption (session keys generated automatically)
4. Maintain secure backup of master key

### Use Case 5: Temporary Secret Sharing

**Goal:** Share a password or secret temporarily.

**Steps:**
1. Use CONDUM LITE text encryption
2. Encrypt the secret with a simple agreed-upon password
3. Send encrypted file
4. Share password verbally or via secure channel
5. Recipient decrypts immediately
6. Both parties delete encrypted file

---

## Troubleshooting

### Problem: "Decryption failed - incorrect password"

**Causes:**
- Wrong password
- Typo in password
- Caps Lock enabled
- Extra spaces in password
- Different password than encryption

**Solutions:**
1. Try password again carefully
2. Check Caps Lock
3. Check for spaces at start/end
4. Verify it's the correct password
5. Try password manager autofill

### Problem: "File appears to be corrupted"

**Causes:**
- Incomplete file transfer
- File modified after encryption
- Storage media errors
- Wrong file version

**Solutions:**
1. Re-download/copy file
2. Check file size matches original
3. Try backup copy
4. Check storage drive health

### Problem: Key generation is slow

**This is normal!** Key generation is intentionally slow to resist brute force attacks.

**Typical Times:**
- CONDUM LITE: 2-5 seconds (500 generations)
- CONDUM HYBRID: 5-10 seconds (200 generations)

**If extremely slow (>30 seconds):**
1. Check CPU usage (other programs)
2. Update NumPy to latest version
3. Check Python version (3.7+)
4. Try reducing generations (less secure)

### Problem: "Password is too weak" warning

**Solution:** Create stronger password with:
- At least 12 characters
- Uppercase AND lowercase letters
- Numbers
- Special characters (!@#$%^&*)

**Example:** Change `password123` to `MyS3cur3P@ss2024!`

### Problem: Large file encryption fails

**Causes:**
- File larger than available RAM
- Python memory limits

**Solutions:**
1. Ensure sufficient free RAM (file size × 3)
2. Close other programs
3. Use 64-bit Python
4. Compress file first (ZIP)

---

## Advanced Examples

### Example: Programmatic Use (for developers)

```python
from condum_lite import generate_condum_lite_key, encrypt_data, decrypt_data

# Generate key
password = "MySecurePassword123!"
key, salt, metadata = generate_condum_lite_key(password)

# Encrypt data
data = b"Secret message"
encrypted = encrypt_data(data, key)

# Save salt + encrypted data
with open("encrypted.bin", "wb") as f:
    f.write(salt + encrypted)

# Later: Decrypt
with open("encrypted.bin", "rb") as f:
    salt = f.read(32)
    encrypted = f.read()

key, _, _ = generate_condum_lite_key(password, salt=salt)
decrypted, metadata = decrypt_data(encrypted, key)
print(decrypted.decode())  # "Secret message"
```

### Example: Automated Backup Script

```python
import os
from condum_hybrid import generate_master_key, hybrid_encrypt

# Generate master key once
master_key, salt, metadata = generate_master_key("BackupMaster2024!")

# Encrypt all files in directory
backup_dir = "documents/"
for filename in os.listdir(backup_dir):
    filepath = os.path.join(backup_dir, filename)
    with open(filepath, 'rb') as f:
        data = f.read()

    encrypted = hybrid_encrypt(data, master_key)

    with open(filepath + ".enc", 'wb') as f:
        f.write(encrypted)

    print(f"Encrypted: {filename}")
```

---

## Quick Reference

### CONDUM LITE vs HYBRID

| Feature | LITE | HYBRID |
|---------|------|--------|
| Key Generation Speed | Slow (2-5s) | Master: Slow (5-10s)<br>Session: Fast (<1ms) |
| Best For | One-off encryption | Frequent encryption |
| Reusable Key | Optional | Required |
| Complexity | Simple | Moderate |
| File Format | .cdlt | .cdhb |

### Command Quick Reference

**CONDUM LITE:**
1. Create Key Package
2. Encrypt Text
3. Decrypt Text
4. Encrypt File
5. Decrypt File
6. Exit

**CONDUM HYBRID:**
1. Create Master Key
2. Encrypt File
3. Decrypt File
4. Encrypt Text
5. Decrypt Text
6. Exit

---

## Questions?

- Check [README.md](README.md) for general information
- See [SECURITY.md](SECURITY.md) for security considerations
- Review [CONTRIBUTING.md](CONTRIBUTING.md) for development help
- Open an issue on GitHub for specific problems

**Happy Encrypting! 🔐**
