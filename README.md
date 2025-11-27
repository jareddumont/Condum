# CONDUM - Cellular Automata Key Derivation System

A novel cryptographic key derivation system that leverages cellular automata (CA) evolution to generate secure encryption keys for AES-256 encryption.

## Overview

CONDUM (Cellular Automata-based Key Derivation) offers two implementations:

### CONDUM LITE
A compact key derivation function that uses CA evolution to generate 32-byte keys compatible with AES-256 encryption.

**Features:**
- PBKDF2 password stretching (100,000 iterations)
- Variable grid sizes (32x32 to 128x128) to prevent pattern analysis
- Full 256-bit seed with no entropy reduction
- SHA-256 final hash for uniform distribution
- AES-256-GCM encryption for data protection
- Secure memory wiping of sensitive data
- Password strength validation
- File integrity verification

**Use Cases:**
- Standalone encryption tool
- Secure file encryption
- Text encryption
- Key package generation and storage

### CONDUM HYBRID
Combines CA-based master keys with fast session keys for optimal security and performance.

**Architecture:**
1. **Master Key:** Generated using CA evolution (slow, done once)
2. **Session Keys:** Standard 32-byte keys (fast, rotatable)
3. **Data Encryption:** AES-256-GCM with session keys
4. **Key Wrapping:** Session keys encrypted with master key

**Benefits:**
- CA complexity for master key security
- Fast session key rotation
- Forward secrecy support
- Compatible with key ratcheting
- Ideal for both offline storage and active use

## Installation

### Requirements
- Python 3.7+
- NumPy
- Cryptography library

### Install Dependencies
```bash
pip install numpy cryptography
```

## Usage

### CONDUM LITE

Run the interactive CLI:
```bash
python condum_lite.py
```

**Available Operations:**
1. Create Key Package
2. Encrypt Text
3. Decrypt Text
4. Encrypt File
5. Decrypt File

**Example - File Encryption:**
```bash
# Run the program
python condum_lite.py

# Select option 4 (Encrypt File)
# Enter a strong password
# Specify input file path
# Specify output file path
```

### CONDUM HYBRID

Run the interactive CLI:
```bash
python condum_hybrid.py
```

**Available Operations:**
1. Create Master Key
2. Encrypt File
3. Decrypt File
4. Encrypt Text
5. Decrypt Text

**Example - Master Key Creation:**
```bash
# Run the program
python condum_hybrid.py

# Select option 1 (Create Master Key)
# Enter a strong master password
# Save the master key securely (e.g., master.cdhb)
```

## Security Features

### Password Protection
- Minimum 12-character passwords recommended
- Password strength scoring system
- Warnings for weak passwords

### Key Derivation
- PBKDF2-HMAC-SHA256 with 100,000 iterations
- Variable grid sizes prevent pattern analysis
- Multi-stage hashing for maximum entropy

### Encryption
- AES-256-GCM authenticated encryption
- Unique nonces for each encryption
- HMAC authentication for integrity verification
- Secure memory wiping of sensitive data

### Error Handling
- Custom exceptions for clear error messages
- File integrity verification
- Corruption detection
- Password mismatch detection

## File Formats

### CONDUM LITE Key Package (.cdlt)
```
[MAGIC: CDLT][VERSION][SALT][META_LEN][ENCRYPTED_META][KEY][HMAC]
```

### CONDUM HYBRID Master Key (.cdhb)
```
[MAGIC: CDHB][VERSION][SALT][MASTER_KEY][META_LEN][METADATA][HMAC]
```

### Encrypted Files
Contains salt, wrapped session key (hybrid), and AES-GCM encrypted data with metadata.

## Security Considerations

### Best Practices
- Use strong, unique passwords (12+ characters with mixed case, numbers, and symbols)
- Store master keys in encrypted storage (USB drives, password managers)
- Never transmit master keys over insecure channels
- Make encrypted backups of master keys
- Rotate session keys regularly (HYBRID mode)

### Limitations
- Key derivation is computationally intensive by design (defense against brute force)
- Large files may require significant memory
- CA evolution adds overhead to key generation time

### Warning
This is a novel cryptographic approach. While it implements standard cryptographic primitives (AES-256-GCM, PBKDF2, HMAC), the CA-based key derivation is experimental. For production use, consider:
- Independent security audit
- Peer review of the CA evolution algorithm
- Compliance with organizational security policies

## Technical Details

### Cellular Automata Evolution
The system uses a 2D grid of bytes (0-255) that evolves over multiple generations using neighborhood rules:

```python
# Each cell is updated based on sum of 8 neighbors
new_value = (current_value + sum_of_neighbors) % 256
```

Grid evolution parameters:
- **LITE:** 32x32 to 128x128 grid, 500 generations (default)
- **HYBRID:** 64x64 grid, 200 generations (default)

### Entropy Analysis
Keys are validated using Shannon entropy calculation to ensure high randomness.

## Performance

### CONDUM LITE
- Key generation: ~2-5 seconds (depending on grid size and generations)
- File encryption: Fast (AES-GCM native speed)
- File decryption: Fast (AES-GCM native speed)

### CONDUM HYBRID
- Master key generation: ~5-10 seconds (done once)
- Session key generation: <1ms
- File encryption: Fast (session key encryption)
- File decryption: Fast (session key decryption)

## Contributing

Contributions are welcome! Areas of interest:
- Security analysis and testing
- Performance optimization
- Additional CA evolution rules
- Cross-platform testing
- Documentation improvements

## License

[Specify your license here - see LICENSE file]

## Disclaimer

This software is provided as-is for educational and research purposes. Users are responsible for:
- Evaluating security for their specific use case
- Maintaining secure backups of keys and encrypted data
- Understanding the experimental nature of CA-based key derivation

**DO NOT use for critical applications without thorough security review.**


---

**Status:** Experimental
**Version:** 1.0
**Last Updated:** 2025
