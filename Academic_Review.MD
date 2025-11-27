# Condum

**A Cellular Automata-Based Key Derivation Function**

*Technical Summary for Academic Review*

---

*Note on naming: "Condum" is a portmanteau of "Conway" (John Conway, creator of the Game of Life) and my name. It is not an acronym.*

---

## Abstract

Condum is a key derivation function that uses cellular automata evolution as a source of deterministic computational complexity. The system stretches user passwords through PBKDF2-HMAC-SHA256 (100,000 iterations), uses the stretched key to seed and evolve a 2D cellular automata grid, then extracts the final key through SHA-256 hashing. This document describes the construction, security properties, and areas where expert review is requested.

---

## 1. Motivation

Standard key derivation functions like PBKDF2, bcrypt, and Argon2 rely primarily on iteration count for computational hardness. Condum explores whether cellular automata evolution can provide an additional dimension of complexity. The hypothesis is that CA evolution exhibits computational irreducibility—the final state cannot be predicted without running the full evolution—potentially providing resistance against certain optimization attacks.

This is an exploratory construction by someone without formal cryptography training. I am seeking expert feedback on whether the approach has merit, what security properties it may or may not provide, and what vulnerabilities may exist that I have not considered.

---

## 2. Construction Overview

### 2.1 High-Level Flow (Lite Version)

The Lite version generates 32-byte keys suitable for AES-256. The derivation process:

1. **Salt generation:** 32 bytes from os.urandom()

2. **Password stretching:** PBKDF2-HMAC-SHA256, 100,000 iterations, produces 32-byte stretched_key

3. **Seed extraction:** First 8 bytes of stretched_key converted to 32-bit integer (mod 2³²) for NumPy seeding

4. **Grid size derivation:** Bytes 8-12 of stretched_key determine grid size in range 32-128

5. **Grid initialization:** NumPy PRNG (seeded above) fills grid with random values 0-255

6. **CA evolution:** 500 generations using additive neighbor rules with toroidal wrapping. Each cell becomes (cell + sum_of_8_neighbors) mod 256

7. **Key extraction:** stage1 = SHA256(stretched_key || grid_bytes), stage2 = SHA256(stage1 || grid_bytes[0:32]), final_key = XOR(stage1, stage2)

### 2.2 Versions

Two versions are provided for review:

- **Lite:** Generates 32-byte keys suitable for AES-256. Faster generation (0.5-2 seconds). Intended for general-purpose encryption. This is the primary implementation.

- **Hybrid:** CA-derived master key with random session keys per encryption. Session keys wrapped with master key using AES-GCM. Provides forward secrecy. Demonstrates architectural application of the core concept.

### 2.3 CA Evolution Rules

The CA uses an additive rule rather than standard Game of Life. Each cell value (0-255) is updated as: new_value = (current_value + sum_of_8_neighbors) mod 256. The grid uses toroidal wrap-around at edges. This differs from Conway's Game of Life (which uses binary states and birth/death rules) but was chosen to work with byte-valued cells and produce high entropy output.

---

## 3. Security Properties (Claimed)

The following properties are intended but not formally proven:

- **Password hardening:** PBKDF2 with 100,000 iterations provides baseline protection against weak passwords before CA processing.

- **Computational irreducibility:** The CA evolution step is hypothesized to resist shortcuts—no way to compute the final state without running all generations. This is the novel claim requiring validation.

- **Variable grid resistance:** Password-dependent grid sizes (32-128 for Lite) prevent precomputation attacks targeting a fixed configuration.

- **Key file authentication:** HMAC-SHA256 protects stored key material against tampering.

- **Memory wiping:** Implementation attempts to securely zero sensitive data after use (best-effort in Python).

---

## 4. Known Limitations and Concerns

- **Novelty without pedigree:** This construction has not undergone peer review or cryptanalysis. It should not be used for production security without expert validation.

- **Seed reduction:** NumPy's PRNG requires a 32-bit seed. The stretched_key is 256 bits, but only 32 bits seed the grid initialization. The remaining entropy is preserved through the grid size derivation and final key extraction, but this reduction may have implications I haven't considered.

- **Non-standard CA rules:** The additive mod-256 rule was chosen pragmatically for byte-valued cells. I don't know if this rule has been analyzed for cryptographic properties.

- **Potential shortcuts:** While additive CA may be irreducible in general, specific initial configurations derived from password hashes might have exploitable structure.

- **Key extraction:** The multi-stage SHA-256 with XOR combination is ad-hoc. I don't know if this properly preserves entropy or introduces weaknesses.

- **Side channels:** The implementation uses standard Python/NumPy and is not hardened against timing or cache-based attacks.

---

## 5. Implementation Details

### 5.1 Dependencies

Python 3.8+, NumPy (grid operations), cryptography library (PBKDF2, AES-GCM, HMAC, HKDF). Encryption uses AES-256-GCM with 12-byte random nonces.

### 5.2 Key Extraction (Lite Version, verbatim from code)

```python
ca_bytes = grid.tobytes()
stage1 = sha256(stretched_key + ca_bytes).digest()
stage2 = sha256(stage1 + ca_bytes[:32]).digest()
final_key = bytes(a ^ b for a, b in zip(stage1, stage2))
```

### 5.3 File Formats

Lite keys use magic bytes 'CDLT', Hybrid master keys use 'CDHB'. Both include version byte, salt, metadata (JSON), and HMAC-SHA256 authentication tag.

---

## 6. Questions for Review

I would appreciate expert perspective on the following:

1. Does the CA evolution step provide any meaningful security beyond what PBKDF2 already provides? Or is it security theater?

2. Is the 32-bit seed reduction for NumPy a critical flaw? The full stretched_key is still used in the final key extraction, but I'm uncertain if this matters.

3. Are there known attacks against additive CA-based constructions?

4. Is the computational irreducibility hypothesis valid for this use case, or are there likely shortcuts for PRNG-derived initial states?

5. Does the key extraction method (SHA256 stages + XOR) properly preserve entropy?

6. What formal security model would be appropriate for analyzing this construction?

7. Are there obvious flaws that would disqualify this approach entirely?

---

## 7. Code Availability

Complete source code is available in this repository.

The repository contains two implementations: the Lite version (primary implementation demonstrating the core key derivation concept) and the Hybrid version (master key + session key architecture with forward secrecy). Both include entropy analysis functions, secure memory wiping, and metadata logging.

---

## 8. Closing Note

I am not a cryptographer or computer scientist. This project emerged from personal interest in cellular automata and encryption. I am not claiming to have invented anything revolutionary—I am genuinely asking whether this approach has any merit or if I am fundamentally misunderstanding something. Any feedback, including "this is completely wrong because X," would be valuable and appreciated.

Thank you for your time and consideration.

---

**Contact:** Jared Dumont

**Repository:** https://github.com/jareddumont/Condum