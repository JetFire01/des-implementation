# DES implementation in Python

Implementation of the DES (Data Encryption Standard) block cipher: encryption and decryption of a single 64-bit block.

Written for the *Cryptographie et Sécurité* course, Série 6 (TP Python – DES).

## Project structure

```
src/des_implementation/
├── main.py         # DES implementation and test run
└── des_tables.py   # permutation tables (IP, IP⁻¹, PC-1, PC-2, E, P) and S-boxes
```

## Requirements

Python 3 only, no external libraries.

## Usage

```bash
cd src/des_implementation
python3 main.py
```

## Expected output

```
Message (plaintext):    0011223344556677
Key:                    0123456789ABCDEF
Ciphertext reference:   CADB6782EE2B4823

Ciphertext calculated:  CADB6782EE2B4823
Plaintext decrypted:    0011223344556677
```

## How it works

1. **Key schedule.** PC-1 reduces the 64-bit key to 56 bits and splits it into two 28-bit halves C and D. In each of the 16 rounds, C and D are rotated left (1 or 2 bits), then PC-2 selects 48 bits to produce the subkey Kᵢ.
2. **Initial permutation.** IP reorders the 64 message bits, which are then split into L₀ and R₀ (32 bits each).
3. **16 Feistel rounds.**
   - L(i+1) = R(i)
   - R(i+1) = L(i) ⊕ f(R(i), Kᵢ)
   - with f(R, K) = P(S(E(R) ⊕ K)): expansion to 48 bits, XOR with the subkey, 8 S-boxes (48 → 32 bits), permutation P.
4. **Final permutation.** The halves are joined as R₁₆ + L₁₆ (no swap after the last round), then FP = IP⁻¹ is applied.
5. **Decryption.** Same algorithm applied to the ciphertext, with the subkeys in reverse order (K₁₆ … K₁).

Bits are represented as Python lists of `0` / `1`.
