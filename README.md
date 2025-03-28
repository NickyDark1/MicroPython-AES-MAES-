# MicroPython AES (MAES)

An optimized implementation of the AES (Advanced Encryption Standard) encryption algorithm for MicroPython, designed to be memory-efficient and performant, especially on resource-constrained devices.

## Features

- Support for 128, 192, and 256-bit keys (AES-128, AES-192, AES-256)
- Implementation of encryption modes:
  - ECB (Electronic Codebook) - *Note: not recommended for production use*
  - CBC (Cipher Block Chaining)
- PKCS#7 padding functions to handle input data of any length
- Optimized for MicroPython with efficient memory usage
- Compliant with the PEP-272 API for compatibility with other implementations

## Requirements

- MicroPython 1.9.4 or higher
- Required modules:
  - `ubinascii` (included in MicroPython)
  - `array` (included in MicroPython)
  - `micropython` (included in MicroPython)

## Installation

Copy the `maes_optimized.py` and `maes_padding.py` files to your MicroPython device. You can use tools like `ampy`, `rshell`, or the Thonny plugin for MicroPython.

```bash
ampy --port /dev/ttyUSB0 put maes_optimized.py
ampy --port /dev/ttyUSB0 put maes_padding.py
```

## Usage

### Import the modules

```python
import maes_optimized
import maes_padding
```

### Encrypt data

```python
# Define key and initialization vector
key = b'0123456789abcdef'  # 16-byte key (AES-128)
iv = b'abcdefghijklmnop'   # Initialization vector for CBC

# Create a cipher instance in CBC mode
cipher = maes_optimized.new(key, maes_optimized.MODE_CBC, iv)

# Text to encrypt
plaintext = b'This is a secret message'

# Apply padding to ensure length is a multiple of 16
padded_plaintext = maes_padding.pad(plaintext)

# Encrypt data
encrypted = cipher.encrypt(padded_plaintext)
```

### Decrypt data

```python
# Create a new instance for decryption
cipher = maes_optimized.new(key, maes_optimized.MODE_CBC, iv)

# Decrypt data
decrypted = cipher.decrypt(encrypted)

# Remove padding to get the original text
original = maes_padding.unpad(decrypted)

# Convert to readable text if needed
text = maes_padding.decode(original)
print(text)  # "This is a secret message"
```

## Complete example

```python
import maes_optimized
import maes_padding

# Create an AES cipher instance in CBC mode
key = b'0123456789abcdef'  # 16-byte key (AES-128)
iv = b'abcdefghijklmnop'   # Initialization vector for CBC
cipher = maes_optimized.new(key, maes_optimized.MODE_CBC, iv)

# Original text
plaintext = b'This is a secret phrase'

# Apply padding to ensure length is a multiple of 16
padded_plaintext = maes_padding.pad(plaintext)

# Encrypt data
encrypted = cipher.encrypt(padded_plaintext)
print(f"Encrypted: {encrypted}")

# Create a new instance for decryption
cipher = maes_optimized.new(key, maes_optimized.MODE_CBC, iv)

# Decrypt data
decrypted = cipher.decrypt(encrypted)

# Remove padding to get the original text
original = maes_padding.unpad(decrypted)

print(f"Decrypted (bytes): {original}")
print(f"Original text: {maes_padding.decode(original)}")
```

## Performance considerations

This implementation uses several optimization techniques to improve performance on resource-constrained devices:

- Pre-calculated tables for S-box and GF(2^8) operations
- Use of `array` instead of lists for more efficient memory handling
- Use of `__slots__` to reduce memory consumption in classes
- Use of `const()` to optimize constants

## Encryption modes

### MODE_ECB (Electronic Codebook)

This mode applies the encryption function to each block individually without feedback.

⚠️ **Warning**: ECB is not secure for almost all production purposes, as identical patterns in the input data produce identical patterns in the encrypted data.

### MODE_CBC (Cipher Block Chaining)

In this mode, each plaintext block is combined (via XOR) with the preceding ciphertext block, which helps hide patterns and improve security.
