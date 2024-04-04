import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256


def generate_nonce(length=16):
    return os.urandom(length).hex()

def encrypt_message(plaintext, key_str):
    # Hash the key_str to ensure it's the correct size for AES-256
    key = SHA256.new(key_str.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    # The plaintext needs to be padded to make it a multiple of the block size.
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(padded_plaintext)
    return encrypted_message  # Returns byte string

def decrypt_message(encrypted_message, key_str):
    # Hash the key_str to ensure it's the correct size for AES-256
    key = SHA256.new(key_str.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    # Remove padding
    return unpad(decrypted_padded_message, AES.block_size).decode()

def derive_keys(master_key): # must take in bytes
    # Use HKDF to derive two 256-bit keys
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # Deriving 64 bytes (512 bits), 256 bits for each key
        salt=None,  # Optional: A salt value (recommended)
        info=b'encrypt_and_mac',  # Optional: Application/context-specific info
        backend=default_backend()
    )
    
    key_material = hkdf.derive(master_key)
    
    # Split the derived bytes into two keys
    encryption_key = key_material[:32]
    mac_key = key_material[32:]
    
    return encryption_key.hex(), mac_key.hex()

