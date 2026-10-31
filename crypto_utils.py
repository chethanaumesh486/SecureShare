"""
All cryptography for SecureShare lives here (one algorithm, one job).

  AES-256-GCM  -> encrypts the actual file (confidentiality + ciphertext integrity)
  RSA-OAEP     -> wraps the random AES key for the receiver
  SHA-256      -> hashes the whole encrypted package
  RSA-PSS      -> sender signs that hash; receiver verifies it before decrypting
  scrypt+AES   -> protects each user's RSA private key with their password

Key layout by role (the admin has no keys at all, so the admin cannot decrypt):
  sender   -> RSA signing key pair      (private key signs packages)
  receiver -> RSA encryption key pair   (private key unwraps AES keys)
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss

RSA_BITS = 2048


# ---------------------------------------------------------------- RSA keys
def generate_rsa_keypair():
    key = RSA.generate(RSA_BITS)
    return key.publickey().export_key(), key.export_key()


def protect_private_key(private_pem: bytes, password: str) -> bytes:
    """Encrypt a private key under a password-derived key.
    Layout: salt(16) | nonce(16) | tag(16) | ciphertext"""
    salt = get_random_bytes(16)
    kek = scrypt(password.encode(), salt, 32, N=2 ** 15, r=8, p=1)
    cipher = AES.new(kek, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(private_pem)
    return salt + cipher.nonce + tag + ct


def unlock_private_key(blob: bytes, password: str) -> bytes:
    salt, nonce, tag, ct = blob[:16], blob[16:32], blob[32:48], blob[48:]
    kek = scrypt(password.encode(), salt, 32, N=2 ** 15, r=8, p=1)
    return AES.new(kek, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


# ----------------------------------------------------------- AES-256-GCM
def aes_encrypt(plaintext: bytes):
    aes_key = get_random_bytes(32)  # fresh random 256-bit key for every file
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return aes_key, cipher.nonce, tag, ciphertext


def aes_decrypt(aes_key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    return AES.new(aes_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)


# -------------------------------------------------------------- RSA-OAEP
def wrap_key(aes_key: bytes, receiver_public_pem: bytes) -> bytes:
    return PKCS1_OAEP.new(RSA.import_key(receiver_public_pem), hashAlgo=SHA256).encrypt(aes_key)


def unwrap_key(wrapped: bytes, receiver_private_pem: bytes) -> bytes:
    return PKCS1_OAEP.new(RSA.import_key(receiver_private_pem), hashAlgo=SHA256).decrypt(wrapped)


# ------------------------------------------------- SHA-256 + RSA-PSS signature
def package_hash(name, mime, sender, receiver, nonce, tag, wrapped_key, ciphertext):
    """Hash everything in the package, so changing any part breaks the signature."""
    h = SHA256.new()
    for part in (name.encode(), mime.encode(), sender.encode(), receiver.encode(),
                 nonce, tag, wrapped_key, ciphertext):
        h.update(len(part).to_bytes(8, "big"))  # length prefix removes ambiguity
        h.update(part)
    return h


def sign(h, sender_private_pem: bytes) -> bytes:
    return pss.new(RSA.import_key(sender_private_pem)).sign(h)


def verify(h, signature: bytes, sender_public_pem: bytes) -> bool:
    try:
        pss.new(RSA.import_key(sender_public_pem)).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def sha256_hex(data: bytes) -> str:
    return SHA256.new(data).hexdigest()
