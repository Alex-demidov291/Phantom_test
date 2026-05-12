import os
import hmac
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HASH_LEN = 32
AEAD_KEY_LEN = 32
AEAD_NONCE_LEN = 12


def secure_random(n):
    return os.urandom(n)


def hkdf(ikm, salt, info, length=32):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def kdf_root_key(root_key, dh_out):
    out = hkdf(
        ikm=dh_out,
        salt=root_key,
        info=b'PhantomChats/RootKDF/v1',
        length=64,
    )
    return out[:32], out[32:64]


def kdf_chain_key_step(chain_key):
    new_ck = hmac.new(chain_key, b'\x02', hashlib.sha256).digest()
    mk = hmac.new(chain_key, b'\x01', hashlib.sha256).digest()
    return new_ck, mk


def derive_message_keys(message_key):
    out = hkdf(
        ikm=message_key,
        salt=b'\x00' * 32,
        info=b'PhantomChats/MessageKey/v1',
        length=AEAD_KEY_LEN + AEAD_NONCE_LEN,
    )
    enc_key = out[:AEAD_KEY_LEN]
    nonce = out[AEAD_KEY_LEN:AEAD_KEY_LEN + AEAD_NONCE_LEN]
    return enc_key, nonce


def aead_encrypt(message_key, plaintext, associated_data):
    enc_key, nonce = derive_message_keys(message_key)
    return AESGCM(enc_key).encrypt(nonce, plaintext, associated_data)


def aead_decrypt(message_key, ciphertext, associated_data):
    enc_key, nonce = derive_message_keys(message_key)
    return AESGCM(enc_key).decrypt(nonce, ciphertext, associated_data)


def aead_encrypt_with_random_nonce(key, plaintext, associated_data=None):
    nonce = secure_random(AEAD_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def aead_decrypt_with_random_nonce(key, blob, associated_data=None):
    nonce = blob[:AEAD_NONCE_LEN]
    ct = blob[AEAD_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, associated_data)
