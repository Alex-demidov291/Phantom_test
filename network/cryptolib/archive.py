import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from network.cryptolib.primitives import hkdf, AEAD_NONCE_LEN


ARCHIVE_KEY_INFO = b'PhantomChats/Archive/v1'
ARCHIVE_HANDLE_INFO = b'PhantomChats/Archive/Handle/v1'


def derive_archive_key(master_key):
    return hkdf(ikm=bytes(master_key), salt=b'\x00' * 32,
                info=ARCHIVE_KEY_INFO, length=32)


def derive_archive_handle_key(master_key):
    return hkdf(ikm=bytes(master_key), salt=b'\x00' * 32,
                info=ARCHIVE_HANDLE_INFO, length=32)


def compute_archive_peer_handle(master_key, peer_login):
    if not isinstance(peer_login, str):
        raise TypeError('peer_login must be str')
    handle_key = derive_archive_handle_key(master_key)
    digest = hmac.new(handle_key, peer_login.encode('utf-8'),
                      hashlib.sha256).digest()
    return base64.b64encode(digest).decode('ascii')


def archive_encrypt(master_key, payload):
    key = derive_archive_key(master_key)
    nonce = os.urandom(AEAD_NONCE_LEN)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        'ciphertext': base64.b64encode(ct).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
    }


def archive_decrypt(master_key, ciphertext_b64, nonce_b64):
    key = derive_archive_key(master_key)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    plaintext = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(plaintext.decode('utf-8'))
