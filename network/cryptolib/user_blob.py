import base64
import json

from network.cryptolib.primitives import (
    hkdf, aead_encrypt_with_random_nonce, aead_decrypt_with_random_nonce,
)


BLOB_KEY_INFO_PREFIX = b'PhantomChats/UserBlob/v1/'


class UserBlobError(Exception):
    pass


def _derive_blob_key(master_key, kind):
    if not isinstance(kind, str) or not kind:
        raise UserBlobError('kind is required')
    info = BLOB_KEY_INFO_PREFIX + kind.encode('utf-8')
    return hkdf(ikm=bytes(master_key), salt=b'\x00' * 32, info=info, length=32)


def encrypt_user_blob(master_key, kind, payload):
    key = _derive_blob_key(master_key, kind)
    plaintext = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')
    blob = aead_encrypt_with_random_nonce(key, plaintext)
    nonce = blob[:12]
    ct = blob[12:]
    return {
        'ciphertext': base64.b64encode(ct).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii'),
    }


def decrypt_user_blob(master_key, kind, server_blob):
    if not isinstance(server_blob, dict):
        raise UserBlobError('server_blob must be a dict')
    ct_b64 = server_blob.get('ciphertext')
    nonce_b64 = server_blob.get('nonce')
    if not ct_b64 or not nonce_b64:
        raise UserBlobError('server_blob missing ciphertext/nonce')
    try:
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)
    except Exception as exc:
        raise UserBlobError(f'base64 decode failed: {exc}')
    key = _derive_blob_key(master_key, kind)
    try:
        plaintext = aead_decrypt_with_random_nonce(key, nonce + ct)
    except Exception as exc:
        raise UserBlobError(f'blob decryption failed: {exc}')
    try:
        return json.loads(plaintext.decode('utf-8'))
    except Exception as exc:
        raise UserBlobError(f'blob is not JSON: {exc}')
