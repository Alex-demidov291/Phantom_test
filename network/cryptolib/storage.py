import json
import os
import tempfile

from network.cryptolib.primitives import (
    hkdf, aead_encrypt_with_random_nonce, aead_decrypt_with_random_nonce,
)


PREKEY_KEY_INFO = b'PhantomChats/Storage/PreKeys/v2'
SESSION_KEY_INFO = b'PhantomChats/Storage/Session/v2'
CHECKPOINT_KEY_INFO = b'PhantomChats/Storage/Checkpoint/v1'


def _derive_storage_key(master_key, info):
    return hkdf(ikm=bytes(master_key), salt=b'\x00' * 32, info=info, length=32)


def _atomic_write_bytes(path, data):
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix='.tmp_', suffix='.bin')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def encrypt_and_write(path, master_key, info, obj):
    key = _derive_storage_key(master_key, info)
    plaintext = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    blob = aead_encrypt_with_random_nonce(key, plaintext)
    _atomic_write_bytes(path, blob)


def read_and_decrypt(path, master_key, info):
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        blob = f.read()
    key = _derive_storage_key(master_key, info)
    plaintext = aead_decrypt_with_random_nonce(key, blob)
    return json.loads(plaintext.decode('utf-8'))


def _safe_segment(name, fallback='unknown'):
    safe = ''.join(c for c in (name or '') if c.isalnum() or c in '-_')[:64]
    return safe or fallback


def crypto_root_dir(own_login):
    from utils import DATA_PATH
    p = DATA_PATH / 'crypto' / _safe_segment(own_login)
    p.mkdir(parents=True, exist_ok=True)
    return p


def device_root_dir(own_login, own_device_id):
    p = crypto_root_dir(own_login) / 'devices' / _safe_segment(own_device_id, 'device')
    p.mkdir(parents=True, exist_ok=True)
    return p


def prekey_store_path(own_login, own_device_id):
    return device_root_dir(own_login, own_device_id) / 'prekeys.bin'


def sessions_root_dir(own_login, own_device_id):
    p = device_root_dir(own_login, own_device_id) / 'sessions'
    p.mkdir(parents=True, exist_ok=True)
    return p


def session_path(own_login, own_device_id, peer_login, peer_device_id):
    sessions_dir = sessions_root_dir(own_login, own_device_id)
    fname = f'{_safe_segment(peer_login)}__{_safe_segment(peer_device_id, "device")}.bin'
    return sessions_dir / fname


def trust_path(own_login):
    return crypto_root_dir(own_login) / 'trust.json'


def checkpoint_path(own_login, own_device_id):
    return device_root_dir(own_login, own_device_id) / 'checkpoint.bin'


def load_message_checkpoint(own_login, own_device_id, master_key):
    path = str(checkpoint_path(own_login, own_device_id))
    try:
        data = read_and_decrypt(path, master_key, CHECKPOINT_KEY_INFO)
    except Exception:
        return {}
    return data or {}


def save_message_checkpoint(own_login, own_device_id, master_key, data):
    path = str(checkpoint_path(own_login, own_device_id))
    encrypt_and_write(path, master_key, CHECKPOINT_KEY_INFO, data)
