import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PBKDF2_ITERATIONS = 600000


class KeyChangedError(Exception):
    def __init__(self, contact_login=None, *args, **kwargs):
        self.contact_login = contact_login
        super().__init__(f"Ключ контакта '{contact_login}' изменился")


def gen_msg_master_key():
    return os.urandom(64)


def encrypt_master_key(master_key, password):
    sol = os.urandom(32)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sol,
                    iterations=PBKDF2_ITERATIONS)
    kluch = kdf.derive(password.encode())
    nonce = os.urandom(12)
    shifr = AESGCM(kluch)
    return {
        'salt': base64.b64encode(sol).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(shifr.encrypt(nonce, master_key, None)).decode('utf-8'),
    }


def decrypt_master_key(encrypted, password):
    sol = base64.b64decode(encrypted['salt'])
    nonce = base64.b64decode(encrypted['nonce'])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sol,
                    iterations=PBKDF2_ITERATIONS)
    kluch = kdf.derive(password.encode())
    shifr = AESGCM(kluch)
    return shifr.decrypt(nonce, base64.b64decode(encrypted['ciphertext']), None)
