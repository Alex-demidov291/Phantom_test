import base64
import hashlib
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from network.cryptolib.primitives import hkdf


PAIR_INFO = b'PhantomChats/Pairing/v1'
PAIR_AD = b'PhantomChats/PairingAD/v1'


class PairingError(Exception):
    pass


def generate_pairing_code(n_digits=9):
    return ''.join(str(secrets.randbelow(10)) for _ in range(n_digits))


def pairing_code_hash(code):
    return hashlib.sha256(b'PhantomChats/PairCodeHash/v1|'
                          + code.encode('utf-8')).hexdigest()


def _x25519_pub(b):
    return x25519.X25519PublicKey.from_public_bytes(b)


def gen_pairing_ephemeral():
    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_b, pub_b


def derive_pair_key(own_priv_bytes, peer_pub_bytes, code):
    priv = x25519.X25519PrivateKey.from_private_bytes(own_priv_bytes)
    shared = priv.exchange(_x25519_pub(peer_pub_bytes))
    salt = hashlib.sha256(b'PhantomChats/PairSalt/v1|'
                          + code.encode('utf-8')).digest()
    return hkdf(ikm=shared, salt=salt, info=PAIR_INFO, length=32)


def seal_pairing_bundle(own_priv_bytes, peer_pub_bytes, code, bundle_obj):
    import json
    key = derive_pair_key(own_priv_bytes, peer_pub_bytes, code)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        bundle_obj, ensure_ascii=False, separators=(',', ':'),
    ).encode('utf-8')
    ct = AESGCM(key).encrypt(nonce, plaintext, PAIR_AD)
    return {
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'ct': base64.b64encode(ct).decode('ascii'),
    }


def unseal_pairing_bundle(own_priv_bytes, peer_pub_bytes, code, sealed):
    import json
    if not isinstance(sealed, dict):
        raise PairingError('sealed bundle must be dict')
    try:
        nonce = base64.b64decode(sealed['nonce'])
        ct = base64.b64decode(sealed['ct'])
    except (KeyError, ValueError) as exc:
        raise PairingError(f'malformed sealed bundle: {exc}')
    key = derive_pair_key(own_priv_bytes, peer_pub_bytes, code)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, PAIR_AD)
    except Exception as exc:
        raise PairingError(f'sealed bundle decryption failed: {exc}')
    try:
        return json.loads(plaintext.decode('utf-8'))
    except Exception as exc:
        raise PairingError(f'sealed bundle is not JSON: {exc}')
