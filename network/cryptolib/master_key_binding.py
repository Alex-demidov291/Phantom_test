import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from network.cryptolib.identity import IdentityKeys
from network.cryptolib.primitives import hkdf


BINDING_DOMAIN = b'PhantomChats/MasterKeyBinding/v1'


class MasterKeyBindingError(Exception):
    pass


def _canonical_blob_bytes(encrypted_master_key):
    if isinstance(encrypted_master_key, (bytes, bytearray)):
        encrypted_master_key = encrypted_master_key.decode('utf-8')
    if isinstance(encrypted_master_key, str):
        encrypted_master_key = json.loads(encrypted_master_key)
    if not isinstance(encrypted_master_key, dict):
        raise MasterKeyBindingError(
            'encrypted_master_key must be a JSON object'
        )
    return json.dumps(
        encrypted_master_key, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')


def _binding_message(login, encrypted_master_key):
    if not isinstance(login, str) or not login:
        raise MasterKeyBindingError('login is required for binding')
    blob_bytes = _canonical_blob_bytes(encrypted_master_key)
    h = hashlib.sha256()
    h.update(BINDING_DOMAIN)
    h.update(b'|')
    h.update(login.encode('utf-8'))
    h.update(b'|')
    h.update(hashlib.sha256(blob_bytes).digest())
    return h.digest()


def _sik_from_master_key(master_key):
    sik_seed = hkdf(
        bytes(master_key), salt=b'',
        info=IdentityKeys.SIK_INFO, length=32,
    )
    return Ed25519PrivateKey.from_private_bytes(sik_seed)


def sign_master_key_binding(master_key, login, encrypted_master_key):
    sik_priv = _sik_from_master_key(master_key)
    msg = _binding_message(login, encrypted_master_key)
    sig = sik_priv.sign(msg)
    sik_pub = sik_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        'signature': base64.b64encode(sig).decode('ascii'),
        'sik_pub': base64.b64encode(sik_pub).decode('ascii'),
    }


def verify_master_key_binding(master_key, login, encrypted_master_key,
                              signature_b64, expected_sik_pub_b64=None):
    if not signature_b64:
        raise MasterKeyBindingError(
            '...'
        )
    try:
        sig = base64.b64decode(signature_b64)
    except Exception as exc:
        raise MasterKeyBindingError(
            f'master_key binding signature is not valid base64: {exc}'
        )

    sik_priv = _sik_from_master_key(master_key)
    derived_sik_pub = sik_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    if expected_sik_pub_b64 is not None:
        try:
            expected = base64.b64decode(expected_sik_pub_b64)
        except Exception as exc:
            raise MasterKeyBindingError(
                f'stored SIK pub isнт valid base64: {exc}'
            )
        a = derived_sik_pub
        b = expected
        if len(a) != len(b):
            n = max(len(a), len(b))
            a = a.ljust(n, b'\x00')
            b = b.ljust(n, b'\x00')
            ok = False
        else:
            ok = hmac.compare_digest(a, b)
        if not ok:
            raise MasterKeyBindingError(
                '...')

    msg = _binding_message(login, encrypted_master_key)
    try:
        Ed25519PublicKey.from_public_bytes(derived_sik_pub).verify(sig, msg)
    except InvalidSignature:
        raise MasterKeyBindingError(
            '...')
    return True
