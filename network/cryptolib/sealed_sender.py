import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

from network.cryptolib.identity import IdentityKeys
from network.cryptolib.primitives import hkdf


SEAL_INFO = b'PhantomChats/SealedSender/v1'
SEAL_AD = b'PhantomChats/SealedSenderAD/v1'
SEAL_SIG_DOMAIN = b'PhantomChats/SealedSenderSig/v1'


class SealedSenderError(Exception):
    pass


def _b64e(b):
    return base64.b64encode(b).decode('ascii')


def _b64d(s):
    return base64.b64decode(s.encode('ascii') if isinstance(s, str) else s)


def _x25519_pub(b):
    return x25519.X25519PublicKey.from_public_bytes(b)


def _derive_key(eph_priv, recipient_pub_bytes, eph_pub_bytes):
    shared = eph_priv.exchange(_x25519_pub(recipient_pub_bytes))
    salt = hashlib.sha256(eph_pub_bytes + recipient_pub_bytes).digest()
    return hkdf(ikm=shared, salt=salt, info=SEAL_INFO, length=32)


def _sender_cert_message(recipient_user_id, recipient_device_id,
                         inner_wire_bytes):
    h = hashlib.sha256()
    h.update(SEAL_SIG_DOMAIN)
    h.update(b'|')
    h.update(str(int(recipient_user_id)).encode('ascii'))
    h.update(b'|')
    h.update(recipient_device_id.encode('utf-8'))
    h.update(b'|')
    h.update(hashlib.sha256(inner_wire_bytes).digest())
    return h.digest()


def seal_envelope(sender_identity, sender_login, sender_device_id,
                  recipient_user_id, recipient_device_id,
                  recipient_ik_pub_bytes, inner_wire):
    if not isinstance(recipient_ik_pub_bytes, (bytes, bytearray)) \
            or len(recipient_ik_pub_bytes) != 32:
        raise SealedSenderError('recipient IK must be 32 bytes')

    inner_wire_bytes = json.dumps(
        inner_wire, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')

    cert_msg = _sender_cert_message(
        recipient_user_id, recipient_device_id, inner_wire_bytes,
    )
    cert_signature = sender_identity.sign(cert_msg)

    sealed_payload = {
        'sender_login': sender_login,
        'sender_device_id': sender_device_id,
        'sender_ik_pub': _b64e(sender_identity.ik_pub_bytes),
        'sender_sik_pub': _b64e(sender_identity.sik_pub_bytes),
        'cert_signature': _b64e(cert_signature),
        'inner_wire': inner_wire,
    }
    plaintext = json.dumps(
        sealed_payload, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')

    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key = _derive_key(eph_priv, bytes(recipient_ik_pub_bytes), eph_pub_bytes)
    nonce = os.urandom(12)
    ad = (SEAL_AD + b'|'
          + str(int(recipient_user_id)).encode('ascii') + b'|'
          + recipient_device_id.encode('utf-8') + b'|'
          + eph_pub_bytes)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, ad)

    return {
        'v': 1,
        'eph_pub': _b64e(eph_pub_bytes),
        'nonce': _b64e(nonce),
        'ct': _b64e(ciphertext),
    }


def unseal_envelope(recipient_identity, recipient_user_id,
                    recipient_device_id, sealed):
    if not isinstance(sealed, dict):
        try:
            sealed = json.loads(sealed)
        except Exception as exc:
            raise SealedSenderError(f'sealed envelope is not JSON: {exc}')

    try:
        eph_pub = _b64d(sealed['eph_pub'])
        nonce = _b64d(sealed['nonce'])
        ct = _b64d(sealed['ct'])
    except (KeyError, ValueError) as exc:
        raise SealedSenderError(f'sealed envelope missing fields: {exc}')

    shared = recipient_identity.ik_priv.exchange(_x25519_pub(eph_pub))
    salt = hashlib.sha256(
        eph_pub + recipient_identity.ik_pub_bytes,
    ).digest()
    key = hkdf(ikm=shared, salt=salt, info=SEAL_INFO, length=32)

    ad = (SEAL_AD + b'|'
          + str(int(recipient_user_id)).encode('ascii') + b'|'
          + recipient_device_id.encode('utf-8') + b'|'
          + eph_pub)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, ad)
    except Exception as exc:
        raise SealedSenderError(f'sealed envelope decryption failed: {exc}')

    try:
        payload = json.loads(plaintext.decode('utf-8'))
    except Exception as exc:
        raise SealedSenderError(f'sealed payload is not JSON: {exc}')

    for field in ('sender_login', 'sender_device_id', 'sender_sik_pub',
                  'cert_signature', 'inner_wire'):
        if field not in payload:
            raise SealedSenderError(
                f'sealed payload missing required field: {field}'
            )

    inner_wire = payload['inner_wire']
    inner_wire_bytes = json.dumps(
        inner_wire, sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')
    cert_msg = _sender_cert_message(
        recipient_user_id, recipient_device_id, inner_wire_bytes,
    )
    try:
        sik_pub = _b64d(payload['sender_sik_pub'])
        cert_sig = _b64d(payload['cert_signature'])
        Ed25519PublicKey.from_public_bytes(sik_pub).verify(cert_sig, cert_msg)
    except (InvalidSignature, ValueError) as exc:
        raise SealedSenderError(
            f'sender certificate signature did not verify: {exc}'
        )

    return {
        'sender_login': payload['sender_login'],
        'sender_device_id': payload['sender_device_id'],
        'sender_ik_pub': payload.get('sender_ik_pub'),
        'sender_sik_pub': payload['sender_sik_pub'],
        'inner_wire': inner_wire,
    }
