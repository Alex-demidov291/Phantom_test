from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from network.cryptolib.primitives import hkdf


class IdentityKeys:
    IK_INFO = b'PhantomChats/Identity/X25519/v2/device'
    LEGACY_IK_INFO = b'PhantomChats/Identity/X25519/v1'
    SIK_INFO = b'PhantomChats/Identity/Ed25519/v1'

    def __init__(self, ik_priv, sik_priv, device_id=None):
        self.ik_priv = ik_priv
        self.ik_pub = ik_priv.public_key()
        self.sik_priv = sik_priv
        self.sik_pub = sik_priv.public_key()
        self.device_id = device_id

    @classmethod
    def from_master_key(cls, master_key, device_id=None):
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) < 32:
            raise ValueError('master_key must be at least 32 bytes')
        if device_id:
            ik_seed = hkdf(
                bytes(master_key),
                salt=device_id.encode('utf-8') if isinstance(device_id, str)
                     else bytes(device_id),
                info=cls.IK_INFO,
                length=32,
            )
        else:
            ik_seed = hkdf(bytes(master_key), salt=b'',
                           info=cls.LEGACY_IK_INFO, length=32)
        sik_seed = hkdf(bytes(master_key), salt=b'', info=cls.SIK_INFO, length=32)
        ik_priv = x25519.X25519PrivateKey.from_private_bytes(ik_seed)
        sik_priv = Ed25519PrivateKey.from_private_bytes(sik_seed)
        return cls(ik_priv, sik_priv, device_id=device_id)

    @classmethod
    def user_ik_pub_bytes(cls, master_key):
        ik_seed = hkdf(bytes(master_key), salt=b'',
                       info=cls.LEGACY_IK_INFO, length=32)
        priv = x25519.X25519PrivateKey.from_private_bytes(ik_seed)
        return priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def ik_pub_bytes(self):
        return self.ik_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def sik_pub_bytes(self):
        return self.sik_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign_identity_binding(self):
        return self.sik_priv.sign(self.ik_pub_bytes)

    def sign(self, message):
        return self.sik_priv.sign(message)

    @staticmethod
    def verify_signature(sik_pub_bytes, message, signature):
        try:
            Ed25519PublicKey.from_public_bytes(sik_pub_bytes).verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False

    def diffie_hellman(self, peer_x25519_pub_bytes):
        peer = x25519.X25519PublicKey.from_public_bytes(peer_x25519_pub_bytes)
        return self.ik_priv.exchange(peer)
