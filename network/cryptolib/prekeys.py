import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


SPK_ROTATION_SECONDS = 7 * 24 * 3600
SPK_HISTORY_GRACE_SECONDS = 14 * 24 * 3600
DEFAULT_OPK_BATCH = 100
OPK_REFILL_THRESHOLD = 30


def _gen_x25519():
    priv = x25519.X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return priv_bytes, pub_bytes


class SignedPreKey:
    def __init__(self, key_id, priv_bytes, pub_bytes, signature, created_at):
        self.key_id = key_id
        self.priv_bytes = priv_bytes
        self.pub_bytes = pub_bytes
        self.signature = signature
        self.created_at = created_at

    def to_dict(self):
        import base64
        return {
            'key_id': self.key_id,
            'priv': base64.b64encode(self.priv_bytes).decode(),
            'pub': base64.b64encode(self.pub_bytes).decode(),
            'signature': base64.b64encode(self.signature).decode(),
            'created_at': self.created_at,
        }

    @classmethod
    def from_dict(cls, d):
        import base64
        return cls(
            key_id=d['key_id'],
            priv_bytes=base64.b64decode(d['priv']),
            pub_bytes=base64.b64decode(d['pub']),
            signature=base64.b64decode(d['signature']),
            created_at=d['created_at'],
        )

    def needs_rotation(self, now=None):
        now = now if now is not None else time.time()
        return (now - self.created_at) >= SPK_ROTATION_SECONDS


class OneTimePreKey:

    def __init__(self, key_id, priv_bytes, pub_bytes):
        self.key_id = key_id
        self.priv_bytes = priv_bytes
        self.pub_bytes = pub_bytes

    def to_dict(self):
        import base64
        return {
            'key_id': self.key_id,
            'priv': base64.b64encode(self.priv_bytes).decode(),
            'pub': base64.b64encode(self.pub_bytes).decode(),
        }

    @classmethod
    def from_dict(cls, d):
        import base64
        return cls(
            key_id=d['key_id'],
            priv_bytes=base64.b64decode(d['priv']),
            pub_bytes=base64.b64decode(d['pub']),
        )


class PreKeyStore:
    def __init__(self, signed_prekey=None, one_time_prekeys=None,
                 next_spk_id=1, next_opk_id=1,
                 previous_signed_prekeys=None):
        self.signed_prekey = signed_prekey
        self.previous_signed_prekeys = list(previous_signed_prekeys or [])
        self.one_time_prekeys = list(one_time_prekeys or [])
        self.next_spk_id = next_spk_id
        self.next_opk_id = next_opk_id

    def to_dict(self):
        return {
            'spk': self.signed_prekey.to_dict() if self.signed_prekey else None,
            'spk_history': [p.to_dict() for p in self.previous_signed_prekeys],
            'opks': [k.to_dict() for k in self.one_time_prekeys],
            'next_spk_id': self.next_spk_id,
            'next_opk_id': self.next_opk_id,
        }

    @classmethod
    def from_dict(cls, d):
        spk = SignedPreKey.from_dict(d['spk']) if d.get('spk') else None
        opks = [OneTimePreKey.from_dict(x) for x in d.get('opks', [])]
        history = [SignedPreKey.from_dict(x) for x in d.get('spk_history', [])]
        return cls(
            signed_prekey=spk,
            previous_signed_prekeys=history,
            one_time_prekeys=opks,
            next_spk_id=d.get('next_spk_id', 1),
            next_opk_id=d.get('next_opk_id', 1),
        )

    def rotate_signed_prekey(self, identity_keys):
        if self.signed_prekey is not None:
            self.previous_signed_prekeys.append(self.signed_prekey)
        priv_bytes, pub_bytes = _gen_x25519()
        signature = identity_keys.sign(pub_bytes)
        spk = SignedPreKey(
            key_id=self.next_spk_id,
            priv_bytes=priv_bytes,
            pub_bytes=pub_bytes,
            signature=signature,
            created_at=time.time(),
        )
        self.next_spk_id += 1
        self.signed_prekey = spk
        self.prune_signed_prekey_history()
        return spk

    def ensure_signed_prekey(self, identity_keys, force_rotate=False):
        if (force_rotate
                or self.signed_prekey is None
                or self.signed_prekey.needs_rotation()):
            return self.rotate_signed_prekey(identity_keys)
        return self.signed_prekey

    def prune_signed_prekey_history(self, now=None,
                                    grace_seconds=SPK_HISTORY_GRACE_SECONDS):
        now = now if now is not None else time.time()
        self.previous_signed_prekeys = [
            p for p in self.previous_signed_prekeys
            if now - p.created_at < grace_seconds
        ]

    def generate_one_time_prekeys(self, count=DEFAULT_OPK_BATCH):
        new_keys = []
        for _ in range(count):
            priv_bytes, pub_bytes = _gen_x25519()
            opk = OneTimePreKey(
                key_id=self.next_opk_id,
                priv_bytes=priv_bytes,
                pub_bytes=pub_bytes,
            )
            self.next_opk_id += 1
            new_keys.append(opk)
            self.one_time_prekeys.append(opk)
        return new_keys

    def take_one_time_prekey(self, opk_id):
        for i, opk in enumerate(self.one_time_prekeys):
            if opk.key_id == opk_id:
                return self.one_time_prekeys.pop(i)
        return None

    def remaining_one_time_prekeys(self):
        return len(self.one_time_prekeys)

    def get_signed_prekey_by_id(self, spk_id):
        if self.signed_prekey is not None and self.signed_prekey.key_id == spk_id:
            return self.signed_prekey
        for p in self.previous_signed_prekeys:
            if p.key_id == spk_id:
                return p
        return None
