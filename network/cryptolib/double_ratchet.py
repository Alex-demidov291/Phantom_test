import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from network.cryptolib.primitives import (
    aead_encrypt, aead_decrypt,
    kdf_chain_key_step, kdf_root_key,
)


MAX_SKIP = 1000  # max messages we'll skip ahead in a single chain
MAX_TOTAL_SKIPPED = 2000  # hard cap on total stored skipped keys
HEADER_AD_INFO = b'PhantomChats/Header/v1'


class RatchetError(Exception):
    pass


class DuplicateMessage(RatchetError):
    pass


def _gen_dh_keypair():
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


def _dh(priv_bytes, pub_bytes):
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)


def _b64(b):
    return base64.b64encode(b).decode() if b is not None else None


def _ub64(s):
    return base64.b64decode(s) if s is not None else None


def _header_bytes(header_dict):
    return json.dumps(
        {'dh': header_dict['dh'], 'n': header_dict['n'], 'pn': header_dict['pn']},
        sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')


class DoubleRatchet:
    def __init__(self, dhs_priv, dhs_pub, dhr_pub, rk, cks, ckr,
                 ns, nr, pn, skipped):
        self.dhs_priv = dhs_priv
        self.dhs_pub = dhs_pub
        self.dhr_pub = dhr_pub
        self.rk = rk
        self.cks = cks
        self.ckr = ckr
        self.ns = ns
        self.nr = nr
        self.pn = pn
        self.skipped = dict(skipped or {})

    @classmethod
    def init_initiator(cls, sk, peer_initial_dh_pub):
        dhs_priv, dhs_pub = _gen_dh_keypair()
        new_rk, cks = kdf_root_key(sk, _dh(dhs_priv, peer_initial_dh_pub))
        return cls(
            dhs_priv=dhs_priv, dhs_pub=dhs_pub,
            dhr_pub=peer_initial_dh_pub,
            rk=new_rk, cks=cks, ckr=None,
            ns=0, nr=0, pn=0, skipped={},
        )

    @classmethod
    def init_responder(cls, sk, own_initial_dh_priv, own_initial_dh_pub):
        return cls(
            dhs_priv=own_initial_dh_priv, dhs_pub=own_initial_dh_pub,
            dhr_pub=None,
            rk=sk, cks=None, ckr=None,
            ns=0, nr=0, pn=0, skipped={},
        )

    def to_dict(self):
        return {
            'dhs_priv': _b64(self.dhs_priv),
            'dhs_pub': _b64(self.dhs_pub),
            'dhr_pub': _b64(self.dhr_pub),
            'rk': _b64(self.rk),
            'cks': _b64(self.cks),
            'ckr': _b64(self.ckr),
            'ns': self.ns,
            'nr': self.nr,
            'pn': self.pn,
            'skipped': [
                {'dhr': dhr_b64, 'n': n, 'mk': _b64(mk)}
                for (dhr_b64, n), mk in self.skipped.items()
            ],
        }

    @classmethod
    def from_dict(cls, d):
        skipped = {}
        for entry in d.get('skipped', []):
            skipped[(entry['dhr'], entry['n'])] = _ub64(entry['mk'])
        return cls(
            dhs_priv=_ub64(d['dhs_priv']),
            dhs_pub=_ub64(d['dhs_pub']),
            dhr_pub=_ub64(d['dhr_pub']),
            rk=_ub64(d['rk']),
            cks=_ub64(d['cks']),
            ckr=_ub64(d['ckr']),
            ns=d['ns'], nr=d['nr'], pn=d['pn'],
            skipped=skipped,
        )

    def encrypt(self, plaintext, ad):
        if self.cks is None:
            raise RatchetError('no sending chain key — cannot encrypt yet')
        self.cks, mk = kdf_chain_key_step(self.cks)
        header = {
            'dh': _b64(self.dhs_pub),
            'n': self.ns,
            'pn': self.pn,
        }
        self.ns += 1
        bound_ad = ad + b'|' + _header_bytes(header)
        ciphertext = aead_encrypt(mk, plaintext, bound_ad)
        return header, ciphertext

    def _snapshot(self):
        return (
            self.dhs_priv, self.dhs_pub, self.dhr_pub,
            self.rk, self.cks, self.ckr,
            self.ns, self.nr, self.pn,
            dict(self.skipped),
        )

    def _restore(self, snap):
        (self.dhs_priv, self.dhs_pub, self.dhr_pub,
         self.rk, self.cks, self.ckr,
         self.ns, self.nr, self.pn, self.skipped) = (
            snap[0], snap[1], snap[2],
            snap[3], snap[4], snap[5],
            snap[6], snap[7], snap[8], dict(snap[9]),
        )

    def decrypt(self, header, ciphertext, ad):
        snap = self._snapshot()
        try:
            plaintext = self._try_skipped(header, ciphertext, ad)
            if plaintext is not None:
                return plaintext

            header_dh = _ub64(header['dh'])
            same_chain = (self.dhr_pub is not None and header_dh == self.dhr_pub)

            if same_chain and header['n'] < self.nr:
                self._restore(snap)
                raise DuplicateMessage(
                    f'message n={header["n"]} already consumed (nr={self.nr})'
                )

            if not same_chain:
                self._skip_message_keys(header['pn'])
                self._dh_ratchet(header_dh)
            self._skip_message_keys(header['n'])
            self.ckr, mk = kdf_chain_key_step(self.ckr)
            self.nr += 1
            bound_ad = ad + b'|' + _header_bytes(header)
            try:
                return aead_decrypt(mk, ciphertext, bound_ad)
            except Exception as exc:
                self._restore(snap)
                raise RatchetError(f'AEAD decrypt failed: {exc}')
        except DuplicateMessage:
            raise
        except RatchetError:
            self._restore(snap)
            raise
        except Exception as exc:
            self._restore(snap)
            raise RatchetError(f'ratchet decrypt failed: {exc}')
    def _try_skipped(self, header, ciphertext, ad):
        key = (header['dh'], header['n'])
        mk = self.skipped.pop(key, None)
        if mk is None:
            return None
        bound_ad = ad + b'|' + _header_bytes(header)
        return aead_decrypt(mk, ciphertext, bound_ad)

    def _skip_message_keys(self, until):
        if self.ckr is None:
            return
        if self.nr + MAX_SKIP < until:
            raise RatchetError(
                f'cannot skip {until - self.nr} messages '
                f'(MAX_SKIP={MAX_SKIP})'
            )
        if len(self.skipped) > MAX_TOTAL_SKIPPED:
            raise RatchetError('too many skipped message keys retained')
        dhr_b64 = _b64(self.dhr_pub)
        while self.nr < until:
            self.ckr, mk = kdf_chain_key_step(self.ckr)
            self.skipped[(dhr_b64, self.nr)] = mk
            self.nr += 1

    def _dh_ratchet(self, new_remote_dh_pub):
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr_pub = new_remote_dh_pub
        self.rk, self.ckr = kdf_root_key(self.rk, _dh(self.dhs_priv, self.dhr_pub))
        self.dhs_priv, self.dhs_pub = _gen_dh_keypair()
        self.rk, self.cks = kdf_root_key(self.rk, _dh(self.dhs_priv, self.dhr_pub))
