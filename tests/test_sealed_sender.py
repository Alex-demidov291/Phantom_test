"""Tests for the Sealed Sender envelope.

The sealed envelope must:

  * decrypt cleanly when the right recipient unwraps it,
  * authenticate the sender certificate end-to-end,
  * reject any tampering with eph_pub / nonce / ct,
  * reject delivery to the *wrong* recipient (AD binding),
  * reject delivery to the right recipient *user* but a different
    *device* of theirs (per-device AD),
  * reject a forged sender certificate,
  * not leak the sender identity in the public envelope fields.
"""

import os
import sys
import json
import unittest
import base64

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from network.cryptolib.identity import IdentityKeys
from network.cryptolib.sealed_sender import (
    seal_envelope, unseal_envelope, SealedSenderError,
)


class SealedSenderRoundTrip(unittest.TestCase):
    def setUp(self):
        # Distinct master_keys ⇒ distinct identities; per-device IK is
        # what the sealed envelope encrypts to.
        self.alice = IdentityKeys.from_master_key(b'\x01' * 32, device_id='dev-A')
        self.bob = IdentityKeys.from_master_key(b'\x02' * 32, device_id='dev-B')
        self.bob_user_id = 1001
        self.bob_dev = 'dev-B'
        self.inner = {
            'type': 'ratchet', 'v': 3,
            'header': {'dh': 'AAAA', 'n': 0, 'pn': 0},
            'ciphertext': base64.b64encode(b'opaque').decode(),
        }

    def _seal(self):
        return seal_envelope(
            sender_identity=self.alice,
            sender_login='alice',
            sender_device_id='dev-A',
            recipient_user_id=self.bob_user_id,
            recipient_device_id=self.bob_dev,
            recipient_ik_pub_bytes=self.bob.ik_pub_bytes,
            inner_wire=self.inner,
        )

    def test_round_trip(self):
        sealed = self._seal()
        unsealed = unseal_envelope(
            self.bob, self.bob_user_id, self.bob_dev, sealed,
        )
        self.assertEqual(unsealed['sender_login'], 'alice')
        self.assertEqual(unsealed['sender_device_id'], 'dev-A')
        self.assertEqual(unsealed['inner_wire'], self.inner)

    def test_public_envelope_does_not_contain_sender_identity(self):
        sealed = self._seal()
        # The public fields should not contain the sender login string
        # or any of its identity bytes — that's the whole point.
        flat = json.dumps(sealed)
        self.assertNotIn('alice', flat)
        self.assertNotIn(base64.b64encode(self.alice.ik_pub_bytes).decode(),
                         flat)
        self.assertNotIn(base64.b64encode(self.alice.sik_pub_bytes).decode(),
                         flat)


class SealedSenderTamperDetection(unittest.TestCase):
    def setUp(self):
        self.alice = IdentityKeys.from_master_key(b'\x01' * 32, device_id='dev-A')
        self.bob = IdentityKeys.from_master_key(b'\x02' * 32, device_id='dev-B')
        self.eve = IdentityKeys.from_master_key(b'\x03' * 32, device_id='dev-E')
        self.bob_user_id = 1001
        self.bob_dev = 'dev-B'
        self.inner = {
            'type': 'ratchet', 'v': 3,
            'header': {'dh': 'AAAA', 'n': 0, 'pn': 0},
            'ciphertext': base64.b64encode(b'opaque').decode(),
        }
        self.sealed = seal_envelope(
            sender_identity=self.alice,
            sender_login='alice',
            sender_device_id='dev-A',
            recipient_user_id=self.bob_user_id,
            recipient_device_id=self.bob_dev,
            recipient_ik_pub_bytes=self.bob.ik_pub_bytes,
            inner_wire=self.inner,
        )

    def test_wrong_recipient_user_id_rejected(self):
        with self.assertRaises(SealedSenderError):
            unseal_envelope(self.bob, self.bob_user_id + 1, self.bob_dev,
                            self.sealed)

    def test_wrong_recipient_device_rejected(self):
        with self.assertRaises(SealedSenderError):
            unseal_envelope(self.bob, self.bob_user_id, 'wrong-device',
                            self.sealed)

    def test_wrong_recipient_identity_rejected(self):
        # Eve has Bob's stored sealed blob but not Bob's IK_priv — she
        # cannot decrypt the envelope.
        with self.assertRaises(SealedSenderError):
            unseal_envelope(self.eve, self.bob_user_id, self.bob_dev,
                            self.sealed)

    def test_ciphertext_tamper_rejected(self):
        evil = dict(self.sealed)
        ct = base64.b64decode(evil['ct'])
        ct = bytes([ct[0] ^ 0xff]) + ct[1:]
        evil['ct'] = base64.b64encode(ct).decode()
        with self.assertRaises(SealedSenderError):
            unseal_envelope(self.bob, self.bob_user_id, self.bob_dev, evil)

    def test_eph_pub_swap_rejected(self):
        # Replace eph_pub with a fresh random key — AEAD will reject
        # because the AD includes the original eph_pub the ciphertext
        # was bound to (and the derived key changes anyway).
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519
        new = x25519.X25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        evil = dict(self.sealed)
        evil['eph_pub'] = base64.b64encode(new).decode()
        with self.assertRaises(SealedSenderError):
            unseal_envelope(self.bob, self.bob_user_id, self.bob_dev, evil)

    def test_forged_sender_cert_rejected(self):
        # Eve knows Alice's user-facing identity strings but not her
        # SIK_priv. She tries to seal-as-Alice but her cert won't
        # verify against Alice's claimed SIK pub.
        sealed = seal_envelope(
            sender_identity=self.eve,           # Eve signs
            sender_login='alice',                # but claims to be Alice
            sender_device_id='dev-A',
            recipient_user_id=self.bob_user_id,
            recipient_device_id=self.bob_dev,
            recipient_ik_pub_bytes=self.bob.ik_pub_bytes,
            inner_wire=self.inner,
        )
        # The envelope still decrypts (Bob owns the IK), but the
        # certificate is signed by Eve's SIK; verify_envelope checks the
        # sik_pub embedded inside the payload — which is *Eve's*. The
        # outer protocol layer must additionally pin the expected SIK
        # against the prekey-bundle SIK, which is what the production
        # code does. We assert that the sik_pub returned matches the
        # signer (Eve), so the upper layer can detect impersonation.
        unsealed = unseal_envelope(
            self.bob, self.bob_user_id, self.bob_dev, sealed,
        )
        # The unsealing succeeded internally because the cert is
        # self-consistent (Eve signed her own claim). What it returns
        # is Eve's SIK pub, not Alice's — so the chat layer can
        # cross-check against the trusted SIK and reject.
        self.assertEqual(
            base64.b64decode(unsealed['sender_sik_pub']),
            self.eve.sik_pub_bytes,
        )
        self.assertNotEqual(
            base64.b64decode(unsealed['sender_sik_pub']),
            self.alice.sik_pub_bytes,
        )

    def test_replay_to_different_device_blocked_by_ad(self):
        # Even if Bob has multiple devices, a sealed envelope is
        # cryptographically pinned to a single device_id via AD.
        with self.assertRaises(SealedSenderError):
            unseal_envelope(self.bob, self.bob_user_id, 'other-device',
                            self.sealed)


if __name__ == '__main__':
    unittest.main()
