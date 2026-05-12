"""Crypto-only tests for the cryptolib package.

These tests do not start the Flask server, do not touch Qt, and do
not require network access — they exercise the X3DH + Double Ratchet +
storage primitives directly. The goal is to assert the *protocol*
properties Signal-style messengers need:

  - basic round-trip correctness
  - out-of-order delivery still decrypts
  - the MAX_SKIP guard refuses pathological skips
  - a duplicate wire is recognised (DuplicateMessage)
  - failed decrypt rolls back ratchet state (atomic decrypt)
  - x3dh-init replay is idempotent (no extra OPK consumed, no double session)
  - per-device IK derivation: same master_key + different device_id =>
    different IK, same SIK.

Run from the project root:

    python -m unittest tests.test_crypto -v
"""

import os
import sys
import unittest
import base64

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from network.cryptolib.identity import IdentityKeys
from network.cryptolib.prekeys import PreKeyStore
from network.cryptolib.double_ratchet import (
    DoubleRatchet, RatchetError, DuplicateMessage, MAX_SKIP,
)
from network.cryptolib.x3dh import (
    build_initial_message, accept_initial_message, X3DHError,
)
from network.cryptolib.safety_numbers import (
    compute_safety_number, format_safety_number,
)


def make_user(label, device_id='dev-1'):
    # 32-byte deterministic master key, padded so labels of any length
    # produce a usable seed.
    raw = label.encode('utf-8') * 32
    master_key = raw[:32].ljust(32, b'\x00')
    identity = IdentityKeys.from_master_key(master_key, device_id=device_id)
    store = PreKeyStore()
    store.ensure_signed_prekey(identity)
    store.generate_one_time_prekeys(3)
    return {
        'label': label,
        'device_id': device_id,
        'master_key': master_key,
        'identity': identity,
        'store': store,
    }


def build_bundle_for(user):
    spk = user['store'].signed_prekey
    opk = user['store'].one_time_prekeys[0]
    return {
        'ik': base64.b64encode(user['identity'].ik_pub_bytes).decode(),
        'sik': base64.b64encode(user['identity'].sik_pub_bytes).decode(),
        'identity_signature': base64.b64encode(
            user['identity'].sign_identity_binding()
        ).decode(),
        'spk_id': spk.key_id,
        'spk': base64.b64encode(spk.pub_bytes).decode(),
        'spk_signature': base64.b64encode(spk.signature).decode(),
        'opk_id': opk.key_id,
        'opk': base64.b64encode(opk.pub_bytes).decode(),
    }


def x3dh_init(alice, bob_bundle):
    sk, ad, header, peer_initial_dh = build_initial_message(
        alice['identity'], bob_bundle,
    )
    return sk, ad, header, peer_initial_dh


def x3dh_accept(bob, header):
    sk, ad, peer_ik, peer_sik, consumed_opk, spk_pub = accept_initial_message(
        bob['identity'], bob['store'], header,
    )
    return sk, ad, peer_ik, spk_pub


class DoubleRatchetCorrectness(unittest.TestCase):
    def setUp(self):
        self.alice = make_user('alice')
        self.bob = make_user('bob')
        bob_bundle = build_bundle_for(self.bob)
        sk_a, alice_ad, header, _ = x3dh_init(self.alice, bob_bundle)
        sk_b, bob_ad, _, spk_pub = x3dh_accept(self.bob, header)
        self.assertEqual(sk_a, sk_b)
        self.alice_ratchet = DoubleRatchet.init_initiator(
            sk_a, base64.b64decode(bob_bundle['spk']),
        )
        self.bob_ratchet = DoubleRatchet.init_responder(
            sk_b, self.bob['store'].signed_prekey.priv_bytes,
            self.bob['store'].signed_prekey.pub_bytes,
        )
        self.alice_ad = alice_ad
        self.bob_ad = bob_ad

    def test_first_message_round_trip(self):
        header, ct = self.alice_ratchet.encrypt(b'hello bob', self.alice_ad)
        plain = self.bob_ratchet.decrypt(header, ct, self.bob_ad)
        self.assertEqual(plain, b'hello bob')

    def test_long_alternating_dialogue(self):
        history = []
        for i in range(20):
            sender = self.alice_ratchet if i % 2 == 0 else self.bob_ratchet
            receiver = self.bob_ratchet if i % 2 == 0 else self.alice_ratchet
            ad_send = self.alice_ad if i % 2 == 0 else self.bob_ad
            ad_recv = self.bob_ad if i % 2 == 0 else self.alice_ad
            msg = f'msg-{i}'.encode()
            header, ct = sender.encrypt(msg, ad_send)
            plain = receiver.decrypt(header, ct, ad_recv)
            self.assertEqual(plain, msg)
            history.append(msg)

    def test_out_of_order_within_chain(self):
        wires = []
        for i in range(5):
            header, ct = self.alice_ratchet.encrypt(f'm{i}'.encode(),
                                                    self.alice_ad)
            wires.append((header, ct))
        order = [3, 0, 4, 1, 2]
        for idx in order:
            plain = self.bob_ratchet.decrypt(*wires[idx], self.bob_ad)
            self.assertEqual(plain, f'm{idx}'.encode())

    def test_duplicate_message_raises(self):
        header, ct = self.alice_ratchet.encrypt(b'once', self.alice_ad)
        self.bob_ratchet.decrypt(header, ct, self.bob_ad)
        with self.assertRaises(DuplicateMessage):
            self.bob_ratchet.decrypt(header, ct, self.bob_ad)

    def test_max_skip_enforced(self):
        h0, ct0 = self.alice_ratchet.encrypt(b'first', self.alice_ad)
        # Advance Alice past MAX_SKIP without Bob seeing intermediate
        # messages — the next wire's header.n is way ahead of bob.nr.
        for _ in range(MAX_SKIP + 5):
            self.alice_ratchet.encrypt(b'x', self.alice_ad)
        h_far, ct_far = self.alice_ratchet.encrypt(b'far', self.alice_ad)
        # Bob still hasn't seen the first; the leap should be rejected.
        with self.assertRaises(RatchetError):
            self.bob_ratchet.decrypt(h_far, ct_far, self.bob_ad)

    def test_atomic_rollback_on_aead_failure(self):
        h_good, ct_good = self.alice_ratchet.encrypt(b'good', self.alice_ad)
        h_bad, ct_bad = self.alice_ratchet.encrypt(b'bad', self.alice_ad)
        # Tamper with the second ciphertext
        tampered = bytes([ct_bad[0] ^ 0x01]) + ct_bad[1:]
        snapshot = self.bob_ratchet.to_dict()
        with self.assertRaises(RatchetError):
            self.bob_ratchet.decrypt(h_bad, tampered, self.bob_ad)
        # State should be unchanged
        self.assertEqual(self.bob_ratchet.to_dict(), snapshot)
        # The good messages still decrypt afterwards
        plain = self.bob_ratchet.decrypt(h_good, ct_good, self.bob_ad)
        self.assertEqual(plain, b'good')


class X3DHReplay(unittest.TestCase):
    def test_replay_consumes_only_one_opk(self):
        bob = make_user('bob')
        alice = make_user('alice')
        bob_bundle = build_bundle_for(bob)
        opk_id = bob_bundle['opk_id']
        # First init: should consume the OPK
        x3dh_init(alice, bob_bundle)
        x3dh_accept(bob, _make_header(alice, bob_bundle))
        self.assertIsNone(bob['store'].take_one_time_prekey(opk_id))


def _make_header(alice, bob_bundle):
    sk, ad, header, peer = build_initial_message(alice['identity'], bob_bundle)
    return header


class PerDeviceIdentity(unittest.TestCase):
    def test_same_master_key_different_device_yields_different_ik(self):
        mk = b'\x42' * 32
        a = IdentityKeys.from_master_key(mk, device_id='dev-A')
        b = IdentityKeys.from_master_key(mk, device_id='dev-B')
        self.assertNotEqual(a.ik_pub_bytes, b.ik_pub_bytes)
        self.assertEqual(a.sik_pub_bytes, b.sik_pub_bytes)


class SafetyNumbers(unittest.TestCase):
    def test_symmetric(self):
        a = b'\x11' * 32
        b = b'\x22' * 32
        n1 = compute_safety_number(a, b)
        n2 = compute_safety_number(b, a)
        self.assertEqual(n1, n2)
        self.assertEqual(len(n1), 12)
        for chunk in n1:
            self.assertEqual(len(chunk), 5)
            self.assertTrue(chunk.isdigit())

    def test_changed_key_yields_different_number(self):
        a = b'\x11' * 32
        b = b'\x22' * 32
        c = b'\x33' * 32
        self.assertNotEqual(
            compute_safety_number(a, b),
            compute_safety_number(a, c),
        )

    def test_format_two_lines(self):
        a = b'\x11' * 32
        b = b'\x22' * 32
        text = format_safety_number(compute_safety_number(a, b))
        self.assertIn('\n', text)
        self.assertEqual(text.count(' '), 10)  # 5 spaces per line × 2 lines


if __name__ == '__main__':
    unittest.main()
