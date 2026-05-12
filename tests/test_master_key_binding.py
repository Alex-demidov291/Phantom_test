"""Tests for the SIK-signed encrypted_master_key binding.

The binding is the contract between the client (which knows the
master_key) and the server (which can only return what it stored). It
must:

  * round-trip cleanly for an honest server,
  * reject any byte-level edit of the encrypted blob,
  * reject substitution of another account's blob (login mismatch),
  * reject substitution of another account's blob even if the attacker
    also presents that account's SIK pub (identity mismatch),
  * reject substitution where the attacker forged a "matching" SIK
    pub but with the wrong private key (signature won't verify),
  * reject substitution where the encrypted blob has been swapped to
    one whose underlying master_key is different (SIK mismatch).
"""

import os
import sys
import json
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from network.cryptolib.master_key_binding import (
    sign_master_key_binding, verify_master_key_binding,
    MasterKeyBindingError,
)


def _fake_blob(seed):
    # Shape mirrors what `encrypt_master_key` actually produces.
    return json.dumps({
        'salt': f'salt-{seed}',
        'nonce': f'nonce-{seed}',
        'ciphertext': f'cipher-{seed}',
    })


class BindingRoundTrip(unittest.TestCase):
    def setUp(self):
        self.master = b'\xaa' * 32
        self.login = 'alice'
        self.blob = _fake_blob('legit')
        b = sign_master_key_binding(self.master, self.login, self.blob)
        self.signature = b['signature']
        self.sik_pub = b['sik_pub']

    def test_honest_round_trip(self):
        self.assertTrue(verify_master_key_binding(
            self.master, self.login, self.blob,
            signature_b64=self.signature,
            expected_sik_pub_b64=self.sik_pub,
        ))

    def test_canonicalisation_invariant_to_field_order(self):
        # Server may re-emit the blob with keys in different order.
        # Verification must still pass because we canonicalise before
        # hashing. Manually reorder via a dict literal so the byte
        # representation is genuinely different from the original.
        d = json.loads(self.blob)
        scrambled = json.dumps({
            'ciphertext': d['ciphertext'],
            'nonce': d['nonce'],
            'salt': d['salt'],
        })
        self.assertNotEqual(scrambled, self.blob,
                            'test setup: blob byte order must differ')
        self.assertTrue(verify_master_key_binding(
            self.master, self.login, scrambled,
            signature_b64=self.signature,
            expected_sik_pub_b64=self.sik_pub,
        ))


class BindingTamperDetection(unittest.TestCase):
    def setUp(self):
        self.master = b'\xaa' * 32
        self.login = 'alice'
        self.blob = _fake_blob('legit')
        b = sign_master_key_binding(self.master, self.login, self.blob)
        self.signature = b['signature']
        self.sik_pub = b['sik_pub']

    def test_blob_byte_change_rejected(self):
        d = json.loads(self.blob)
        d['ciphertext'] = d['ciphertext'] + 'X'
        evil = json.dumps(d)
        with self.assertRaises(MasterKeyBindingError):
            verify_master_key_binding(
                self.master, self.login, evil,
                signature_b64=self.signature,
                expected_sik_pub_b64=self.sik_pub,
            )

    def test_login_substitution_rejected(self):
        # Server tries to deliver Alice's blob to Bob's login.
        with self.assertRaises(MasterKeyBindingError):
            verify_master_key_binding(
                self.master, 'bob', self.blob,
                signature_b64=self.signature,
                expected_sik_pub_b64=self.sik_pub,
            )

    def test_account_substitution_rejected(self):
        # Server swaps Alice's stored data for Bob's. Even though Bob's
        # blob+sig+sik_pub all line up against Bob's master_key, the
        # client logging in as Alice will derive Alice's SIK from her
        # password-recovered master_key — that won't match Bob's stored
        # SIK, so verification fails.
        bob_master = b'\xbb' * 32
        bob_blob = _fake_blob('bob')
        bob_b = sign_master_key_binding(bob_master, 'alice', bob_blob)
        # Note we even sign with login='alice' to defeat the login check —
        # this models a fully-malicious server with bob_master to use.
        with self.assertRaises(MasterKeyBindingError):
            verify_master_key_binding(
                self.master,  # Alice's recovered master_key
                'alice',
                bob_blob,
                signature_b64=bob_b['signature'],
                expected_sik_pub_b64=bob_b['sik_pub'],
            )

    def test_signature_replaced_by_random_rejected(self):
        bad_sig = 'A' * 88
        with self.assertRaises(MasterKeyBindingError):
            verify_master_key_binding(
                self.master, self.login, self.blob,
                signature_b64=bad_sig,
                expected_sik_pub_b64=self.sik_pub,
            )

    def test_missing_signature_rejected(self):
        with self.assertRaises(MasterKeyBindingError):
            verify_master_key_binding(
                self.master, self.login, self.blob,
                signature_b64=None,
                expected_sik_pub_b64=self.sik_pub,
            )


class BindingNoSikPubGuard(unittest.TestCase):
    def test_signature_alone_still_verifies_against_derived_sik(self):
        master = b'\x42' * 32
        login = 'alice'
        blob = _fake_blob('x')
        b = sign_master_key_binding(master, login, blob)
        # Verifier omits the expected_sik_pub argument; signature is
        # checked against the SIK derived from `master` directly.
        self.assertTrue(verify_master_key_binding(
            master, login, blob,
            signature_b64=b['signature'],
            expected_sik_pub_b64=None,
        ))


if __name__ == '__main__':
    unittest.main()
