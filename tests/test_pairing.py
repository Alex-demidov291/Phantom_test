"""Tests for the device pairing handshake.

The pairing flow has to survive:

  * server tampering with the ECDH publics in transit (mixing the
    pairing code into the AEAD key salt defeats this),
  * a server that drops the sealed bundle (handshake just stalls,
    no leak),
  * brute-force of the pairing code through /device_pair_enter
    (attempt counter caps replays),
  * fetching the bundle a second time (server deletes the row on
    first fetch).
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import base64

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import opaque_ke_py

from network.cryptolib.pairing import (
    generate_pairing_code, pairing_code_hash, gen_pairing_ephemeral,
    derive_pair_key, seal_pairing_bundle, unseal_pairing_bundle,
    PairingError,
)
from network.cryptolib.master_key_binding import sign_master_key_binding


def _isolate():
    tmp = tempfile.mkdtemp(prefix='phantom-pair-')
    cwd_orig = os.getcwd()
    os.chdir(tmp)
    return tmp, cwd_orig


def _restore(tmp, cwd):
    os.chdir(cwd)
    shutil.rmtree(tmp, ignore_errors=True)


def _import_app():
    if 'app' in sys.modules:
        del sys.modules['app']
    if 'settings' in sys.modules:
        del sys.modules['settings']
    import app as app_module
    return app_module


class PairingCryptoUnit(unittest.TestCase):
    def test_dh_key_round_trip(self):
        code = generate_pairing_code()
        epk_a_priv, epk_a_pub = gen_pairing_ephemeral()
        epk_b_priv, epk_b_pub = gen_pairing_ephemeral()
        bundle = {'master_key': base64.b64encode(b'\x42' * 64).decode()}
        sealed = seal_pairing_bundle(epk_a_priv, epk_b_pub, code, bundle)
        recovered = unseal_pairing_bundle(epk_b_priv, epk_a_pub, code, sealed)
        self.assertEqual(recovered, bundle)

    def test_wrong_code_fails(self):
        epk_a_priv, _ = gen_pairing_ephemeral()
        epk_b_priv, epk_b_pub = gen_pairing_ephemeral()
        _, epk_a_pub = gen_pairing_ephemeral()  # mismatching!
        bundle = {'x': 1}
        sealed = seal_pairing_bundle(epk_a_priv, epk_b_pub, '123456789', bundle)
        with self.assertRaises(PairingError):
            unseal_pairing_bundle(
                epk_b_priv, epk_a_pub, '987654321', sealed,
            )

    def test_mitm_attempt_fails(self):
        # Server-MITM: swaps epk_b_pub for its own. Even if it sees
        # both DH publics, it still needs the code to derive the key.
        code = generate_pairing_code()
        epk_a_priv, epk_a_pub = gen_pairing_ephemeral()
        epk_b_priv, epk_b_pub = gen_pairing_ephemeral()
        attacker_priv, attacker_pub = gen_pairing_ephemeral()
        # A seals with attacker's pub thinking it's B.
        sealed = seal_pairing_bundle(
            epk_a_priv, attacker_pub, code, {'x': 1},
        )
        # Attacker can decrypt only if they know the code, which
        # never travels through them. Verify decryption fails for B.
        with self.assertRaises(PairingError):
            unseal_pairing_bundle(epk_b_priv, epk_a_pub, code, sealed)

    def test_pairing_code_hash_one_way(self):
        code = generate_pairing_code()
        h = pairing_code_hash(code)
        self.assertEqual(len(h), 64)  # SHA-256 hex
        self.assertNotIn(code, h)


class PairingEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp, self._cwd = _isolate()
        self.app_mod = _import_app()
        self.client = self.app_mod.app.test_client()
        # Register Alice on device A.
        master_key = os.urandom(64)
        cs = opaque_ke_py.client_registration_start(b'pw1234')
        self.client.post('/api/opaque/register/start',
                         json={'login': 'alice', 'username': 'alice'},
                         headers={'X-Device-ID': 'dev-A'})
        r = self.client.post('/api/opaque/register/finish', json={
            'login': 'alice', 'username': 'alice',
            'registration_request': base64.b64encode(
                cs.get_message()).decode(),
        }, headers={'X-Device-ID': 'dev-A'})
        sr = base64.b64decode(r.get_json()['server_response'])
        cf = opaque_ke_py.client_registration_finish(b'pw1234',
                                                    cs.get_state(), sr)
        blob = json.dumps({'salt': 'YQ==', 'nonce': 'YQ==',
                           'ciphertext': 'YQ=='})
        b = sign_master_key_binding(master_key, 'alice', blob)
        r = self.client.post('/api/opaque/register/upload', json={
            'login': 'alice', 'username': 'alice',
            'registration_upload': base64.b64encode(cf.get_message()).decode(),
            'encrypted_master_key': blob,
            'master_key_binding_sig': b['signature'],
            'master_key_binding_sik_pub': b['sik_pub'],
        }, headers={'X-Device-ID': 'dev-A'})
        reg = r.get_json()
        self.master_key = master_key
        self.alice_headers = {
            'X-Session-Token': reg['session_token'],
            'X-User-Id': str(reg['user_id']),
            'X-Device-ID': 'dev-A',
        }
        self.alice_user_id = reg['user_id']

    def tearDown(self):
        _restore(self._tmp, self._cwd)

    def test_full_flow(self):
        code = generate_pairing_code()
        code_hash = pairing_code_hash(code)
        # 1. A starts pairing.
        epk_a_priv, epk_a_pub = gen_pairing_ephemeral()
        r = self.client.post('/api/device_pair_start', json={
            'code_hash': code_hash,
            'epk_a_pub': base64.b64encode(epk_a_pub).decode(),
        }, headers=self.alice_headers)
        body = r.get_json()
        self.assertTrue(body['success'], body)
        pair_id = body['pair_id']

        # 2. B types the code, ANONYMOUSLY exchanges its pub.
        epk_b_priv, epk_b_pub = gen_pairing_ephemeral()
        r = self.client.post('/api/device_pair_enter', json={
            'code_hash': code_hash,
            'epk_b_pub': base64.b64encode(epk_b_pub).decode(),
        })
        body = r.get_json()
        self.assertTrue(body['success'])
        self.assertEqual(body['primary_user_id'], self.alice_user_id)
        peer_pub_for_a = base64.b64decode(body['epk_a_pub'])
        self.assertEqual(peer_pub_for_a, epk_a_pub)

        # 3. A polls for B's pub, then seals the master_key bundle.
        r = self.client.post('/api/device_pair_status',
                             json={'pair_id': pair_id},
                             headers=self.alice_headers)
        peer_pub_b = base64.b64decode(r.get_json()['epk_b_pub'])
        sealed = seal_pairing_bundle(epk_a_priv, peer_pub_b, code, {
            'master_key': base64.b64encode(self.master_key).decode(),
            'login': 'alice',
        })
        r = self.client.post('/api/device_pair_complete', json={
            'pair_id': pair_id,
            'sealed_bundle': sealed,
        }, headers=self.alice_headers)
        self.assertTrue(r.get_json()['success'])

        # 4. B fetches the sealed bundle, decrypts.
        r = self.client.post('/api/device_pair_fetch',
                             json={'code_hash': code_hash})
        body = r.get_json()
        self.assertTrue(body['success'])
        bundle = unseal_pairing_bundle(epk_b_priv, epk_a_pub, code,
                                       body['sealed_bundle'])
        self.assertEqual(base64.b64decode(bundle['master_key']),
                         self.master_key)
        self.assertEqual(bundle['login'], 'alice')

        # Fetching a second time finds nothing — single-use.
        r = self.client.post('/api/device_pair_fetch',
                             json={'code_hash': code_hash})
        self.assertEqual(r.status_code, 404)

    def test_brute_force_attempts_capped(self):
        # Server caps device_pair_enter attempts per pair_id.
        code = generate_pairing_code()
        code_hash = pairing_code_hash(code)
        _, epk_a_pub = gen_pairing_ephemeral()
        self.client.post('/api/device_pair_start', json={
            'code_hash': code_hash,
            'epk_a_pub': base64.b64encode(epk_a_pub).decode(),
        }, headers=self.alice_headers)
        _, epk_b_pub = gen_pairing_ephemeral()
        # 5 attempts succeed, 6th must 429.
        for i in range(5):
            r = self.client.post('/api/device_pair_enter', json={
                'code_hash': code_hash,
                'epk_b_pub': base64.b64encode(epk_b_pub).decode(),
            })
            self.assertEqual(r.status_code, 200, f'attempt {i}')
        r = self.client.post('/api/device_pair_enter', json={
            'code_hash': code_hash,
            'epk_b_pub': base64.b64encode(epk_b_pub).decode(),
        })
        self.assertEqual(r.status_code, 429)


if __name__ == '__main__':
    unittest.main()
