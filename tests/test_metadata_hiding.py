"""End-to-end metadata hiding tests against the real Flask server.

These tests assert the *server-side* contract: that contact relations,
file names, file types, and archive peer references are not visible
in plaintext to any party that gets to read DB rows or wire bodies.
The cryptographic primitives the client uses are tested separately;
here we only check that the server doesn't accept a path that would
write plaintext metadata, and that the encrypted paths round-trip.
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

from network.cryptolib.identity import IdentityKeys
from network.cryptolib.master_key_binding import sign_master_key_binding
from network.cryptolib.user_blob import encrypt_user_blob, decrypt_user_blob
from network.cryptolib.archive import compute_archive_peer_handle


def _isolate_server_state():
    tmp = tempfile.mkdtemp(prefix='phantom-meta-')
    cwd_orig = os.getcwd()
    os.chdir(tmp)
    return tmp, cwd_orig


def _restore_cwd(tmp, cwd_orig):
    os.chdir(cwd_orig)
    shutil.rmtree(tmp, ignore_errors=True)


def _import_app():
    if 'app' in sys.modules:
        del sys.modules['app']
    if 'settings' in sys.modules:
        del sys.modules['settings']
    import app as app_module
    return app_module


def _register(client, login, password='pw1234', master_key=None,
              device_id='dev-test'):
    master_key = master_key or os.urandom(64)
    cs = opaque_ke_py.client_registration_start(password.encode('utf-8'))
    client.post('/api/opaque/register/start',
                json={'login': login, 'username': login},
                headers={'X-Device-ID': device_id})
    r = client.post('/api/opaque/register/finish',
                    json={
                        'login': login, 'username': login,
                        'registration_request': base64.b64encode(
                            cs.get_message()).decode(),
                    },
                    headers={'X-Device-ID': device_id})
    server_response = base64.b64decode(r.get_json()['server_response'])
    cf = opaque_ke_py.client_registration_finish(
        password.encode('utf-8'), cs.get_state(), server_response,
    )
    blob = json.dumps({
        'salt': base64.b64encode(os.urandom(32)).decode(),
        'nonce': base64.b64encode(os.urandom(12)).decode(),
        'ciphertext': base64.b64encode(os.urandom(64)).decode(),
    })
    b = sign_master_key_binding(master_key, login, blob)
    r = client.post('/api/opaque/register/upload', json={
        'login': login, 'username': login,
        'registration_upload': base64.b64encode(cf.get_message()).decode(),
        'encrypted_master_key': blob,
        'master_key_binding_sig': b['signature'],
        'master_key_binding_sik_pub': b['sik_pub'],
    }, headers={'X-Device-ID': device_id})
    reg = r.get_json()
    headers = {
        'X-Session-Token': reg['session_token'],
        'X-User-Id': str(reg['user_id']),
        'X-Device-ID': device_id,
    }
    return master_key, reg, headers


class EncryptedContactsServerSide(unittest.TestCase):
    def setUp(self):
        self._tmp, self._cwd = _isolate_server_state()
        self.app_mod = _import_app()
        self.client = self.app_mod.app.test_client()

    def tearDown(self):
        _restore_cwd(self._tmp, self._cwd)

    def test_contacts_blob_round_trip(self):
        master_key, _, headers = _register(self.client, 'alice')
        # Initial fetch: no blob yet.
        r = self.client.post('/api/user_blob_get', json={'kind': 'contacts'},
                             headers=headers)
        self.assertTrue(r.get_json()['success'])
        self.assertIsNone(r.get_json()['blob'])

        # Upload an encrypted contact list.
        contacts = [{'login': 'bob', 'username': 'bob', 'user_id': 99}]
        enc = encrypt_user_blob(master_key, 'contacts', contacts)
        r = self.client.post('/api/user_blob_put', json={
            'kind': 'contacts',
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'expected_version': 0,
        }, headers=headers)
        self.assertTrue(r.get_json()['success'], r.get_json())

        # Server-side row must not contain 'bob' in plaintext.
        db = self.app_mod.db
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('SELECT ciphertext FROM user_encrypted_blobs '
                    'WHERE kind = ?', ('contacts',))
        ct = cur.fetchone()[0]
        conn.close()
        self.assertNotIn('bob', ct)
        # And not in the legacy contacts table either: we never wrote it.
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute(
            'SELECT contact_login FROM contacts WHERE contact_owner = ?',
            ('alice',),
        )
        rows = cur.fetchall()
        conn.close()
        self.assertEqual(rows, [])

        # Fetch, decrypt, verify.
        r = self.client.post('/api/user_blob_get', json={'kind': 'contacts'},
                             headers=headers)
        blob = r.get_json()['blob']
        out = decrypt_user_blob(master_key, 'contacts', blob)
        self.assertEqual(out, contacts)

    def test_version_conflict_rejected(self):
        master_key, _, headers = _register(self.client, 'alice')
        enc = encrypt_user_blob(master_key, 'contacts', [])
        # First write at v0 succeeds.
        r = self.client.post('/api/user_blob_put', json={
            'kind': 'contacts',
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'expected_version': 0,
        }, headers=headers)
        self.assertTrue(r.get_json()['success'])
        # Replaying the same v0 update must fail (server is now at v1).
        r = self.client.post('/api/user_blob_put', json={
            'kind': 'contacts',
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'expected_version': 0,
        }, headers=headers)
        self.assertFalse(r.get_json()['success'])
        self.assertEqual(r.get_json()['current_version'], 1)


class EncryptedArchivePeerIndex(unittest.TestCase):
    def setUp(self):
        self._tmp, self._cwd = _isolate_server_state()
        self.app_mod = _import_app()
        self.client = self.app_mod.app.test_client()

    def tearDown(self):
        _restore_cwd(self._tmp, self._cwd)

    def test_peer_handle_not_reversible(self):
        # Two different users archiving messages to the same peer
        # produce DIFFERENT handles — the server can't correlate
        # "alice talks to bob" with "carol talks to bob" via DB.
        alice_mk, _, alice_h = _register(self.client, 'alice',
                                         device_id='dev-A')
        carol_mk, _, carol_h = _register(self.client, 'carol',
                                         device_id='dev-C')
        handle_alice = compute_archive_peer_handle(alice_mk, 'bob')
        handle_carol = compute_archive_peer_handle(carol_mk, 'bob')
        self.assertNotEqual(handle_alice, handle_carol)
        # And the handle is base64-of-32-bytes, not the login.
        self.assertNotIn('bob', handle_alice)
        self.assertEqual(len(base64.b64decode(handle_alice)), 32)

    def test_archive_upload_requires_peer_handle(self):
        _, _, headers = _register(self.client, 'alice')
        # Refuse archive uploads without peer_handle.
        r = self.client.post('/api/archive_upload', json={
            'entries': [{
                'ciphertext': 'YQ==', 'nonce': 'YQ==',
                'message_group_id': 'abc',
            }],
        }, headers=headers)
        self.assertFalse(r.get_json()['success'])

    def test_archive_round_trip_via_handle(self):
        master_key, _, headers = _register(self.client, 'alice')
        handle = compute_archive_peer_handle(master_key, 'bob')
        r = self.client.post('/api/archive_upload', json={
            'entries': [{
                'peer_handle': handle,
                'ciphertext': 'Y2lwaGVydGV4dA==',
                'nonce': 'bm9uY2Vfdmw=',
                'message_group_id': 'mg-1',
            }],
        }, headers=headers)
        self.assertTrue(r.get_json()['success'], r.get_json())
        # Fetch by handle works.
        r = self.client.post('/api/archive_fetch', json={
            'peer_handle': handle, 'since_archive_id': 0,
        }, headers=headers)
        body = r.get_json()
        self.assertTrue(body['success'])
        self.assertEqual(len(body['entries']), 1)
        # And the row on disk has no peer_login / peer_user_id.
        db = self.app_mod.db
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('SELECT peer_login, peer_user_id FROM archive '
                    'WHERE message_group_id = ?', ('mg-1',))
        row = cur.fetchone()
        conn.close()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])


if __name__ == '__main__':
    unittest.main()
