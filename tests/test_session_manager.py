"""SessionManager scenarios — integration of X3DH + Double Ratchet +
persistence + replay protection.

Each test simulates the wire between two clients without involving
the Flask server or the network layer. The fake-server here is just
an in-memory dict of prekey bundles.
"""

import os
import sys
import shutil
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Override DATA_PATH BEFORE importing cryptolib.storage — once the
# storage module captures the path, we can't move it.
_TMP_DIR = tempfile.mkdtemp(prefix='phantom-test-')
import utils  # noqa: E402
utils.DATA_PATH = type(utils.DATA_PATH)(_TMP_DIR)

from network.cryptolib.identity import IdentityKeys              # noqa: E402
from network.cryptolib.prekeys import PreKeyStore                # noqa: E402
from network.cryptolib.session import (                          # noqa: E402
    SessionManager, UnknownInitialMessage, DuplicateWire,
    SessionRekeyRequired,
)
import base64                                                    # noqa: E402


class FakeServer:
    """In-memory prekey directory + per-(user, device) bundle store."""

    def __init__(self):
        self.users = {}  # login -> {'user_id', 'identity', 'devices': {dev_id: store}}

    def register_user(self, login, user_id):
        self.users[login] = {'user_id': user_id, 'devices': {}}

    def register_device(self, login, device_id, master_key):
        identity = IdentityKeys.from_master_key(master_key, device_id=device_id)
        store = PreKeyStore()
        store.ensure_signed_prekey(identity)
        store.generate_one_time_prekeys(20)
        self.users[login]['devices'][device_id] = {
            'identity': identity,
            'store': store,
            'master_key': master_key,
        }
        return identity, store

    def bundle_for(self, contact_login):
        rec = self.users[contact_login]
        # Take the SIK from the first device — SIK is per-USER, so any
        # device's identity has the same SIK pub.
        first = next(iter(rec['devices'].values()))
        identity = first['identity']
        return {
            'user_id': rec['user_id'],
            'login': contact_login,
            'identity': {
                'ik': base64.b64encode(
                    IdentityKeys.user_ik_pub_bytes(first['master_key'])
                ).decode(),
                'sik': base64.b64encode(identity.sik_pub_bytes).decode(),
                'identity_signature': base64.b64encode(
                    identity.sik_priv.sign(
                        IdentityKeys.user_ik_pub_bytes(first['master_key'])
                    )
                ).decode(),
            },
            'devices': [
                {
                    'device_id': dev_id,
                    'spk_id': info['store'].signed_prekey.key_id,
                    'spk': base64.b64encode(
                        info['store'].signed_prekey.pub_bytes
                    ).decode(),
                    'spk_signature': base64.b64encode(
                        info['store'].signed_prekey.signature
                    ).decode(),
                    'opk_id': info['store'].one_time_prekeys[0].key_id
                              if info['store'].one_time_prekeys else None,
                    'opk': (base64.b64encode(
                        info['store'].one_time_prekeys[0].pub_bytes
                    ).decode() if info['store'].one_time_prekeys else None),
                    'dev_ik': base64.b64encode(info['identity'].ik_pub_bytes).decode(),
                    'dev_ik_signature': base64.b64encode(
                        info['identity'].sign_identity_binding()
                    ).decode(),
                }
                for dev_id, info in rec['devices'].items()
            ],
        }


def make_client(server, login, device_id):
    info = server.users[login]['devices'][device_id]
    bundle_fetcher = lambda peer: server.bundle_for(peer)
    sm = SessionManager(
        own_login=login, own_device_id=device_id,
        identity_keys=info['identity'],
        prekey_store=info['store'],
        master_key=info['master_key'],
        bundle_fetcher=bundle_fetcher,
    )
    return sm


class _IsolatedDataPath(unittest.TestCase):
    """Each test gets its own DATA_PATH subdir to avoid cross-test
    leak through the on-disk session store."""

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix='phantom-test-case-', dir=_TMP_DIR)
        utils.DATA_PATH = type(utils.DATA_PATH)(self.workdir)

    def tearDown(self):
        shutil.rmtree(self.workdir, ignore_errors=True)


class SessionManagerScenarios(_IsolatedDataPath):
    def setUp(self):
        super().setUp()
        self.server = FakeServer()
        self.server.register_user('alice', user_id=1)
        self.server.register_user('bob', user_id=2)
        self.server.register_device('alice', 'A', b'\x01' * 32)
        self.server.register_device('bob', 'B', b'\x02' * 32)
        self.alice = make_client(self.server, 'alice', 'A')
        self.bob = make_client(self.server, 'bob', 'B')

    def _alice_send(self, plaintext):
        bundle = self.server.bundle_for('bob')
        wire = self.alice.encrypt_for_device(
            peer_login='bob', peer_device_id='B',
            plaintext=plaintext,
            identity_bundle=bundle['identity'],
            device_bundle=bundle['devices'][0],
        )
        return wire

    def _bob_recv(self, wire):
        return self.bob.decrypt_from_device('alice', 'A', wire)

    def _bob_send(self, plaintext):
        bundle = self.server.bundle_for('alice')
        wire = self.bob.encrypt_for_device(
            peer_login='alice', peer_device_id='A',
            plaintext=plaintext,
            identity_bundle=bundle['identity'],
            device_bundle=bundle['devices'][0],
        )
        return wire

    def _alice_recv(self, wire):
        return self.alice.decrypt_from_device('bob', 'B', wire)

    def test_basic_round_trip(self):
        plaintext = self._bob_recv(self._alice_send(b'hello'))
        self.assertEqual(plaintext, b'hello')
        plaintext = self._alice_recv(self._bob_send(b'hi back'))
        self.assertEqual(plaintext, b'hi back')

    def test_duplicate_wire_recognised(self):
        wire = self._alice_send(b'once')
        self._bob_recv(wire)
        with self.assertRaises(DuplicateWire):
            self._bob_recv(wire)

    def test_unknown_inbound_ratchet_buffered(self):
        # Bob has no session yet; deliver a *ratchet* wire (not the
        # x3dh-init) to him, mimicking out-of-order delivery where the
        # init is still in flight. The session manager must buffer it
        # and surface UnknownInitialMessage rather than dropping or
        # producing garbage.
        #
        # To produce a ratchet (rather than x3dh-init) wire from
        # Alice, we need the initiator's `pending_init` cleared, which
        # happens once Alice has decrypted a reply. We set that up
        # against a third party Charlie so Bob still has no session
        # when we feed the wire in.
        self.server.register_user('charlie', user_id=3)
        self.server.register_device('charlie', 'C', b'\x03' * 32)
        charlie = make_client(self.server, 'charlie', 'C')
        bundle_c = self.server.bundle_for('charlie')
        first = self.alice.encrypt_for_device(
            peer_login='charlie', peer_device_id='C',
            plaintext=b'init',
            identity_bundle=bundle_c['identity'],
            device_bundle=bundle_c['devices'][0],
        )
        charlie.decrypt_from_device('alice', 'A', first)
        # Charlie replies — Alice's pending_init clears after she
        # decrypts that reply.
        bundle_a = self.server.bundle_for('alice')
        reply = charlie.encrypt_for_device(
            peer_login='alice', peer_device_id='A',
            plaintext=b'pong',
            identity_bundle=bundle_a['identity'],
            device_bundle=bundle_a['devices'][0],
        )
        self.alice.decrypt_from_device('charlie', 'C', reply)
        wire2 = self.alice.encrypt_for_device(
            peer_login='charlie', peer_device_id='C',
            plaintext=b'follow',
            identity_bundle=bundle_c['identity'],
            device_bundle=bundle_c['devices'][0],
        )
        self.assertEqual(wire2['type'], 'ratchet')
        with self.assertRaises(UnknownInitialMessage):
            self.bob.decrypt_from_device('alice-bogus', 'A-bogus', wire2)

    def test_x3dh_init_replay_idempotent(self):
        # A duplicate x3dh-init must NOT consume another OPK or break
        # the existing session — it's recognised by fingerprint and
        # routed back through the existing session for trial decrypt.
        wire = self._alice_send(b'first')
        self._bob_recv(wire)  # establishes session
        # Simulate the network re-delivering the same x3dh-init.
        # Force Alice to re-send the same x3dh-init by clearing state.
        # We can mimic this by keeping the original `wire` variable
        # and re-feeding it: it's already type=x3dh-init.
        self.assertEqual(wire['type'], 'x3dh-init')
        with self.assertRaises(DuplicateWire):
            self._bob_recv(wire)

    def test_session_persists_across_manager_reload(self):
        plaintext = self._bob_recv(self._alice_send(b'before'))
        self.assertEqual(plaintext, b'before')
        # Re-create Bob's manager with the same on-disk state.
        bob_info = self.server.users['bob']['devices']['B']
        bob2 = SessionManager(
            own_login='bob', own_device_id='B',
            identity_keys=bob_info['identity'],
            prekey_store=bob_info['store'],
            master_key=bob_info['master_key'],
            bundle_fetcher=lambda p: self.server.bundle_for(p),
        )
        plaintext = bob2.decrypt_from_device(
            'alice', 'A', self._alice_send(b'after-reload'),
        )
        self.assertEqual(plaintext, b'after-reload')


class FanOutMultiDevice(_IsolatedDataPath):
    def setUp(self):
        super().setUp()
        self.server = FakeServer()
        self.server.register_user('alice', user_id=1)
        self.server.register_user('bob', user_id=2)
        self.server.register_device('alice', 'A', b'\x01' * 32)
        self.server.register_device('bob', 'B1', b'\x02' * 32)
        self.server.register_device('bob', 'B2', b'\x02' * 32)
        self.alice = make_client(self.server, 'alice', 'A')

    def test_fan_out_reaches_both_bob_devices(self):
        bundle = self.server.bundle_for('bob')
        envs = self.alice.fan_out_encrypt(
            peer_login='bob',
            plaintext=b'broadcast',
            peer_user_bundle=bundle,
        )
        targets = sorted(e['target_device_id'] for e in envs)
        self.assertEqual(targets, ['B1', 'B2'])
        # And each is independently decryptable by its target device.
        for env in envs:
            recv = make_client(self.server, 'bob', env['target_device_id'])
            plaintext = recv.decrypt_from_device('alice', 'A', env['wire'])
            self.assertEqual(plaintext, b'broadcast')

    def test_per_device_compromise_does_not_leak_other_device_ik(self):
        b1 = self.server.users['bob']['devices']['B1']['identity']
        b2 = self.server.users['bob']['devices']['B2']['identity']
        self.assertNotEqual(b1.ik_pub_bytes, b2.ik_pub_bytes)
        self.assertEqual(b1.sik_pub_bytes, b2.sik_pub_bytes)


if __name__ == '__main__':
    unittest.main()
