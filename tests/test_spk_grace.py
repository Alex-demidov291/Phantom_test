"""Tests for the SPK history / 14-day grace period.

When a client rotates its signed prekey, the previous SPK must
remain decryptable for in-flight peer X3DH handshakes that grabbed
it from the server bundle just before rotation. The PreKeyStore
keeps a bounded history list; entries older than the grace window
are pruned.
"""

import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from network.cryptolib.identity import IdentityKeys
from network.cryptolib.prekeys import (
    PreKeyStore, SPK_HISTORY_GRACE_SECONDS,
)


def _make_store():
    identity = IdentityKeys.from_master_key(b'\x42' * 32, device_id='dev-1')
    store = PreKeyStore()
    store.ensure_signed_prekey(identity)
    return identity, store


class SPKGrace(unittest.TestCase):
    def test_lookup_by_id_finds_current(self):
        identity, store = _make_store()
        spk = store.signed_prekey
        self.assertIs(store.get_signed_prekey_by_id(spk.key_id), spk)

    def test_rotation_archives_previous(self):
        identity, store = _make_store()
        old = store.signed_prekey
        new = store.ensure_signed_prekey(identity, force_rotate=True)
        self.assertNotEqual(old.key_id, new.key_id)
        self.assertIs(store.signed_prekey, new)
        # Old SPK is still findable by id for the grace window.
        found = store.get_signed_prekey_by_id(old.key_id)
        self.assertIs(found, old)

    def test_pruning_drops_too_old_entries(self):
        identity, store = _make_store()
        store.ensure_signed_prekey(identity, force_rotate=True)
        # Make the archived entry artificially old.
        store.previous_signed_prekeys[0].created_at = (
            time.time() - SPK_HISTORY_GRACE_SECONDS - 1
        )
        store.prune_signed_prekey_history()
        self.assertEqual(store.previous_signed_prekeys, [])

    def test_multiple_rotations_keep_recent_history(self):
        identity, store = _make_store()
        first = store.signed_prekey
        store.ensure_signed_prekey(identity, force_rotate=True)
        second = store.signed_prekey
        store.ensure_signed_prekey(identity, force_rotate=True)
        third = store.signed_prekey
        for old in (first, second):
            self.assertIs(store.get_signed_prekey_by_id(old.key_id), old)
        self.assertIs(store.get_signed_prekey_by_id(third.key_id), third)

    def test_serialise_round_trip_preserves_history(self):
        identity, store = _make_store()
        store.ensure_signed_prekey(identity, force_rotate=True)
        store.ensure_signed_prekey(identity, force_rotate=True)
        reloaded = PreKeyStore.from_dict(store.to_dict())
        self.assertEqual(
            reloaded.signed_prekey.key_id, store.signed_prekey.key_id,
        )
        self.assertEqual(
            sorted(p.key_id for p in reloaded.previous_signed_prekeys),
            sorted(p.key_id for p in store.previous_signed_prekeys),
        )


if __name__ == '__main__':
    unittest.main()
