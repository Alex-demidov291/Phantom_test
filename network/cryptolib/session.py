import base64
import hashlib
import json
import os
import threading

from network.cryptolib.double_ratchet import (
    DoubleRatchet, RatchetError, DuplicateMessage,
)
from network.cryptolib.x3dh import (
    X3DHError, build_initial_message, accept_initial_message,
)
from network.cryptolib.storage import (
    PREKEY_KEY_INFO, SESSION_KEY_INFO,
    encrypt_and_write, read_and_decrypt,
    prekey_store_path, session_path, sessions_root_dir,
)
from network.cryptolib.padding import pad_plaintext, unpad_plaintext


WIRE_VERSION = 3


class SessionError(Exception):
    pass


class UnknownInitialMessage(SessionError):
    pass


class DuplicateWire(SessionError):
    pass


class SessionRekeyRequired(SessionError):
    pass


def _x3dh_fingerprint(x3dh_header):
    payload = json.dumps(
        {
            'ik': x3dh_header.get('ik'),
            'sik': x3dh_header.get('sik'),
            'ek': x3dh_header.get('ek'),
            'spk_id': x3dh_header.get('spk_id'),
            'opk_id': x3dh_header.get('opk_id'),
        },
        sort_keys=True, separators=(',', ':'),
    ).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


class PeerSession:
    def __init__(self, peer_login, peer_device_id, peer_ik, peer_sik, ad,
                 ratchet, pending_init=None, seen_x3dh=None,
                 pending_inbound=None, peer_dev_ik=None):
        self.peer_login = peer_login
        self.peer_device_id = peer_device_id
        self.peer_ik = peer_ik
        self.peer_sik = peer_sik
        self.peer_dev_ik = peer_dev_ik
        self.ad = ad
        self.ratchet = ratchet
        self.pending_init = pending_init
        self.seen_x3dh = list(seen_x3dh or [])
        self.pending_inbound = list(pending_inbound or [])

    def to_dict(self):
        return {
            'peer_login': self.peer_login,
            'peer_device_id': self.peer_device_id,
            'peer_ik': base64.b64encode(self.peer_ik).decode(),
            'peer_sik': base64.b64encode(self.peer_sik).decode(),
            'peer_dev_ik': (base64.b64encode(self.peer_dev_ik).decode()
                            if self.peer_dev_ik else None),
            'ad': base64.b64encode(self.ad).decode(),
            'ratchet': self.ratchet.to_dict(),
            'pending_init': self.pending_init,
            'seen_x3dh': self.seen_x3dh[-32:],
            'pending_inbound': self.pending_inbound[-50:],
        }

    @classmethod
    def from_dict(cls, d):
        peer_dev_ik_b64 = d.get('peer_dev_ik')
        return cls(
            peer_login=d['peer_login'],
            peer_device_id=d.get('peer_device_id', ''),
            peer_ik=base64.b64decode(d['peer_ik']),
            peer_sik=base64.b64decode(d['peer_sik']),
            peer_dev_ik=(base64.b64decode(peer_dev_ik_b64)
                         if peer_dev_ik_b64 else None),
            ad=base64.b64decode(d['ad']),
            ratchet=DoubleRatchet.from_dict(d['ratchet']),
            pending_init=d.get('pending_init'),
            seen_x3dh=d.get('seen_x3dh') or [],
            pending_inbound=d.get('pending_inbound') or [],
        )

    def encrypt_wire(self, plaintext):
        padded = pad_plaintext(plaintext)
        header, ciphertext = self.ratchet.encrypt(padded, self.ad)
        ct_b64 = base64.b64encode(ciphertext).decode()
        if self.pending_init is not None:
            return {
                'type': 'x3dh-init',
                'v': WIRE_VERSION,
                'x3dh': self.pending_init,
                'header': header,
                'ciphertext': ct_b64,
            }
        return {
            'type': 'ratchet',
            'v': WIRE_VERSION,
            'header': header,
            'ciphertext': ct_b64,
        }


class SessionManager:
    def __init__(self, own_login, own_device_id, identity_keys, prekey_store,
                 master_key, bundle_fetcher):
        self.own_login = own_login
        self.own_device_id = own_device_id
        self.identity = identity_keys
        self.prekey_store = prekey_store
        self.master_key = master_key
        self.bundle_fetcher = bundle_fetcher
        self._sessions = {}
        self._lock = threading.RLock()
        self._persist_lock = threading.Lock()

    def save_prekey_store(self):
        path = str(prekey_store_path(self.own_login, self.own_device_id))
        encrypt_and_write(path, self.master_key, PREKEY_KEY_INFO,
                          self.prekey_store.to_dict())

    @classmethod
    def load_prekey_store_dict(cls, own_login, own_device_id, master_key):
        path = str(prekey_store_path(own_login, own_device_id))
        try:
            return read_and_decrypt(path, master_key, PREKEY_KEY_INFO)
        except Exception:
            try:
                os.unlink(path)
            except OSError:
                pass
            return None

    def _session_path(self, peer_login, peer_device_id):
        return str(session_path(self.own_login, self.own_device_id,
                                peer_login, peer_device_id))

    def _save_session(self, session):
        with self._persist_lock:
            encrypt_and_write(
                self._session_path(session.peer_login, session.peer_device_id),
                self.master_key,
                SESSION_KEY_INFO,
                session.to_dict(),
            )

    def _load_session(self, peer_login, peer_device_id):
        try:
            d = read_and_decrypt(
                self._session_path(peer_login, peer_device_id),
                self.master_key,
                SESSION_KEY_INFO,
            )
        except Exception:
            self._drop_session_file(peer_login, peer_device_id)
            return None
        if d is None:
            return None
        try:
            return PeerSession.from_dict(d)
        except Exception:
            self._drop_session_file(peer_login, peer_device_id)
            return None

    def _drop_session_file(self, peer_login, peer_device_id):
        try:
            os.unlink(self._session_path(peer_login, peer_device_id))
        except OSError:
            pass

    def _session_key(self, peer_login, peer_device_id):
        return (peer_login, peer_device_id)

    def _get_loaded_session(self, peer_login, peer_device_id):
        with self._lock:
            key = self._session_key(peer_login, peer_device_id)
            sess = self._sessions.get(key)
            if sess is None:
                sess = self._load_session(peer_login, peer_device_id)
                if sess is not None:
                    self._sessions[key] = sess
            return sess

    def has_session(self, peer_login, peer_device_id):
        return self._get_loaded_session(peer_login, peer_device_id) is not None

    def forget_session(self, peer_login, peer_device_id):
        with self._lock:
            self._sessions.pop(self._session_key(peer_login, peer_device_id), None)
            self._drop_session_file(peer_login, peer_device_id)

    def prepare_outbound_session(self, peer_login, peer_device_id,
                                 identity_bundle, device_bundle,
                                 force_new_session=False):
        with self._lock:
            if force_new_session:
                self.forget_session(peer_login, peer_device_id)
            session = self._get_loaded_session(peer_login, peer_device_id)
            if session is not None:
                return session
            session = self._establish_outbound(
                peer_login, peer_device_id, identity_bundle, device_bundle,
            )
            self._sessions[self._session_key(peer_login, peer_device_id)] = session
            self._save_session(session)
            return session

    def encrypt_for_device(self, peer_login, peer_device_id, plaintext,
                           identity_bundle, device_bundle,
                           force_new_session=False):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        with self._lock:
            if force_new_session:
                self.forget_session(peer_login, peer_device_id)
            session = self._get_loaded_session(peer_login, peer_device_id)
            if session is None:
                session = self._establish_outbound(
                    peer_login, peer_device_id, identity_bundle, device_bundle,
                )
                self._sessions[self._session_key(peer_login, peer_device_id)] = session
            wire = session.encrypt_wire(plaintext)
            self._save_session(session)
            return wire

    def fan_out_encrypt(self, peer_login, plaintext, peer_user_bundle,
                        own_other_devices_bundle=None,
                        force_new_session_for=None):
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext

        force_set = set(force_new_session_for or ())
        envelopes = []
        identity = peer_user_bundle.get('identity')
        peer_devices = peer_user_bundle.get('devices') or []
        peer_user_id = peer_user_bundle.get('user_id')
        for d in peer_devices:
            target = (peer_login, d['device_id'])
            wire = self.encrypt_for_device(
                peer_login=peer_login,
                peer_device_id=d['device_id'],
                plaintext=plaintext_bytes,
                identity_bundle=identity,
                device_bundle=d,
                force_new_session=target in force_set,
            )
            envelopes.append({
                'target_user_id': peer_user_id,
                'target_device_id': d['device_id'],
                'wire': wire,
            })

        if own_other_devices_bundle:
            own_identity = own_other_devices_bundle.get('identity')
            own_user_id = own_other_devices_bundle.get('user_id')
            own_devices = own_other_devices_bundle.get('devices') or []
            for d in own_devices:
                if d['device_id'] == self.own_device_id:
                    continue
                target = (self.own_login, d['device_id'])
                wire = self.encrypt_for_device(
                    peer_login=self.own_login,
                    peer_device_id=d['device_id'],
                    plaintext=plaintext_bytes,
                    identity_bundle=own_identity,
                    device_bundle=d,
                    force_new_session=target in force_set,
                )
                envelopes.append({
                    'target_user_id': own_user_id,
                    'target_device_id': d['device_id'],
                    'wire': wire,
                })
        return envelopes

    def decrypt_from_device(self, peer_login, peer_device_id, wire):
        if isinstance(wire, str):
            wire = json.loads(wire)
        if not isinstance(wire, dict):
            raise SessionError('wire payload is not a JSON object')
        msg_type = wire.get('type')
        with self._lock:
            if msg_type == 'x3dh-init':
                return self._handle_inbound_x3dh(peer_login, peer_device_id, wire)
            if msg_type == 'ratchet':
                return self._handle_inbound_ratchet(peer_login, peer_device_id, wire)
            raise SessionError(f'unsupported wire type: {msg_type!r}')

    def _handle_inbound_x3dh(self, peer_login, peer_device_id, wire):
        x3dh_header = wire.get('x3dh')
        if not x3dh_header:
            raise SessionError('x3dh-init wire missing x3dh header')
        fp = _x3dh_fingerprint(x3dh_header)
        existing = self._get_loaded_session(peer_login, peer_device_id)

        if existing is not None and fp in existing.seen_x3dh:
            return self._decrypt_with_session(
                existing, wire, peer_login, peer_device_id,
                already_x3dh=True,
            )
        new_session = self._accept_inbound(peer_login, peer_device_id, wire)
        new_session.seen_x3dh.append(fp)
        if existing is not None:
            new_session.pending_inbound = list(existing.pending_inbound)
        self._sessions[self._session_key(peer_login, peer_device_id)] = new_session
        self._save_session(new_session)
        self.save_prekey_store()
        return self._decrypt_with_session(
            new_session, wire, peer_login, peer_device_id,
            already_x3dh=False,
        )

    def _handle_inbound_ratchet(self, peer_login, peer_device_id, wire):
        session = self._get_loaded_session(peer_login, peer_device_id)
        if session is None:

            self._buffer_pending_inbound(peer_login, peer_device_id, wire)
            raise UnknownInitialMessage(
                f'no session for {peer_login}:{peer_device_id} but received '
                f'ratchet — buffered for later'
            )
        return self._decrypt_with_session(
            session, wire, peer_login, peer_device_id, already_x3dh=False,
        )

    def _decrypt_with_session(self, session, wire, peer_login, peer_device_id,
                              already_x3dh):
        header = wire['header']
        ciphertext = base64.b64decode(wire['ciphertext'])
        try:
            plaintext = session.ratchet.decrypt(header, ciphertext, session.ad)
        except DuplicateMessage:

            raise DuplicateWire(
                f'wire from {peer_login}:{peer_device_id} already processed'
            )
        except RatchetError as exc:

            raise SessionRekeyRequired(
                f'ratchet failure on {peer_login}:{peer_device_id}: {exc}'
            )

        if session.pending_init is not None:
            session.pending_init = None
        self._save_session(session)
        try:
            return unpad_plaintext(plaintext)
        except ValueError:
            raise SessionError(
                f'unpad failed for {peer_login}:{peer_device_id} — '
                'session likely speaks an older wire format'
            )

    def _buffer_pending_inbound(self, peer_login, peer_device_id, wire):
        key = self._session_key(peer_login, peer_device_id)
        bucket = self._sessions.get(('__pending__', key))
        if bucket is None:
            bucket = []
            self._sessions[('__pending__', key)] = bucket
        if len(bucket) >= 50:
            bucket.pop(0)
        bucket.append(wire)

    def drain_pending_inbound(self, peer_login, peer_device_id):
        key = self._session_key(peer_login, peer_device_id)
        with self._lock:
            return self._sessions.pop(('__pending__', key), [])

    def _establish_outbound(self, peer_login, peer_device_id,
                            identity_bundle, device_bundle):
        if not identity_bundle or not device_bundle:
            raise SessionError(
                f"can't start E2EE session with {peer_login}:{peer_device_id}: "
                "missing identity or device bundle"
            )
        ik_b64 = device_bundle.get('dev_ik') or identity_bundle['ik']
        peer_dev_ik = (base64.b64decode(device_bundle['dev_ik'])
                       if device_bundle.get('dev_ik') else None)
        merged = {
            'ik': ik_b64,
            'sik': identity_bundle['sik'],
            'identity_signature': (
                device_bundle.get('dev_ik_signature')
                or identity_bundle['identity_signature']
            ),
            'spk_id': device_bundle['spk_id'],
            'spk': device_bundle['spk'],
            'spk_signature': device_bundle['spk_signature'],
            'opk_id': device_bundle.get('opk_id'),
            'opk': device_bundle.get('opk'),
        }
        sk, ad, header_x3dh, peer_initial_dh = build_initial_message(
            self.identity, merged,
        )
        ratchet = DoubleRatchet.init_initiator(sk, peer_initial_dh)
        return PeerSession(
            peer_login=peer_login,
            peer_device_id=peer_device_id,
            peer_ik=base64.b64decode(identity_bundle['ik']),
            peer_sik=base64.b64decode(identity_bundle['sik']),
            peer_dev_ik=peer_dev_ik,
            ad=ad,
            ratchet=ratchet,
            pending_init=header_x3dh,
        )

    def _accept_inbound(self, peer_login, peer_device_id, wire):
        x3dh_header = wire.get('x3dh')
        if not x3dh_header:
            raise SessionError('x3dh-init wire missing x3dh header')
        sk, ad, peer_ik, peer_sik, consumed_opk, spk_pub = accept_initial_message(
            self.identity, self.prekey_store, x3dh_header,
        )
        spk = self.prekey_store.get_signed_prekey_by_id(x3dh_header['spk_id'])
        if spk is None:
            raise SessionError('signed prekey vanished between accept and init')
        ratchet = DoubleRatchet.init_responder(
            sk, spk.priv_bytes, spk.pub_bytes,
        )
        return PeerSession(
            peer_login=peer_login,
            peer_device_id=peer_device_id,
            peer_ik=peer_ik,
            peer_sik=peer_sik,
            peer_dev_ik=peer_ik,
            ad=ad,
            ratchet=ratchet,
            pending_init=None,
        )

    def peer_identity(self, peer_login, peer_device_id):
        sess = self._get_loaded_session(peer_login, peer_device_id)
        if sess is None:
            return None
        return (sess.peer_dev_ik or sess.peer_ik), sess.peer_sik
