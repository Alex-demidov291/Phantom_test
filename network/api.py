import hashlib
import json
import os
import base64
import platform
import uuid
from datetime import datetime, timezone
from PyQt6.QtCore import QSettings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import opaque_ke_py
from network.manager import NetworkManager
from network.cache import FileCache
from network.crypto import (
    gen_msg_master_key, encrypt_master_key, decrypt_master_key,
)
from network.cryptolib import (
    IdentityKeys, PreKeyStore, SessionManager,
    UnknownInitialMessage, SessionError,
    DuplicateWire, SessionRekeyRequired,
    archive_encrypt, archive_decrypt,
    compute_archive_peer_handle,
    compute_safety_number, format_safety_number,
    safety_qr_payload, verify_scan_code,
    safety_qr_matrix, render_qr_matrix_ascii,
)
from network.cryptolib.master_key_binding import (
    sign_master_key_binding, verify_master_key_binding,
    MasterKeyBindingError,
)
from network.cryptolib.sealed_sender import (
    seal_envelope, unseal_envelope, SealedSenderError,
)
from network.cryptolib.user_blob import (
    encrypt_user_blob, decrypt_user_blob, UserBlobError,
)
from network.cryptolib.prekeys import OPK_REFILL_THRESHOLD, DEFAULT_OPK_BATCH
from network.transport import AsyncHTTPRequest


class MessengerAPI:
    def __init__(self, host='localhost', port=6666):
        self.network_manager = NetworkManager(host, port)
        self.file_cache = None
        self.login_in_progress = False
        self.device_id = None
        self.user_login = None
        self.master_key_bytes = None
        self.identity = None
        self.prekey_store = None
        self.session_manager = None
        self.encrypted_master_key = None

    def init_device_id(self):
        settings = QSettings("Phantom", "Messenger")
        device_id = settings.value("device_id", "")
        if not device_id:
            device_id = str(uuid.uuid4())
            settings.setValue("device_id", device_id)
        self.device_id = device_id

    def _device_label(self):
        try:
            return f'{platform.system()} {platform.node()}'.strip()[:100] or 'device'
        except Exception:
            return 'device'

    def get_user_info(self, token, user_id, target_login):
        data = {'user_token': token, 'user_id': user_id, 'target_login': target_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_user_info', data)

    def set_user_credentials(self, session_token, user_id, user_login=None):
        if user_login is not None:
            self.user_login = user_login
        self.network_manager.set_credentials(session_token=session_token, user_id=user_id, user_login=self.user_login)
        if user_id:
            self.file_cache = FileCache(user_id)

    def set_session_token(self, session_token):
        self.network_manager.session_token = session_token

    def auth(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        response = self.network_manager.send_sync_request('auth', data)
        if response and response.get('success'):
            self.network_manager.set_credentials(session_token=self.network_manager.session_token, user_token=token,
                                                 user_id=user_id)
            self.network_manager.start_event_listener()
        return response

    def init_e2ee(self, master_key):
        if not self.device_id:
            self.init_device_id()
        self.master_key_bytes = bytes(master_key)
        self.identity = IdentityKeys.from_master_key(
            self.master_key_bytes, device_id=self.device_id,
        )

        own_login = self.user_login or 'unknown'
        stored = SessionManager.load_prekey_store_dict(
            own_login, self.device_id, self.master_key_bytes,
        )
        if stored is not None:
            self.prekey_store = PreKeyStore.from_dict(stored)
        else:
            self.prekey_store = PreKeyStore()

        self.session_manager = SessionManager(
            own_login=own_login,
            own_device_id=self.device_id,
            identity_keys=self.identity,
            prekey_store=self.prekey_store,
            master_key=self.master_key_bytes,
            bundle_fetcher=self._fetch_prekey_bundle,
        )

        self._publish_identity_bundle()
        self._register_device()
        self.prekey_store.prune_signed_prekey_history()
        self._ensure_signed_prekey_published(force_rotate=True)
        self._maybe_refill_one_time_prekeys()
        self.session_manager.save_prekey_store()

    def _publish_identity_bundle(self):
        user_ik = IdentityKeys.user_ik_pub_bytes(self.master_key_bytes)
        bundle = json.dumps({
            'x25519': base64.b64encode(user_ik).decode(),
            'ed25519': base64.b64encode(self.identity.sik_pub_bytes).decode(),
        }, separators=(',', ':'))
        signature = base64.b64encode(self.identity.sign(user_ik)).decode()
        self.network_manager.send_sync_request('publish_public_key', {
            'public_key': bundle,
            'signature': signature,
        })

    def _register_device(self):
        dev_ik_pub = self.identity.ik_pub_bytes
        dev_ik_sig = self.identity.sign(dev_ik_pub)
        self.network_manager.send_sync_request('register_device', {
            'device_label': self._device_label(),
            'dev_ik': base64.b64encode(dev_ik_pub).decode(),
            'dev_ik_signature': base64.b64encode(dev_ik_sig).decode(),
        })

    def _ensure_signed_prekey_published(self, force_rotate=False):
        spk = self.prekey_store.ensure_signed_prekey(
            self.identity, force_rotate=force_rotate,
        )
        self.network_manager.send_sync_request('upload_signed_prekey', {
            'spk_id': spk.key_id,
            'public_key': base64.b64encode(spk.pub_bytes).decode(),
            'signature': base64.b64encode(spk.signature).decode(),
        })

    def _maybe_refill_one_time_prekeys(self):
        resp = self.network_manager.send_sync_request('get_one_time_prekey_count', {})
        remote = (resp or {}).get('count', 0) if isinstance(resp, dict) else 0
        if remote >= OPK_REFILL_THRESHOLD:
            return
        new_keys = self.prekey_store.generate_one_time_prekeys(DEFAULT_OPK_BATCH)
        payload = [
            {'opk_id': k.key_id,
             'public_key': base64.b64encode(k.pub_bytes).decode()}
            for k in new_keys
        ]
        self.network_manager.send_sync_request('upload_one_time_prekeys', {
            'prekeys': payload,
        })

    def _fetch_prekey_bundle(self, contact_login):
        resp = self.network_manager.send_sync_request('get_prekey_bundle', {
            'contact_login': contact_login,
        })
        if not resp or not resp.get('success'):
            return None
        return {
            'user_id': resp.get('user_id'),
            'login': resp.get('login'),
            'identity': resp.get('identity'),
            'devices': resp.get('devices') or [],
        }

    def _fetch_own_other_devices_bundle(self):
        if not self.user_login:
            return None
        return self._fetch_prekey_bundle(self.user_login)

    def get_message_checkpoint(self, peer_user_id):
        if not (self.user_login and self.device_id and self.master_key_bytes):
            return 0
        from network.cryptolib.storage import load_message_checkpoint
        cp = load_message_checkpoint(self.user_login, self.device_id,
                                     self.master_key_bytes)
        return int(cp.get(str(peer_user_id), 0))

    def update_message_checkpoint(self, peer_user_id, last_id):
        if not (self.user_login and self.device_id and self.master_key_bytes):
            return
        if not isinstance(last_id, int) or last_id <= 0:
            return
        from network.cryptolib.storage import (
            load_message_checkpoint, save_message_checkpoint,
        )
        cp = load_message_checkpoint(self.user_login, self.device_id,
                                     self.master_key_bytes)
        key = str(peer_user_id)
        cur = int(cp.get(key, 0))
        if last_id > cur:
            cp[key] = last_id
            save_message_checkpoint(self.user_login, self.device_id,
                                    self.master_key_bytes, cp)

    def warm_sessions_for(self, peer_login):
        if not self.session_manager:
            return {'ready': False, 'reason': 'no_session_manager'}
        bundle = self._fetch_prekey_bundle(peer_login)
        if not bundle or not bundle.get('devices'):
            return {'ready': False, 'reason': 'no_devices', 'devices': []}
        identity = bundle.get('identity')
        ready_devices = []
        missing_devices = []
        for d in bundle['devices']:
            dev_id = d.get('device_id')
            if not dev_id:
                continue
            if self.session_manager.has_session(peer_login, dev_id):
                ready_devices.append(dev_id)
                continue
            try:
                self.session_manager.prepare_outbound_session(
                    peer_login=peer_login,
                    peer_device_id=dev_id,
                    identity_bundle=identity,
                    device_bundle=d,
                )
                ready_devices.append(dev_id)
            except Exception as exc:
                missing_devices.append({'device_id': dev_id, 'error': str(exc)})
        return {
            'ready': not missing_devices,
            'devices': ready_devices,
            'missing': missing_devices,
        }

    def list_my_devices(self, callback=None):
        if callback is None:
            callback = lambda x: None
        make_server_request_async('list_my_devices', {}, callback)

    def unlink_device(self, device_id, callback=None):
        if callback is None:
            callback = lambda x: None
        make_server_request_async('unlink_device', {'device_id': device_id}, callback)

    def _archive_one(self, peer_login, payload, message_group_id):
        if not self.master_key_bytes:
            return None
        enc = archive_encrypt(self.master_key_bytes, payload)
        peer_handle = compute_archive_peer_handle(
            self.master_key_bytes, peer_login,
        )
        return {
            'peer_handle': peer_handle,
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'message_group_id': message_group_id,
        }

    def archive_upload_async(self, entries, callback=None):
        if callback is None:
            callback = lambda x: None
        if not entries:
            callback({'success': True})
            return
        make_server_request_async('archive_upload', {'entries': entries}, callback)

    def archive_fetch(self, peer_login=None, since_archive_id=0):
        data = {'since_archive_id': since_archive_id}
        if peer_login and self.master_key_bytes:
            data['peer_handle'] = compute_archive_peer_handle(
                self.master_key_bytes, peer_login,
            )
        resp = self.network_manager.send_sync_request('archive_fetch', data)
        if not resp or not resp.get('success'):
            return []
        out = []
        for entry in resp.get('entries', []):
            try:
                payload = archive_decrypt(self.master_key_bytes,
                                          entry['ciphertext'], entry['nonce'])
            except Exception:
                continue
            payload['_archive_id'] = entry['archive_id']
            payload['_peer_login'] = (
                payload.get('receiver_login')
                if payload.get('kind') == 'sent'
                else payload.get('sender_login')
            ) or entry.get('peer_login')
            payload['_peer_user_id'] = entry.get('peer_user_id')
            payload['_message_group_id'] = entry.get('message_group_id')
            payload['_created_at'] = entry.get('created_at')
            out.append(payload)
        return out

    def encrypt_file_data(self, file_data, thumbnail_data):
        if not self.session_manager:
            raise SessionError('Session manager not initialised')
        file_key = os.urandom(32)
        nonce_file = os.urandom(12)
        aesgcm = AESGCM(file_key)
        ciphertext = aesgcm.encrypt(nonce_file, file_data, None)
        result = {
            'file_key': base64.b64encode(file_key).decode('utf-8'),
            'nonce_file': base64.b64encode(nonce_file).decode('utf-8'),
            'sha256': hashlib.sha256(file_data).hexdigest(),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        }
        if thumbnail_data:
            nonce_thumb = os.urandom(12)
            thumb_cipher = aesgcm.encrypt(nonce_thumb, thumbnail_data, None)
            result['thumbnail'] = base64.b64encode(thumb_cipher).decode('utf-8')
            result['nonce_thumbnail'] = base64.b64encode(nonce_thumb).decode('utf-8')
        return result

    def decrypt_file_bytes(self, ciphertext, nonce, file_key, expected_sha256=None):
        plaintext = AESGCM(file_key).decrypt(nonce, ciphertext, None)
        if expected_sha256 and hashlib.sha256(plaintext).hexdigest() != expected_sha256:
            raise SessionError('file integrity check failed')
        return plaintext

    def upload_file(self, token, user_id, file_data_b64, file_name, file_type,
                    nonce_file_b64, is_image_only=False,
                    thumbnail_b64=None, nonce_thumbnail_b64=None):
        data = {
            'user_token': token,
            'user_id': user_id,
            'file_data': file_data_b64,
            'file_name': file_name,
            'file_type': file_type,
            'is_image_only': is_image_only,
            'nonce_file': nonce_file_b64,
        }
        if thumbnail_b64:
            data['thumbnail'] = thumbnail_b64
        if nonce_thumbnail_b64:
            data['nonce_thumbnail'] = nonce_thumbnail_b64
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('upload_file', data)

    def get_file(self, token, user_id, file_id, include_data=True, include_thumbnail=False):
        data = {
            'user_token': token,
            'user_id': user_id,
            'file_id': file_id,
            'include_data': include_data,
            'include_thumbnail': include_thumbnail
        }
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_file', data)

    def _fetch_sealed_token(self):
        """Fetch one short-lived anonymous-delivery token."""
        resp = self.network_manager.send_sync_request('sealed_token',
                                                      {'count': 1})
        if not resp or not resp.get('success'):
            return None
        tokens = resp.get('tokens') or []
        return tokens[0] if tokens else None

    def send_sealed_message(self, receiver_login, text='', file_id=None,
                            file_meta=None):
        if not self.session_manager:
            raise SessionError('E2EE не инициализирован — сообщение не отправлено.')
        if not text and not file_id:
            raise SessionError('Empty message')

        peer_bundle = self._fetch_prekey_bundle(receiver_login)
        if not peer_bundle or not peer_bundle.get('devices'):
            raise SessionError(
                f"can't send to {receiver_login}: no devices registered")

        payload = {'text': text or ''}
        if file_id is not None and file_meta is not None:
            payload['file_id'] = file_id
            payload['file_meta'] = file_meta
        plaintext_bytes = json.dumps(payload, separators=(',', ':'),
                                     ensure_ascii=False).encode('utf-8')
        peer_user_id = peer_bundle.get('user_id')
        peer_identity = peer_bundle.get('identity')
        sealed_envelopes = []
        for d in peer_bundle['devices']:
            dev_id = d.get('device_id')
            if not dev_id:
                continue
            inner = self.session_manager.encrypt_for_device(
                peer_login=receiver_login,
                peer_device_id=dev_id,
                plaintext=plaintext_bytes,
                identity_bundle=peer_identity,
                device_bundle=d,
            )
            recipient_ik = base64.b64decode(
                d.get('dev_ik') or peer_identity['ik']
            )
            sealed = seal_envelope(
                sender_identity=self.identity,
                sender_login=self.user_login,
                sender_device_id=self.device_id,
                recipient_user_id=peer_user_id,
                recipient_device_id=dev_id,
                recipient_ik_pub_bytes=recipient_ik,
                inner_wire=inner,
            )
            sealed_envelopes.append({
                'target_user_id': peer_user_id,
                'target_device_id': dev_id,
                'sealed': sealed,
            })

        if not sealed_envelopes:
            raise SealedSenderError('No reachable target devices')
        token = self._fetch_sealed_token()
        if not token:
            raise SealedSenderError('Failed to acquire sealed-delivery token')

        message_group_id = str(uuid.uuid4())
        client_timestamp = datetime.now(timezone.utc).isoformat(
            timespec='seconds').replace('+00:00', 'Z')
        nonce = os.urandom(8).hex()

        archive_payload = {
            'kind': 'sent',
            'sender_login': self.user_login,
            'sender_device_id': self.device_id,
            'receiver_login': receiver_login,
            'text': text or '',
            'file_id': file_id,
            'file_meta': file_meta,
            'client_timestamp': client_timestamp,
            'sealed': True,
        }
        archive_self = self._archive_one(receiver_login, archive_payload,
                                         message_group_id)

        body = {
            'sealed_token': token,
            'receiver_login': receiver_login,
            'envelopes': sealed_envelopes,
            'file_id': file_id,
            'client_timestamp': client_timestamp,
            'nonce': nonce,
            'message_group_id': message_group_id,
        }
        resp = self.network_manager.send_sync_request('sealed_send', body)
        if archive_self:
            self.archive_upload_async([archive_self])
        if isinstance(resp, dict):
            resp['_archive_payload'] = archive_payload
            resp['_message_group_id'] = message_group_id
            resp['_client_timestamp'] = client_timestamp
        return resp

    def fetch_sealed_inbox(self, since_id=0):
        data = {'since_id': int(since_id or 0)}
        resp = self.network_manager.send_sync_request('sealed_inbox_since', data)
        if not resp or not resp.get('success'):
            return []
        return resp.get('messages') or []

    def send_message(self, token, user_id, receiver_login, text='', file_id=None,
                     file_meta=None, silent=False):
        if not self.session_manager:
            raise SessionError(
                'E2EE не инициализирован — сообщение не отправлено. '
                'Перелогиньтесь, чтобы восстановить шифрование.'
            )
        if not silent and not text and not file_id:
            raise SessionError('Empty message')

        peer_bundle = self._fetch_prekey_bundle(receiver_login)
        if not peer_bundle or not peer_bundle.get('devices'):
            raise SessionError(
                f"can't send to {receiver_login}: no devices registered")

        own_bundle = self._fetch_own_other_devices_bundle()

        payload = {'text': text or ''}
        if file_id is not None and file_meta is not None:
            payload['file_id'] = file_id
            payload['file_meta'] = file_meta
        if silent:
            payload['kind'] = 'rekey_ping'

        plaintext_bytes = json.dumps(payload, separators=(',', ':'),
                                     ensure_ascii=False).encode('utf-8')

        envelopes = self.session_manager.fan_out_encrypt(
            peer_login=receiver_login,
            plaintext=plaintext_bytes,
            peer_user_bundle=peer_bundle,
            own_other_devices_bundle=own_bundle,
        )

        if not envelopes:
            raise SessionError('No reachable target devices')

        message_group_id = str(uuid.uuid4())
        client_timestamp = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        nonce = os.urandom(8).hex()

        archive_payload = {
            'kind': 'sent',
            'sender_login': self.user_login,
            'sender_device_id': self.device_id,
            'receiver_login': receiver_login,
            'text': text or '',
            'file_id': file_id,
            'file_meta': file_meta,
            'client_timestamp': client_timestamp,
        }
        archive_self = (None if silent
                        else self._archive_one(receiver_login, archive_payload,
                                               message_group_id))

        data = {
            'user_token': token,
            'user_id': user_id,
            'receiver_login': receiver_login,
            'envelopes': envelopes,
            'file_id': file_id,
            'client_timestamp': client_timestamp,
            'nonce': nonce,
            'message_group_id': message_group_id,
            'archive_self': archive_self,
        }
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        resp = self.network_manager.send_sync_request('send_message', data)
        if isinstance(resp, dict):
            resp['_archive_payload'] = archive_payload
            resp['_message_group_id'] = message_group_id
            resp['_client_timestamp'] = client_timestamp
        return resp

    def decrypt_incoming(self, msg):
        if not self.session_manager:
            raise SessionError('Session manager not initialised')
        sender_login = msg.get('sender_login')
        sender_device_id = msg.get('sender_device_id')
        wire_str = msg.get('wire')
        if not sender_login or not sender_device_id or not wire_str:
            raise SessionError('incoming message missing fields')
        wire = json.loads(wire_str) if isinstance(wire_str, str) else wire_str
        if isinstance(wire, dict) and wire.get('type') == 'sealed':
            sealed_blob = wire.get('sealed')
            if not sealed_blob:
                raise SealedSenderError('sealed wire missing sealed payload')
            unsealed = unseal_envelope(
                recipient_identity=self.identity,
                recipient_user_id=self.network_manager.user_id,
                recipient_device_id=self.device_id,
                sealed=sealed_blob,
            )
            sender_login = unsealed['sender_login']
            sender_device_id = unsealed['sender_device_id']
            wire = unsealed['inner_wire']
            msg['sender_login'] = sender_login
            msg['sender_device_id'] = sender_device_id
            msg['_sealed'] = True

        plaintext = self.session_manager.decrypt_from_device(
            sender_login, sender_device_id, wire,
        )
        try:
            payload = json.loads(plaintext.decode('utf-8'))
        except Exception:
            payload = {'text': plaintext.decode('utf-8', errors='replace')}
        if payload.get('kind') == 'rekey_ping':
            return payload
        peer_login = (msg.get('receiver_login') if sender_login == self.user_login
                      else sender_login)
        archive_payload = {
            'kind': 'received' if sender_login != self.user_login else 'sync',
            'sender_login': sender_login,
            'sender_device_id': sender_device_id,
            'receiver_login': msg.get('receiver_login'),
            'text': payload.get('text', ''),
            'file_id': payload.get('file_id'),
            'file_meta': payload.get('file_meta'),
            'client_timestamp': msg.get('client_timestamp'),
            'message_group_id': msg.get('message_group_id'),
        }
        message_group_id = msg.get('message_group_id') or str(uuid.uuid4())
        archive_entry = self._archive_one(peer_login, archive_payload, message_group_id)
        if archive_entry:
            self.archive_upload_async([archive_entry])
        return payload

    def get_messages(self, token, user_id, other_user_login):
        data = {'user_token': token, 'user_id': user_id, 'other_user_login': other_user_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_messages', data)

    def get_messages_since(self, token, user_id, contact_login, since_id):
        data = {'user_token': token, 'user_id': user_id, 'contact_login': contact_login, 'since_id': since_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_messages_since', data)

    def logout_current(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        resp = self.network_manager.send_sync_request('logout_current', data)
        self.network_manager.stop_event_listener()
        self.file_cache = None
        return resp

    def info(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('info', data)

    def get_sessions(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_sessions', data)

    def logout_session(self, token, user_id, target_session_id):
        data = {'user_token': token, 'user_id': user_id, 'target_session_id': target_session_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('logout_session', data)

    def logout_all_sessions(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('logout_all_sessions', data)

    def get_cleanup_interval(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_cleanup_interval', data)

    def set_cleanup_interval(self, token, user_id, interval):
        data = {'user_token': token, 'user_id': user_id, 'interval': interval}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('set_cleanup_interval', data)

    def update_profile(self, token, user_id, username=None, avatar=None):
        data = {'user_token': token, 'user_id': user_id}
        if username:
            data['username'] = username
        if avatar:
            data['avatar'] = avatar
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('update_profile', data)
    def _user_blob_get(self, kind):
        resp = self.network_manager.send_sync_request(
            'user_blob_get', {'kind': kind},
        )
        if not resp or not resp.get('success'):
            return None, 0
        blob = resp.get('blob')
        if blob is None:
            return None, 0
        try:
            payload = decrypt_user_blob(self.master_key_bytes, kind, blob)
        except UserBlobError:
            return None, blob.get('version', 0)
        return payload, blob.get('version', 0)

    def _user_blob_put(self, kind, payload, expected_version):
        enc = encrypt_user_blob(self.master_key_bytes, kind, payload)
        resp = self.network_manager.send_sync_request('user_blob_put', {
            'kind': kind,
            'ciphertext': enc['ciphertext'],
            'nonce': enc['nonce'],
            'expected_version': expected_version,
        })
        return resp

    def _user_blob_update(self, kind, mutator, default=None, max_attempts=5):
        for _ in range(max_attempts):
            current, version = self._user_blob_get(kind)
            if current is None:
                current = default if default is not None else []
            new_payload = mutator(current)
            resp = self._user_blob_put(kind, new_payload, version)
            if resp and resp.get('success'):
                return new_payload
        raise RuntimeError(f'failed to update user blob {kind!r} after retries')

    def get_contacts_encrypted(self):
        if not self.master_key_bytes:
            return []
        payload, _ = self._user_blob_get('contacts')
        return payload or []

    def add_contact_encrypted(self, contact_login):
        if not self.master_key_bytes:
            return {'success': False, 'error': 'E2EE не инициализирован'}
        info = self.network_manager.send_sync_request('get_user_info', {
            'target_login': contact_login,
        })
        if not info or not info.get('success'):
            return info or {'success': False, 'error': 'lookup failed'}
        target = info['user']

        def mutator(current):
            entries = list(current or [])
            if any(c.get('login') == contact_login for c in entries):
                return entries
            entries.append({
                'login': target['login'],
                'username': target.get('username'),
                'user_id': target.get('user_id'),
                'added_at': datetime.now(timezone.utc).isoformat(
                    timespec='seconds').replace('+00:00', 'Z'),
            })
            return entries
        self._user_blob_update('contacts', mutator, default=[])
        return {'success': True}

    def remove_contact_encrypted(self, contact_login):
        if not self.master_key_bytes:
            return {'success': False, 'error': 'E2EE не инициализирован'}
        self._user_blob_update(
            'contacts',
            mutator=lambda current: [c for c in (current or [])
                                     if c.get('login') != contact_login],
            default=[],
        )
        return {'success': True}

    def add_contact(self, token, user_id, contact_login):
        data = {'user_token': token, 'user_id': user_id,
                'contact_login': contact_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('add_contact', data)

    def get_contacts(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_contacts', data)

    def get_avatar_versions(self, token, user_id, user_ids):
        data = {'user_token': token, 'user_id': user_id, 'user_ids': user_ids}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_avatar_versions', data)

    def get_avatar(self, token, user_id, target_user_id):
        data = {'user_token': token, 'user_id': user_id, 'target_user_id': target_user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('get_avatar', data)

    def save_contact_settings(self, token, user_id, contact_login, display_name):
        data = {'user_token': token, 'user_id': user_id,
                'contact_login': contact_login, 'display_name': display_name}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request(
            'save_contact_settings', data,
        )

    def get_contact_settings(self, token, user_id):
        data = {'user_token': token, 'user_id': user_id}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request(
            'get_contact_settings', data,
        )

    def remove_contact(self, token, user_id, contact_login):
        data = {'user_token': token, 'user_id': user_id,
                'contact_login': contact_login}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('remove_contact', data)

    def search_users(self, token, user_id, search_query):
        data = {'user_token': token, 'user_id': user_id, 'search_query': search_query}
        if self.network_manager.session_token:
            data['session_token'] = self.network_manager.session_token
        return self.network_manager.send_sync_request('search_users', data)

    def disconnect(self):
        self.network_manager.stop_event_listener()
        self.file_cache = None

    def safety_number_for(self, peer_login):
        if not self.identity or not self.master_key_bytes:
            return None
        bundle = self._fetch_prekey_bundle(peer_login)
        if not bundle or not bundle.get('identity'):
            return None
        peer_ik = base64.b64decode(bundle['identity']['ik'])
        own_user_ik = IdentityKeys.user_ik_pub_bytes(self.master_key_bytes)
        chunks = compute_safety_number(own_user_ik, peer_ik)
        scan_code = safety_qr_payload(own_user_ik, peer_ik)
        qr_matrix = safety_qr_matrix(scan_code)
        qr_ascii = render_qr_matrix_ascii(qr_matrix)
        return {
            'peer_login': peer_login,
            'chunks': chunks,
            'pretty': format_safety_number(chunks),
            'own_ik': base64.b64encode(own_user_ik).decode(),
            'peer_ik': bundle['identity']['ik'],
            'scan_code': scan_code,
            'qr_ascii': qr_ascii,
            'qr_matrix': [[1 if c else 0 for c in row] for row in qr_matrix],
        }

    def verify_peer_scan_code(self, peer_login, candidate):
        if not self.identity or not self.master_key_bytes:
            return 'unavailable'
        bundle = self._fetch_prekey_bundle(peer_login)
        if not bundle or not bundle.get('identity'):
            return 'unavailable'
        peer_ik = base64.b64decode(bundle['identity']['ik'])
        own_user_ik = IdentityKeys.user_ik_pub_bytes(self.master_key_bytes)
        if not verify_scan_code(own_user_ik, peer_ik, candidate or ''):
            return 'mismatch'
        self.mark_peer_verified(peer_login, bundle['identity']['ik'])
        return 'match'

    def trust_path(self):
        from network.cryptolib.storage import trust_path
        return trust_path(self.user_login or 'unknown')

    def get_trust_state(self):
        path = self.trust_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def set_trust_state(self, state):
        import tempfile
        path = self.trust_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix='.trust_',
                                    suffix='.json')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, str(path))

    def mark_peer_verified(self, peer_login, peer_ik_b64):
        state = self.get_trust_state()
        state[peer_login] = {
            'verified_ik': peer_ik_b64,
            'verified_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        }
        self.set_trust_state(state)

    def get_peer_trust_state(self, peer_login):
        if not self.identity or not self.master_key_bytes:
            return None
        bundle = self._fetch_prekey_bundle(peer_login)
        if not bundle or not bundle.get('identity'):
            return None
        current_ik = bundle['identity']['ik']
        state = self.get_trust_state()
        entry = state.get(peer_login)
        if entry is None:
            return 'unknown'
        if entry.get('verified_ik') == current_ik:
            return 'verified'
        if entry.get('seen_ik') == current_ik:
            return 'unchanged'
        return 'changed'

    def check_peer_key_change(self, peer_login, current_ik_b64):
        state = self.get_trust_state()
        entry = state.get(peer_login)
        if entry is None:
            state[peer_login] = {
                'seen_ik': current_ik_b64,
                'first_seen_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            }
            self.set_trust_state(state)
            return 'unknown'
        prev = entry.get('verified_ik') or entry.get('seen_ik')
        if prev == current_ik_b64:
            return 'unchanged'
        return 'changed'

    def _handle_register_start(self, login, username, password, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return
        client_reg_start = opaque_ke_py.client_registration_start(password.encode('utf-8'))
        registration_request = client_reg_start.get_message()
        client_reg_state = client_reg_start.get_state()
        make_server_request_async('opaque/register/finish', {
            'login': login,
            'username': username,
            'registration_request': base64.b64encode(registration_request).decode('utf-8')
        }, lambda resp: self._handle_register_finish(login, username, password, client_reg_state, callback, resp))

    def _handle_register_finish(self, login, username, password, client_reg_state, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return
        server_response = base64.b64decode(response['server_response'])
        client_reg_finish = opaque_ke_py.client_registration_finish(password.encode('utf-8'), client_reg_state,
                                                                    server_response)
        registration_upload = client_reg_finish.get_message()
        master_key = gen_msg_master_key()
        encrypted = encrypt_master_key(master_key, password)
        encrypted_master_key = json.dumps(encrypted)
        binding = sign_master_key_binding(master_key, login, encrypted_master_key)
        make_server_request_async('opaque/register/upload', {
            'login': login,
            'username': username,
            'registration_upload': base64.b64encode(registration_upload).decode('utf-8'),
            'encrypted_master_key': encrypted_master_key,
            'master_key_binding_sig': binding['signature'],
            'master_key_binding_sik_pub': binding['sik_pub'],
        }, lambda resp: self._handle_register_upload(login, username, password, master_key, callback, resp))

    def _handle_register_upload(self, login, username, password, master_key, callback, response):
        if response and response.get('success'):
            self.user_login = login
            session_token = response.get('session_token')
            user_id = response.get('user_id')
            if session_token:
                self.set_user_credentials(session_token, user_id, login)
                self.network_manager.start_event_listener()
            try:
                self.init_e2ee(master_key)
            except Exception as exc:
                print(f'init_e2ee failed during register: {type(exc).__name__}: {exc}')
            callback(response)
        else:
            callback(response)

    def opaque_register_async(self, login, username, password, callback):
        make_server_request_async('opaque/register/start', {
            'login': login,
            'username': username
        }, lambda resp: self._handle_register_start(login, username, password, callback, resp))

    def _handle_login_start(self, login, password, client_login_state, callback, response):
        if not response or not response.get('success'):
            self.login_in_progress = False
            self.network_manager.stop_event_listener()
            callback(response)
            return
        state_id = response['state_id']
        credential_response = base64.b64decode(response['credential_response'])
        try:
            client_login_finish = opaque_ke_py.client_login_finish(password.encode('utf-8'), client_login_state,
                                                                   credential_response)
            credential_finalization = client_login_finish.get_message()
        except Exception:
            def handle_failed_response(failed_response):
                self.login_in_progress = False
                self.network_manager.stop_event_listener()
                if failed_response and failed_response.get('blocked'):
                    callback({'success': False, 'error': failed_response.get('error')})
                else:
                    callback({'success': False, 'error': 'Неверный логин или пароль'})
            make_server_request_async('opaque/login/failed', {
                'login': login
            }, handle_failed_response)
            return
        make_server_request_async('opaque/login/finish', {
            'state_id': state_id,
            'credential_finalization': base64.b64encode(credential_finalization).decode('utf-8')
        }, lambda resp: self._handle_login_finish(login, password, callback, resp))

    def _handle_login_finish(self, login, password, callback, response):
        if response and response.get('success'):
            user_id = response['user_id']
            self.set_user_credentials(response['session_token'], user_id, login)
            encrypted_master_key_str = response.get('encrypted_master_key')
            if encrypted_master_key_str:
                try:
                    encrypted = json.loads(encrypted_master_key_str)
                    master_key = decrypt_master_key(encrypted, password)
                    verify_master_key_binding(
                        master_key, login,
                        encrypted_master_key_str,
                        signature_b64=response.get('master_key_binding_sig'),
                        expected_sik_pub_b64=response.get('master_key_binding_sik_pub'),
                    )
                    self.init_e2ee(master_key)
                except MasterKeyBindingError as exc:
                    self.login_in_progress = False
                    self.network_manager.stop_event_listener()
                    callback({
                        'success': False,
                        'error': (
                            'Подмена ключа аккаунта обнаружена. '
                            f'Вход отклонён ({exc}).'
                        ),
                    })
                    return
                except Exception as exc:
                    print(f'init_e2ee failed during login: {type(exc).__name__}: {exc}')
            self.network_manager.start_event_listener()
            self.login_in_progress = False
            callback(response)
        else:
            self.login_in_progress = False
            callback(response)

    def opaque_login_async(self, login, password, callback):
        if self.login_in_progress:
            callback({'success': False, 'error': 'Логин уже выполняется'})
            return
        self.login_in_progress = True
        client_login_start = opaque_ke_py.client_login_start(password.encode('utf-8'))
        credential_request = client_login_start.get_message()
        client_login_state = client_login_start.get_state()
        make_server_request_async('opaque/login/start', {
            'login': login,
            'credential_request': base64.b64encode(credential_request).decode('utf-8')
        }, lambda resp: self._handle_login_start(login, password, client_login_state, callback, resp))

    def _handle_change_password_server_response(self, new_password, client_reg_state, callback, response):
        if not response or not response.get('success'):
            callback(response)
            return
        server_response = base64.b64decode(response['server_response'])
        client_reg_finish = opaque_ke_py.client_registration_finish(new_password.encode('utf-8'), client_reg_state,
                                                                    server_response)
        registration_upload = client_reg_finish.get_message()
        master_key = self.master_key_bytes
        encrypted_new = encrypt_master_key(master_key, new_password)
        encrypted_master_key_new = json.dumps(encrypted_new)
        binding = sign_master_key_binding(
            master_key, self.user_login, encrypted_master_key_new,
        )
        make_server_request_async('opaque/change_password/upload', {
            'registration_upload': base64.b64encode(registration_upload).decode('utf-8'),
            'encrypted_master_key': encrypted_master_key_new,
            'master_key_binding_sig': binding['signature'],
            'master_key_binding_sik_pub': binding['sik_pub'],
        }, lambda resp: self._handle_change_password_upload(callback, resp))

    def _handle_change_password_upload(self, callback, response):
        if response and response.get('success'):
            callback({'success': True})
        else:
            callback(response)

    def opaque_change_password_async(self, new_password, callback):
        if not self.master_key_bytes:
            callback({'success': False, 'error': 'E2EE не инициализирован'})
            return
        client_reg_start = opaque_ke_py.client_registration_start(new_password.encode('utf-8'))
        client_reg_state = client_reg_start.get_state()
        registration_request = client_reg_start.get_message()
        make_server_request_async('opaque/change_password/get_server_response', {
            'registration_request': base64.b64encode(registration_request).decode('utf-8')
        }, lambda resp: self._handle_change_password_server_response(new_password, client_reg_state, callback, resp))


messenger_api = MessengerAPI()


def make_server_request_async(endpoint, data=None, callback=None):
    if data is None:
        data = {}
    if callback is None:
        callback = lambda x: None
    payload = dict(data)
    nm = messenger_api.network_manager
    if nm.session_token and 'session_token' not in payload:
        payload['session_token'] = nm.session_token
    if nm.user_token and 'user_token' not in payload:
        payload['user_token'] = nm.user_token
    if nm.user_id and 'user_id' not in payload:
        payload['user_id'] = nm.user_id
    AsyncHTTPRequest(endpoint, payload, callback)