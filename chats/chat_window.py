from pathlib import Path
import sys
import os
import json
import time
import shutil
import mimetypes
from datetime import datetime, timedelta
import traceback
import hashlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QFileDialog, QMessageBox
from PyQt6.QtCore import QUrl, QTimer, QObject, pyqtSlot, Qt
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import QByteArray, QBuffer

from utils import BASE_PATH, DATA_PATH
from network import make_server_request_async, messenger_api, Contact
from network.crypto import KeyChangedError
from network.cryptolib import (
    UnknownInitialMessage, SessionError,
    DuplicateWire, SessionRekeyRequired,
)
import markdown
import base64
import html
import bleach


class Bridge(QObject):
    def __init__(self, chat_window):
        super().__init__()
        self.chat_window = chat_window

    @pyqtSlot()
    def loadUserData(self):
        self.chat_window.load_user_data()

    @pyqtSlot(str)
    def loadMessages(self, contact_login):
        self.chat_window.load_messages(contact_login)

    @pyqtSlot(str, str)
    def sendMessage(self, receiver_login, text):
        self.chat_window.send_message(receiver_login, text)

    @pyqtSlot(str)
    def attachFile(self, params_json):
        self.chat_window.attach_file(params_json)

    @pyqtSlot(int, str)
    def downloadFile(self, file_id, file_info_json):
        self.chat_window.download_file(file_id, json.loads(file_info_json))

    @pyqtSlot(str)
    def addContact(self, login):
        self.chat_window.add_contact(login)

    @pyqtSlot(str)
    def deleteChat(self, contact_login):
        self.chat_window.delete_chat(contact_login)

    @pyqtSlot(str, str)
    def renameContact(self, contact_login, new_name):
        self.chat_window.rename_contact(contact_login, new_name)

    @pyqtSlot()
    def showSettings(self):
        self.chat_window.show_settings()

    @pyqtSlot(str, str)
    def saveFullscreenImage(self, image_data, file_name):
        self.chat_window.save_fullscreen_image(image_data, file_name)

    @pyqtSlot(str)
    def viewSafetyNumber(self, peer_login):
        self.chat_window.view_safety_number(peer_login)

    @pyqtSlot(str)
    def markPeerVerified(self, peer_login):
        self.chat_window.mark_peer_verified(peer_login)

    @pyqtSlot(str, str)
    def verifyScanCode(self, peer_login, candidate):
        self.chat_window.verify_scan_code(peer_login, candidate)

    @pyqtSlot(str, result=str)
    def getPeerTrustState(self, peer_login):
        try:
            state = messenger_api.get_peer_trust_state(peer_login)
        except Exception:
            state = None
        return state or ''

FUCK_FIX = (
    'Ошибка расшифровки',
    'Ожидание установки сессии',
    'Сессия будет переустановлена',
)


def _is_legacy(text):
    if not isinstance(text, str):
        return False
    s = text.strip()
    if not s:
        return False
    if not (s.startswith('[') and (s.endswith(']') or s.endswith('…]'))):
        return False
    return any(frag in s for frag in FUCK_FIX)


def _is_real_decrypted(m):
    txt = m.get('decrypted_text')
    return txt is not None and not _is_legacy(txt)


def _msg_sort_key(m):
    ts = m.get('client_timestamp') or m.get('timestamp') or ''
    mid = m.get('id')
    int_id = mid if isinstance(mid, int) else 0
    return (ts, int_id)


class MessageCache:
    def __init__(self, user_id):
        self.user_id = user_id
        self.cache_dir = DATA_PATH / 'chats_save' / str(user_id)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_contact_file(self, contact_user_id):
        return self.cache_dir / f"{contact_user_id}.json"

    def load_messages(self, contact_user_id):
        fayl = self._get_contact_file(contact_user_id)
        if not fayl.exists():
            return []
        try:
            with open(fayl, 'r', encoding='utf-8') as f:
                data = json.load(f)
                msgs = data.get('messages', [])
        except (json.JSONDecodeError, OSError):
            return []
        cleaned = []
        changed = False
        for m in msgs:
            if _is_legacy(m.get('decrypted_text')):
                changed = True
                continue
            if _is_legacy(m.get('message_text')):
                m = dict(m)
                m.pop('message_text', None)
                changed = True
            cleaned.append(m)
        if changed:
            try:
                self.save_messages(contact_user_id, cleaned)
            except OSError:
                pass
        return cleaned

    def save_messages(self, contact_user_id, messages):
        fayl = self._get_contact_file(contact_user_id)
        max_int_id = max(
            (m['id'] for m in messages if isinstance(m.get('id'), int)),
            default=0,
        )
        data = {
            'contact_user_id': contact_user_id,
            'messages': messages,
            'last_message_id': max_int_id,
            'updated_at': time.time()
        }
        with open(fayl, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def append_messages(self, contact_user_id, novye):
        if not novye:
            return []
        tekushchie = self.load_messages(contact_user_id)
        by_id = {m['id']: m for m in tekushchie}
        by_mgid = {m['message_group_id']: m for m in tekushchie
                   if m.get('message_group_id')}
        added = []
        changed = False
        for raw in novye:
            mid = raw.get('id')
            mgid = raw.get('message_group_id')
            mgid_existing = by_mgid.get(mgid) if mgid else None
            id_existing = by_id.get(mid) if mid is not None else None
            if mgid_existing is not None and id_existing is None:
                if (not _is_real_decrypted(mgid_existing)
                        and _is_real_decrypted(raw)):
                    for k, v in raw.items():
                        if k in ('wire', 'id'):
                            continue
                        mgid_existing[k] = v
                    mgid_existing.pop('wire', None)
                    changed = True
                continue

            if id_existing is None:
                if raw.get('_skip'):
                    continue
                tekushchie.append(raw)
                by_id[mid] = raw
                if mgid:
                    by_mgid[mgid] = raw
                added.append(raw)
                changed = True
            elif (not _is_real_decrypted(id_existing)
                  and _is_real_decrypted(raw)):
                for k, v in raw.items():
                    if k == 'wire':
                        continue
                    id_existing[k] = v
                id_existing.pop('wire', None)
                changed = True
        if not changed:
            return []
        tekushchie.sort(key=_msg_sort_key)
        self.save_messages(contact_user_id, tekushchie)
        return added

    def update_messages(self, contact_user_id, updated):
        if not updated:
            return
        tekushchie = self.load_messages(contact_user_id)
        by_id = {m['id']: i for i, m in enumerate(tekushchie)}
        changed = False
        for msg in updated:
            idx = by_id.get(msg.get('id'))
            if idx is None:
                continue
            tekushchie[idx] = msg
            changed = True
        if changed:
            tekushchie.sort(key=_msg_sort_key)
            self.save_messages(contact_user_id, tekushchie)

    def is_decrypted(self, contact_user_id, msg_id):
        for m in self.load_messages(contact_user_id):
            if m.get('id') == msg_id:
                return _is_real_decrypted(m)
        return False

    def get_last_message_id(self, contact_user_id):
        fayl = self._get_contact_file(contact_user_id)
        if not fayl.exists():
            return 0
        try:
            with open(fayl, 'r', encoding='utf-8') as f:
                data = json.load(f)
                last = data.get('last_message_id', 0)
                return last if isinstance(last, int) else 0
        except (json.JSONDecodeError, OSError):
            return 0

    def clear_cache(self):
        shutil.rmtree(self.cache_dir, ignore_errors=True)

    def save_contact_settings_cache(self, nastroyki):
        fayl = self.cache_dir / "contact_settings.json"
        try:
            with open(fayl, 'w', encoding='utf-8') as f:
                json.dump(nastroyki, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def load_contact_settings_cache(self):
        fayl = self.cache_dir / "contact_settings.json"
        if fayl.exists():
            try:
                with open(fayl, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}


class ChatWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.cur_contact = None
        self.contacts = {}
        self.contact_avatars = {}
        self.script_dir = Path(BASE_PATH)
        self.page_loaded = False
        self.e2ee_ready = False
        self.pending_contact_load = None
        self.settings_retry_count = 0
        self._destroyed = False

        self.avatar_timer = QTimer()
        self.avatar_timer.timeout.connect(self.check_avatar_updates)
        self.avatar_timer.setInterval(60000)

        self.msg_cache = MessageCache(main_window.user_id)
        self.sync_timer = QTimer()
        self.sync_timer.timeout.connect(self.sync_all_contacts)
        self.sync_timer.setInterval(60000)
        self.contacts_need_update = False

        self.init_ui()
        self.load_contacts()
        self.setup_msg_listener()
        self.avatar_timer.start()
        self.sync_timer.start()

    def _safe_run_js(self, js_code):
        if self._destroyed:
            return
        try:
            page = self.web_view.page()
            page.runJavaScript(js_code)
        except RuntimeError:
            self._destroyed = True

    def showEvent(self, event):
        super().showEvent(event)
        if self.page_loaded:
            self._update_contacts_js()
            if self.cur_contact:
                self.load_messages(self.cur_contact.login)
            self.sync_all_contacts()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        self.web_view.setStyleSheet("border: none; background: #ffffff;")
        self.web_view.loadFinished.connect(self.on_page_loaded)
        self.web_view.setZoomFactor(0.8)

        ws = self.web_view.settings()
        ws.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, False)

        self.channel = QWebChannel(self.web_view.page())
        self.bridge = Bridge(self)
        self.channel.registerObject("qt", self.bridge)
        self.web_view.page().setWebChannel(self.channel)
        self.web_view.page().setBackgroundColor(Qt.GlobalColor.white)

        html_path = self.script_dir / "chats" / "messages.html"
        if html_path.exists():
            self.web_view.setUrl(QUrl.fromLocalFile(str(html_path.absolute())))
        else:
            self.web_view.setHtml("""
                <!DOCTYPE html><html>
                <head><meta charset="UTF-8"><title>Ошибка</title></head>
                <body style="font-family: Arial; padding: 20px;">
                    <h2>Файл messages.html не найден</h2>
                </body></html>
            """)
        layout.addWidget(self.web_view)

    def on_page_loaded(self, ok):
        if ok:
            self.page_loaded = True
            self.load_user_data()
            if self.contacts_need_update:
                self._update_contacts_js()
            if self.cur_contact:
                self.load_messages(self.cur_contact.login)
            self.sync_all_contacts()

    def load_user_data(self):
        if not self.page_loaded:
            return
        self._safe_run_js(f'setCurrentUser("{self.main_window.current_user}");')

    def _process_e2ee_msg(self, msg, contact_login):
        cached_text = msg.get('decrypted_text')
        if cached_text is not None and not _is_legacy(cached_text):
            msg['message_text'] = msg.get('message_text') or cached_text or ''
            msg.pop('wire', None)
            msg['_pending_session'] = False
            msg.pop('_transient_status', None)
            return
        if _is_legacy(cached_text):
            msg.pop('decrypted_text', None)
            msg.pop('message_text', None)

        wire_str = msg.get('wire')
        sender_login = msg.get('sender_login')
        sender_device_id = msg.get('sender_device_id')
        if not wire_str or not sender_login or not sender_device_id:
            msg['_skip'] = True
            return

        if not messenger_api.session_manager:
            msg['_skip'] = True
            return

        try:
            payload = messenger_api.decrypt_incoming(msg)
        except DuplicateWire:
            msg['_skip'] = True
            msg.pop('wire', None)
            return
        except UnknownInitialMessage:
            msg['_skip'] = True
            msg.pop('wire', None)
            self._schedule_session_rekey(sender_login, sender_device_id,
                                         'no session for inbound ratchet wire')
            return
        except SessionRekeyRequired as exc:
            msg['_skip'] = True
            msg.pop('wire', None)
            self._schedule_session_rekey(sender_login, sender_device_id, str(exc))
            return
        except SessionError:
            msg['_skip'] = True
            msg.pop('wire', None)
            return
        except Exception:
            try:
                traceback.print_exc()
            except Exception:
                pass
            msg['_skip'] = True
            msg.pop('wire', None)
            return
        if payload.get('kind') == 'rekey_ping':
            msg['_skip'] = True
            msg.pop('wire', None)
            return

        text = payload.get('text', '') or ''
        msg['message_text'] = text
        msg['decrypted_text'] = text
        if payload.get('file_meta') is not None:
            msg['file_meta'] = payload.get('file_meta')
        if payload.get('file_id') is not None:
            msg['file_id'] = payload.get('file_id')
            msg['has_file'] = 1
        msg.pop('wire', None)
        msg.pop('_transient_status', None)
        msg['_pending_session'] = False

    def view_safety_number(self, peer_login):
        if not peer_login or not messenger_api.session_manager:
            return
        info = messenger_api.safety_number_for(peer_login)
        if not info:
            self._safe_run_js(
                'showToast("Не удалось получить ключ собеседника", true);')
            return
        change = messenger_api.check_peer_key_change(peer_login, info['peer_ik'])
        payload = {
            'peer': peer_login,
            'pretty': info['pretty'],
            'chunks': info['chunks'],
            'change': change,
            'scan_code': info.get('scan_code'),
            'qr_matrix': info.get('qr_matrix'),
            'qr_ascii': info.get('qr_ascii'),
        }
        safe_payload = json.dumps(payload)
        self._safe_run_js(
            f'showSafetyNumber({safe_payload});'
        )

    def mark_peer_verified(self, peer_login):
        info = messenger_api.safety_number_for(peer_login)
        if not info:
            return
        messenger_api.mark_peer_verified(peer_login, info['peer_ik'])
        self._safe_run_js('showToast("Контакт отмечен как проверенный");')
        self._refresh_trust_badge(peer_login)

    def _refresh_trust_badge(self, peer_login):
        try:
            state = messenger_api.get_peer_trust_state(peer_login) or 'unknown'
        except Exception:
            state = 'unknown'
        cur = (self.cur_contact.login if getattr(self, 'cur_contact', None)
               else None)
        if cur == peer_login:
            self._safe_run_js(
                f'window.renderTrustBadge && window.renderTrustBadge({json.dumps(state)});'
            )

    def verify_scan_code(self, peer_login, candidate):
        result = messenger_api.verify_peer_scan_code(peer_login, candidate)
        if result == 'match':
            self._safe_run_js(
                'showToast("Скан-код совпал, контакт отмечен как проверенный.");')
            self._refresh_trust_badge(peer_login)
        elif result == 'mismatch':
            self._safe_run_js(
                'showToast("Скан-код не совпадает! Возможна подмена ключа.", true);')
        else:
            self._safe_run_js(
                'showToast("Не удалось проверить скан-код.", true);')

    def _schedule_session_rekey(self, peer_login, peer_device_id, reason=''):
        if not hasattr(self, '_rekey_armed'):
            self._rekey_armed = {}
        key = (peer_login, peer_device_id)
        now = time.time()
        if self._rekey_armed.get(key, 0) > now - 30:
            return
        self._rekey_armed[key] = now
        try:
            messenger_api.session_manager.forget_session(peer_login, peer_device_id)
        except Exception:
            pass
        QTimer.singleShot(50, lambda: self._send_rekey_ping(peer_login))

    def _send_rekey_ping(self, peer_login):
        if peer_login == self.main_window.current_user:
            return
        if not messenger_api.session_manager:
            return
        try:
            messenger_api.send_message(
                token=self.main_window.user_token,
                user_id=self.main_window.user_id,
                receiver_login=peer_login,
                text='',
                file_id=None,
                file_meta=None,
                silent=True,
            )
        except Exception:
            try:
                traceback.print_exc()
            except Exception:
                pass

    def _decrypt_file_bytes(self, raw_bytes, file_info, sender_login=None, file_meta=None):
        if not file_meta:
            file_meta = (file_info or {}).get('file_meta')
        if not file_meta:
            return None
        try:
            file_key = base64.b64decode(file_meta['file_key'])
            nonce_file = base64.b64decode(file_meta['nonce_file'])
        except Exception:
            return None
        try:
            return messenger_api.decrypt_file_bytes(
                raw_bytes, nonce_file, file_key,
                expected_sha256=file_meta.get('sha256'),
            )
        except Exception:
            return None

    def load_messages(self, contact_login):
        self.pending_contact_load = contact_login
        if not self.page_loaded:
            return
        kontakt = self.contacts.get(contact_login)
        if not kontakt:
            make_server_request_async('get_user_info', {
                'user_token': self.main_window.user_token,
                'user_id': self.main_window.user_id,
                'target_login': contact_login,
                'session_token': self.main_window.session_token
            }, lambda otvet: self._handle_user_info_response(contact_login, otvet))
            return
        self._load_messages_after_contact(kontakt)

    def _handle_user_info_response(self, contact_login, otvet):
        if self.pending_contact_load != contact_login:
            return
        if otvet and otvet.get('success'):
            u = otvet.get('user')
            novyy = Contact(login=u['login'], username=u['username'],
                            user_id=u['user_id'], avatar_version=u.get('avatar_version', 0))
            sushchestvuyushchiy = next(
                (c for c in self.contacts.values() if c.user_id == novyy.user_id), None)
            kontakt = sushchestvuyushchiy if sushchestvuyushchiy else novyy
            if not sushchestvuyushchiy:
                self.contacts[contact_login] = kontakt
            self.load_contact_avatar(kontakt)
            self._load_messages_after_contact(kontakt)
        else:
            oshibka = otvet.get('error', 'Контакт не найден') if otvet else 'Ошибка соединения'
            self._safe_run_js(f'showToast("{oshibka}", true);')

    def _load_messages_after_contact(self, contact):
        if self.pending_contact_load != contact.login:
            return
        self.cur_contact = contact
        self._render_messages(contact)

    def _render_messages(self, contact):
        if self.pending_contact_load != contact.login:
            return

        aktualnyy = self.contacts.get(contact.login, contact)
        self.cur_contact = aktualnyy
        self._ensure_session_warm(aktualnyy)
        self.sync_archive_for_contact(aktualnyy)

        soobshenia = self.msg_cache.load_messages(aktualnyy.user_id)
        obrabotannyye = []
        novo_rasshifrovannyye = []
        peremennye_dlya_skip = []
        seen_mgids = set()
        for original in soobshenia:
            msg = dict(original)
            had_decrypted = _is_real_decrypted(msg)
            had_wire = 'wire' in msg
            login_dlya_decrypt = (msg['receiver_login']
                                  if msg['sender_login'] == self.main_window.current_user
                                  else msg['sender_login'])
            self._process_e2ee_msg(msg, login_dlya_decrypt)
            if msg.get('_skip'):
                if had_wire and 'wire' not in msg:
                    peremennye_dlya_skip.append(msg)
                continue
            if msg.get('decrypted_text') is None:
                continue
            mgid = msg.get('message_group_id')
            if mgid:
                if mgid in seen_mgids:
                    continue
                seen_mgids.add(mgid)
            obrabotannyye.append(self.prepare_msg_for_display(msg))
            now_decrypted = _is_real_decrypted(msg)
            if (not had_decrypted and now_decrypted) or (had_wire and 'wire' not in msg):
                novo_rasshifrovannyye.append(msg)

        if novo_rasshifrovannyye:
            self.msg_cache.update_messages(aktualnyy.user_id, novo_rasshifrovannyye)
        if peremennye_dlya_skip:
            self.msg_cache.update_messages(aktualnyy.user_id, peremennye_dlya_skip)

        self._safe_run_js(f'setMessages({json.dumps(obrabotannyye)});')
        self.ensure_msg_previews(aktualnyy.user_id, soobshenia)
        self.sync_contact_msgs(aktualnyy)

    def _ensure_session_warm(self, contact):
        if not messenger_api.session_manager or not contact:
            return
        contact_login = contact.login
        if not hasattr(self, '_warm_state'):
            self._warm_state = {}
        self._warm_state[contact_login] = {'attempts': 0, 'ready': False}
        QTimer.singleShot(0, lambda: self._do_warm_session(contact_login))

    def _do_warm_session(self, contact_login):
        if self._destroyed or not messenger_api.session_manager:
            return
        if not hasattr(self, '_warm_state'):
            self._warm_state = {}
        state = self._warm_state.setdefault(contact_login,
                                            {'attempts': 0, 'ready': False})
        try:
            result = messenger_api.warm_sessions_for(contact_login) or {}
        except Exception:
            try:
                traceback.print_exc()
            except Exception:
                pass
            result = {'ready': False}

        state['attempts'] = int(state.get('attempts', 0)) + 1
        ready = bool(result.get('ready'))
        was_ready = bool(state.get('ready'))
        state['ready'] = ready

        if ready:
            if not was_ready:
                kontakt = self.contacts.get(contact_login)
                if kontakt:
                    QTimer.singleShot(0, lambda: self.sync_contact_msgs(kontakt))
            QTimer.singleShot(60_000, lambda: self._do_warm_session(contact_login))
            return
        delay_ms = min(30_000, 1_000 * (2 ** min(state['attempts'] - 1, 5)))
        QTimer.singleShot(delay_ms, lambda: self._do_warm_session(contact_login))

    def send_message(self, receiver_login, text):
        if not receiver_login or not text:
            return

        if not messenger_api.session_manager:
            self._safe_run_js(
                'showToast("E2EE не инициализирован. Перелогиньтесь для восстановления шифрования.", true);')
            return

        try:
            otvet = messenger_api.send_message(
                token=self.main_window.user_token,
                user_id=self.main_window.user_id,
                receiver_login=receiver_login,
                text=text,
                file_id=None,
                file_meta=None,
            )
        except SessionError as exc:
            safe = html.escape(str(exc)).replace('"', '\\"').replace("'", "\\'")
            self._safe_run_js(f'showToast("E2EE: {safe}", true);')
            return

        if otvet and otvet.get('success'):
            kontakt = self.contacts.get(receiver_login)
            if kontakt:
                local_msg = self._build_local_sent_msg(
                    otvet.get('_archive_payload') or {'text': text},
                    client_timestamp=otvet.get('_client_timestamp'),
                    message_group_id=otvet.get('_message_group_id'),
                )
                self.msg_cache.append_messages(kontakt.user_id, [local_msg])
                self._safe_run_js(
                    f'appendMessage({json.dumps(self.prepare_msg_for_display(local_msg))});')
                self._safe_run_js(
                    'document.getElementById("messageInput").value = "";')
        else:
            oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
            safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
            self._safe_run_js(f'showToast("Ошибка: {safe_error}", true);')

    def attach_file(self, params_json):
        if not self.cur_contact:
            self._safe_run_js('showToast("Сначала выберите контакт", true);')
            return

        if not messenger_api.session_manager:
            self._safe_run_js(
                'showToast("E2EE не инициализирован. Перелогиньтесь для восстановления шифрования.", true);')
            return

        params = json.loads(params_json)
        tekst_vvoda = params.get('text', '')
        tolko_kartinka = params.get('isImageOnly', False)

        if tolko_kartinka:
            filtr = "Изображения (*.jpg *.jpeg *.png *.gif *.bmp)"
        else:
            filtr = ("Все файлы (*);;Изображения (*.jpg *.jpeg *.png *.gif *.bmp *.webp);;"
                     "Документы (*.pdf *.doc *.docx *.txt *.xls *.xlsx *.ppt *.pptx)")

        put_fayla, _ = QFileDialog.getOpenFileName(self, "Выбрать файл", "", filtr)
        if not put_fayla:
            return

        if os.path.getsize(put_fayla) > 100 * 1024 * 1024:
            self._safe_run_js('showToast("Файл слишком большой (максимум 100MB)", true);')
            return

        imya_fayla = os.path.basename(put_fayla)
        tip_fayla, _ = mimetypes.guess_type(put_fayla)
        if not tip_fayla:
            tip_fayla = "application/octet-stream"

        if tip_fayla.lower().startswith('video/') and os.path.getsize(put_fayla) > 1024 * 1024 * 1000:
            self._safe_run_js('showToast("Видео не должно превышать 1000 MB", true);')
            return

        self._safe_run_js('showProgress(0);')
        with open(put_fayla, 'rb') as f:
            dannyye = f.read()

        try:
            enc = messenger_api.encrypt_file_data(dannyye, None)
        except SessionError as exc:
            safe = html.escape(str(exc)).replace('"', '\\"').replace("'", "\\'")
            self._safe_run_js(f'showToast("E2EE: {safe}", true);')
            return

        file_meta_for_wire = {
            'file_key': enc['file_key'],
            'nonce_file': enc['nonce_file'],
            'sha256': enc['sha256'],
            'name': imya_fayla,
            'type': tip_fayla,
            'size': len(dannyye),
            'is_image_only': bool(tolko_kartinka),
        }
        if 'thumbnail' in enc:
            file_meta_for_wire['nonce_thumbnail'] = enc['nonce_thumbnail']

        def handle_upload_otvet(otvet):
            self._safe_run_js('showProgress(100);')
            if otvet and otvet.get('success'):
                self._send_msg_with_file(otvet.get('file_id'), tekst_vvoda,
                                         imya_fayla, tip_fayla, tolko_kartinka,
                                         file_meta_for_wire)
            else:
                oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
                safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
                self._safe_run_js(f'showToast("Ошибка: {safe_error}", true);')

        payload = {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_name': imya_fayla,
            'file_type': tip_fayla,
            'is_image_only': tolko_kartinka,
            'session_token': self.main_window.session_token,
            'file_data': enc['ciphertext'],
            'nonce_file': enc['nonce_file'],
        }
        if 'thumbnail' in enc:
            payload['thumbnail'] = enc['thumbnail']
            payload['nonce_thumbnail'] = enc['nonce_thumbnail']

        make_server_request_async('upload_file', payload, handle_upload_otvet)

    def _send_msg_with_file(self, file_id, text, file_name, file_type,
                            is_image_only, file_meta):
        polnyy_tekst = text if text.strip() else ""

        try:
            otvet = messenger_api.send_message(
                token=self.main_window.user_token,
                user_id=self.main_window.user_id,
                receiver_login=self.cur_contact.login,
                text=polnyy_tekst,
                file_id=file_id,
                file_meta=file_meta,
            )
        except SessionError as exc:
            safe = html.escape(str(exc)).replace('"', '\\"').replace("'", "\\'")
            self._safe_run_js(f'showToast("E2EE: {safe}", true);')
            return

        if otvet and otvet.get('success'):
            archive_payload = otvet.get('_archive_payload') or {}
            local_msg = self._build_local_sent_msg(
                archive_payload,
                client_timestamp=otvet.get('_client_timestamp'),
                message_group_id=otvet.get('_message_group_id'),
                file_id=file_id,
                file_meta=file_meta,
                file_name=file_name, file_type=file_type,
                is_image_only=is_image_only,
            )
            self.msg_cache.append_messages(self.cur_contact.user_id, [local_msg])
            self._safe_run_js(
                f'appendMessage({json.dumps(self.prepare_msg_for_display(local_msg))});')
            self._safe_run_js(
                'document.getElementById("messageInput").value = "";')
            self.ensure_msg_previews(self.cur_contact.user_id, [local_msg])
        else:
            oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
            safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
            self._safe_run_js(f'showToast("Ошибка: {safe_error}", true);')

    def _build_local_sent_msg(self, archive_payload, client_timestamp,
                              message_group_id, file_id=None, file_meta=None,
                              file_name=None, file_type=None, is_image_only=False):
        msg = {
            'id': f'local_{message_group_id}',
            'message_group_id': message_group_id,
            'sender_login': self.main_window.current_user,
            'sender_device_id': messenger_api.device_id or '',
            'receiver_login': self.cur_contact.login,
            'receiver_user_id': self.cur_contact.user_id,
            'message_text': archive_payload.get('text') or '',
            'decrypted_text': archive_payload.get('text') or '',
            'timestamp': client_timestamp or '',
            'client_timestamp': client_timestamp or '',
            'has_file': 1 if file_id else 0,
            'file_id': file_id,
            'file_meta': file_meta,
            'archive_origin': 'sent',
        }
        if file_id and file_meta:
            msg['file_info'] = {
                'id': file_id,
                'name': file_name or file_meta.get('name'),
                'type': file_type or file_meta.get('type'),
                'size': file_meta.get('size', 0),
                'is_image_only': bool(is_image_only),
                'nonce_file': file_meta.get('nonce_file'),
                'nonce_thumbnail': file_meta.get('nonce_thumbnail'),
                'file_meta': file_meta,
            }
        return msg

    def download_file(self, file_id, file_info):
        file_meta = file_info.get('file_meta') or self._lookup_file_meta(file_id)
        if not file_meta:
            self._safe_run_js('showToast("Нет ключа файла. Откройте чат заново.", true);')
            return

        if messenger_api.file_cache and messenger_api.file_cache.has_file(file_id):
            dannyye = messenger_api.file_cache.get_file_data(file_id)
            if dannyye:
                self.save_file_dialog(file_info['name'], dannyye)
                return

        self._safe_run_js('showProgress(0);')

        def handle_file_otvet(otvet):
            self._safe_run_js('showProgress(100);')
            if otvet and otvet.get('success'):
                raw = base64.b64decode(otvet.get('file_data'))
                dannyye = self._decrypt_file_bytes(raw, file_info, file_meta=file_meta)
                if dannyye is None:
                    self._safe_run_js('showToast("Ошибка расшифровки файла", true);')
                    return
                self.save_file_dialog(file_info['name'], dannyye)
                if messenger_api.file_cache:
                    messenger_api.file_cache.save_file(
                        file_id, file_info['name'], file_info['type'], len(dannyye), dannyye, None)
            else:
                oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
                safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
                self._safe_run_js(
                    f'showToast("Не удалось загрузить файл: {safe_error}", true);')

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'include_thumbnail': True,
            'session_token': self.main_window.session_token
        }, handle_file_otvet)

    def _lookup_file_meta(self, file_id):
        for kontakt in self.contacts.values():
            for msg in self.msg_cache.load_messages(kontakt.user_id):
                if msg.get('file_id') == file_id and msg.get('file_meta'):
                    return msg.get('file_meta')
        return None

    def save_file_dialog(self, file_name, dannyye):
        from PyQt6.QtCore import QCoreApplication
        self.main_window.activateWindow()
        self.main_window.raise_()
        QCoreApplication.processEvents()

        suffix = Path(file_name).suffix.lstrip('.')
        filtr = (f"{suffix.upper()} файлы (*.{suffix});;Все файлы (*)"
                 if suffix else "Все файлы (*)")

        put_sohraneniya, _ = QFileDialog.getSaveFileName(
            self.main_window, "Сохранить файл", file_name, filtr)
        if put_sohraneniya:
            with open(put_sohraneniya, 'wb') as f:
                f.write(dannyye)
            self._safe_run_js('showToast("Файл сохранен");')
        else:
            self._safe_run_js('showToast("Сохранение отменено");')

    def save_fullscreen_image(self, image_data, file_name):
        from PyQt6.QtCore import QCoreApplication
        if image_data.startswith('data:'):
            image_data = image_data.split(',', 1)[1]
        bayty = base64.b64decode(image_data)
        self.main_window.activateWindow()
        self.main_window.raise_()
        QCoreApplication.processEvents()
        put_sohraneniya, _ = QFileDialog.getSaveFileName(
            self.main_window, "Сохранить изображение", file_name,
            "Изображения (*.jpg *.png *.gif);;Все файлы (*)")
        if put_sohraneniya:
            with open(put_sohraneniya, 'wb') as f:
                f.write(bayty)
            self._safe_run_js('showToast("Изображение сохранено");')

    def add_contact(self, contact_login):
        if not contact_login:
            self._safe_run_js('showToast("Введите логин пользователя!", true);')
            return
        if contact_login == self.main_window.current_user:
            self._safe_run_js('showToast("Нельзя добавить самого себя!", true);')
            return
        if contact_login in self.contacts:
            self._safe_run_js('showToast("Этот пользователь уже в контактах!", true);')
            return
        make_server_request_async('add_contact', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_add_contact_response(contact_login, otvet))

    def _handle_add_contact_response(self, contact_login, otvet):
        if otvet and otvet.get('success'):
            make_server_request_async('get_user_info', {
                'user_token': self.main_window.user_token,
                'user_id': self.main_window.user_id,
                'target_login': contact_login,
                'session_token': self.main_window.session_token
            }, lambda resp: self._handle_add_contact_info(contact_login, resp))
        else:
            oshibka = otvet.get('error', 'Неизвестная ошибка') if otvet else 'Ошибка соединения'
            safe_error = html.escape(oshibka).replace('"', '\\"').replace("'", "\\'")
            self._safe_run_js(f'showToast("Ошибка: {safe_error}", true);')

    def _handle_add_contact_info(self, contact_login, otvet):
        if otvet and otvet.get('success'):
            u = otvet.get('user')
            if u:
                novyy = Contact(login=u['login'], username=u['username'],
                                user_id=u['user_id'], avatar_version=u.get('avatar_version', 0))
                self.contacts[contact_login] = novyy
                self.load_contact_avatar(novyy)
                self._update_contacts_js()
                self._safe_run_js('showToast("Контакт добавлен!");')
                self.load_contact_settings()
        else:
            self._safe_run_js('showToast("Пользователь не найден!", true);')

    def delete_chat(self, contact_login):
        make_server_request_async('remove_contact', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_remove_contact_response(contact_login, otvet))

    def _handle_remove_contact_response(self, contact_login, otvet):
        if otvet and otvet.get('success'):
            self.contacts.pop(contact_login, None)
            self.contact_avatars.pop(contact_login, None)
            self._update_contacts_js()
            if self.cur_contact and self.cur_contact.login == contact_login:
                self.cur_contact = None
                self._safe_run_js('showWelcomeScreen();')
            self._safe_run_js('showToast("Чат удален!");')

    def rename_contact(self, contact_login, new_name):
        if not new_name:
            return
        if len(new_name) > 64:
            self._safe_run_js('showToast("Имя не может быть длиннее 64 символов", true);')
            return
        make_server_request_async('save_contact_settings', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact_login,
            'display_name': new_name,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_rename_contact_response(contact_login, new_name, otvet))

    def _handle_rename_contact_response(self, contact_login, new_name, otvet):
        if otvet and otvet.get('success') and contact_login in self.contacts:
            self.contacts[contact_login].display_name = new_name
            self._update_contacts_js()
            self._save_settings_cache()
            if self.cur_contact and self.cur_contact.login == contact_login:
                self.cur_contact.display_name = new_name
                safe_name = html.escape(new_name).replace('"', '\\"').replace("'", "\\'")
                self._safe_run_js(
                    f'document.getElementById("chatName").textContent = "{safe_name}";')
            self._safe_run_js('showToast("Контакт переименован!");')

    def show_settings(self):
        self.main_window.show_settings_window()

    def setup_msg_listener(self):
        messenger_api.network_manager.message_received.connect(self.on_msg_received)
        messenger_api.network_manager.avatar_updated.connect(self.on_avatar_updated)

    def on_msg_received(self, message_data):
        login_kontakta = (message_data['receiver_login']
                          if message_data['sender_login'] == self.main_window.current_user
                          else message_data['sender_login'])
        kontakt = self.contacts.get(login_kontakta)
        if not kontakt:
            return

        msg_id = message_data.get('id')
        if msg_id is not None and self.msg_cache.is_decrypted(kontakt.user_id, msg_id):
            return
        mgid = message_data.get('message_group_id')
        if mgid:
            for cached in self.msg_cache.load_messages(kontakt.user_id):
                if (cached.get('message_group_id') == mgid
                        and cached.get('decrypted_text') is not None):
                    if isinstance(msg_id, int):
                        try:
                            messenger_api.update_message_checkpoint(
                                kontakt.user_id, msg_id)
                        except Exception:
                            pass
                    return

        kopiya = dict(message_data)
        self._process_e2ee_msg(kopiya, login_kontakta)
        if isinstance(msg_id, int):
            try:
                messenger_api.update_message_checkpoint(kontakt.user_id, msg_id)
            except Exception:
                pass
        if kopiya.get('_skip'):
            return
        if kopiya.get('decrypted_text') is None:
            return
        if kopiya.get('file_id') and not kopiya.get('file_info'):
            kopiya['file_info'] = message_data.get('file_info') or {}
            if kopiya['file_info'] is not None:
                kopiya['file_info']['file_meta'] = kopiya.get('file_meta')
        self.msg_cache.append_messages(kontakt.user_id, [kopiya])

        if self.cur_contact and self.cur_contact.user_id == kontakt.user_id:
            self._safe_run_js(
                f'appendMessage({json.dumps(self.prepare_msg_for_display(kopiya))});')
            self.ensure_msg_previews(kontakt.user_id, [kopiya])

    def sync_archive_for_contact(self, contact):
        if not messenger_api.session_manager:
            return
        existing = self.msg_cache.load_messages(contact.user_id)
        existing_groups = {m.get('message_group_id') for m in existing if m.get('message_group_id')}
        try:
            entries = messenger_api.archive_fetch(peer_login=contact.login)
        except Exception:
            entries = []
        if not entries:
            return
        novyye = []
        for entry in entries:
            mgid = entry.get('_message_group_id') or entry.get('message_group_id')
            if mgid and mgid in existing_groups:
                continue
            kind = entry.get('kind')
            sender_login = entry.get('sender_login') or self.main_window.current_user
            receiver_login = entry.get('receiver_login') or contact.login
            text = entry.get('text', '') or ''
            file_id = entry.get('file_id')
            file_meta = entry.get('file_meta')
            ts = entry.get('client_timestamp') or entry.get('_created_at') or ''
            archive_id = entry.get('_archive_id', 0)
            msg = {
                'id': f'archive_{archive_id}',
                'message_group_id': mgid,
                'sender_login': sender_login,
                'sender_device_id': entry.get('sender_device_id') or '',
                'receiver_login': receiver_login,
                'message_text': text,
                'decrypted_text': text,
                'timestamp': ts,
                'client_timestamp': ts,
                'has_file': 1 if file_id else 0,
                'file_id': file_id,
                'file_meta': file_meta,
                'archive_origin': kind or 'archive',
            }
            if file_id and file_meta:
                msg['file_info'] = {
                    'id': file_id,
                    'name': file_meta.get('name', 'file'),
                    'type': file_meta.get('type', 'application/octet-stream'),
                    'size': file_meta.get('size', 0),
                    'is_image_only': bool(file_meta.get('is_image_only')),
                    'nonce_file': file_meta.get('nonce_file'),
                    'nonce_thumbnail': file_meta.get('nonce_thumbnail'),
                    'file_meta': file_meta,
                }
            novyye.append(msg)
        if novyye:
            self.msg_cache.append_messages(contact.user_id, novyye)

    def on_avatar_updated(self, data):
        for kontakt in self.contacts.values():
            if kontakt.user_id == data.get('user_id'):
                kontakt.avatar_version = data.get('new_version')
                self.load_contact_avatar(kontakt, force_download=True)
                break

    def check_avatar_updates(self):
        nuzhno_proverit = [c for c in self.contacts.values() if c.needs_avatar_check()]
        if not nuzhno_proverit:
            return
        make_server_request_async('get_avatar_versions', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'user_ids': [c.user_id for c in nuzhno_proverit],
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_avatar_versions_response(nuzhno_proverit, otvet))

    def _handle_avatar_versions_response(self, nuzhno_proverit, otvet):
        if otvet and otvet.get('success'):
            versii = otvet.get('versions', {})
            for kontakt in nuzhno_proverit:
                servernaya_versiya = versii.get(kontakt.user_id, 0)
                if servernaya_versiya != kontakt.avatar_version:
                    kontakt.avatar_version = servernaya_versiya
                    self.load_contact_avatar(kontakt, force_download=True)
                kontakt.update_avatar_check_time()

    def load_contact_avatars(self):
        for kontakt in self.contacts.values():
            self.load_contact_avatar(kontakt)

    def load_contact_avatar(self, contact, force_download=False):
        if (messenger_api.network_manager.has_avatar_cached(contact.user_id, contact.avatar_version)
                and not force_download):
            avatar_dannyye = messenger_api.network_manager.get_avatar_from_cache(
                contact.user_id, contact.avatar_version)
            if avatar_dannyye:
                pixmap = QPixmap()
                pixmap.loadFromData(avatar_dannyye)
                self.contact_avatars[contact.login] = pixmap
                self._update_avatar_in_js(contact.login)
                return

        def handle_avatar_otvet(otvet):
            if otvet and otvet.get('success') and otvet.get('avatar'):
                avatar_bayty = base64.b64decode(otvet['avatar'])
                messenger_api.network_manager.save_avatar_to_cache(
                    contact.user_id, contact.avatar_version, avatar_bayty)
                if contact.avatar_version > 0:
                    messenger_api.network_manager.remove_old_avatar(
                        contact.user_id, contact.avatar_version - 1)
                pixmap = QPixmap()
                pixmap.loadFromData(avatar_bayty)
                self.contact_avatars[contact.login] = pixmap
                self._update_avatar_in_js(contact.login)

        make_server_request_async('get_avatar', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'target_user_id': contact.user_id,
            'session_token': self.main_window.session_token
        }, handle_avatar_otvet)

    def load_contacts(self):
        make_server_request_async('get_contacts', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'session_token': self.main_window.session_token
        }, self._handle_contacts_response)

    def _handle_contacts_response(self, otvet):
        if otvet and otvet.get('success'):
            self.contacts = {}
            for d in otvet['contacts']:
                kontakt = Contact(login=d['login'], username=d['username'],
                                  user_id=d['user_id'], avatar_version=d.get('avatar_version', 0))
                kontakt.update_avatar_check_time()
                self.contacts[d['login']] = kontakt
            self._load_cached_settings()
            self._update_contacts_js()
            self.load_contact_avatars()
            self.sync_all_contacts()
            self.load_user_data()
            self.preload_all_imgs()
            QTimer.singleShot(400, self.load_contact_settings)

    def sync_all_contacts(self):
        for kontakt in self.contacts.values():
            self.sync_archive_for_contact(kontakt)
            self.sync_contact_msgs(kontakt)
        self.preload_all_imgs()

    def sync_contact_msgs(self, contact):
        cache_last = self.msg_cache.get_last_message_id(contact.user_id)
        cp_last = 0
        try:
            cp_last = messenger_api.get_message_checkpoint(contact.user_id)
        except Exception:
            pass
        last_id = max(cache_last, cp_last)
        make_server_request_async('get_messages_since', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'contact_login': contact.login,
            'since_id': last_id,
            'session_token': self.main_window.session_token
        }, lambda otvet: self._handle_messages_since_response(contact, otvet))

    def _handle_messages_since_response(self, contact, otvet):
        if not otvet or not otvet.get('success'):
            return
        novyye = otvet.get('messages', [])
        if not novyye:
            return

        cached = self.msg_cache.load_messages(contact.user_id)
        existing_by_id = {m.get('id'): m for m in cached if m.get('id') is not None}
        existing_decrypted_mgids = {
            m.get('message_group_id') for m in cached
            if m.get('message_group_id') and m.get('decrypted_text') is not None
        }
        is_active = bool(self.cur_contact and self.cur_contact.user_id == contact.user_id)

        max_seen_id = 0
        prepared = []
        for raw in novyye:
            mid = raw.get('id')
            mgid = raw.get('message_group_id')
            if isinstance(mid, int) and mid > max_seen_id:
                max_seen_id = mid

            id_cached = existing_by_id.get(mid) if mid is not None else None
            if id_cached is not None and id_cached.get('decrypted_text') is not None:
                continue
            if mgid and mgid in existing_decrypted_mgids:
                continue

            msg = dict(raw)
            otpravitel = msg.get('sender_login')
            login_dlya_decrypt = (msg.get('receiver_login')
                                  if otpravitel == self.main_window.current_user
                                  else otpravitel)
            self._process_e2ee_msg(msg, login_dlya_decrypt)
            if msg.get('_skip'):
                continue
            if msg.get('decrypted_text') is None:
                continue
            prepared.append(msg)

        if max_seen_id > 0:
            try:
                messenger_api.update_message_checkpoint(contact.user_id, max_seen_id)
            except Exception:
                pass

        if not prepared:
            return

        dobavlennyye = self.msg_cache.append_messages(contact.user_id, prepared)
        if not dobavlennyye:
            return

        if is_active:
            for msg in dobavlennyye:
                if msg.get('decrypted_text') is None:
                    continue
                self._safe_run_js(
                    f'appendMessage({json.dumps(self.prepare_msg_for_display(msg))});')
            self.ensure_msg_previews(contact.user_id, dobavlennyye)

    def preload_all_imgs(self):
        for kontakt in self.contacts.values():
            for msg in self.msg_cache.load_messages(kontakt.user_id):
                if msg.get('has_file') and msg.get('file_info') and msg['file_info'].get('is_image_only'):
                    file_id = msg['file_info']['id']
                    if not messenger_api.file_cache or not messenger_api.file_cache.has_file(file_id):
                        self._load_file_preview_bg(file_id, msg['id'], kontakt.user_id)

    def ensure_msg_previews(self, contact_user_id, soobshenia):
        for msg in soobshenia:
            if msg.get('has_file') and msg.get('file_info') and msg['file_info'].get('is_image_only'):
                file_id = msg['file_info']['id']
                if not messenger_api.file_cache or not messenger_api.file_cache.has_file(file_id):
                    self._load_file_preview(file_id, msg['id'], contact_user_id)

    def _load_file_preview(self, file_id, message_id, contact_user_id):
        file_meta = self._lookup_file_meta(file_id)
        if not file_meta:
            return

        def handle_otvet(otvet):
            if not otvet or not otvet.get('success'):
                return
            raw = base64.b64decode(otvet.get('file_data'))
            dannyye = self._decrypt_file_bytes(raw, None, file_meta=file_meta)
            if dannyye is None:
                return
            prevyu = self._gen_thumbnail(dannyye)
            if messenger_api.file_cache:
                messenger_api.file_cache.save_file(
                    file_id,
                    file_meta.get('name', 'unknown'),
                    file_meta.get('type', 'application/octet-stream'),
                    file_meta.get('size', 0),
                    dannyye, prevyu)
            if prevyu:
                prevyu_b64 = base64.b64encode(prevyu).decode('utf-8')
                self._safe_run_js(
                    f'updateMessageThumbnail({json.dumps(message_id)}, "{prevyu_b64}");')

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'session_token': self.main_window.session_token
        }, handle_otvet)

    def _load_file_preview_bg(self, file_id, message_id, contact_user_id):
        file_meta = self._lookup_file_meta(file_id)
        if not file_meta:
            return

        def handle_otvet(otvet):
            if not otvet or not otvet.get('success'):
                return
            raw = base64.b64decode(otvet.get('file_data'))
            dannyye = self._decrypt_file_bytes(raw, None, file_meta=file_meta)
            if dannyye is None:
                return
            prevyu = self._gen_thumbnail(dannyye)
            if messenger_api.file_cache:
                messenger_api.file_cache.save_file(
                    file_id,
                    file_meta.get('name', 'unknown'),
                    file_meta.get('type', 'application/octet-stream'),
                    file_meta.get('size', 0),
                    dannyye, prevyu)

        make_server_request_async('get_file', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'file_id': file_id,
            'include_data': True,
            'session_token': self.main_window.session_token
        }, handle_otvet)

    def load_contact_settings(self):
        make_server_request_async('get_contact_settings', {
            'user_token': self.main_window.user_token,
            'user_id': self.main_window.user_id,
            'session_token': self.main_window.session_token
        }, self._handle_settings_response)

    def _handle_settings_response(self, otvet):
        if otvet and otvet.get('success'):
            nastroyki = otvet.get('settings', {})
            obnovleno = False
            for login, setting in nastroyki.items():
                if login in self.contacts:
                    imya = setting.get('display_name')
                    if imya and self.contacts[login].display_name != imya:
                        self.contacts[login].display_name = imya
                        obnovleno = True
            if obnovleno:
                self._update_contacts_js()
                self._save_settings_cache()
                if self.cur_contact and self.cur_contact.login in nastroyki:
                    novoe_imya = nastroyki[self.cur_contact.login].get('display_name')
                    if novoe_imya:
                        self.cur_contact.display_name = novoe_imya
                        safe_name = html.escape(novoe_imya).replace('"', '\\"').replace("'", "\\'")
                        self._safe_run_js(
                            f'document.getElementById("chatName").textContent = "{safe_name}";')
            self._save_settings_cache()
            self.settings_retry_count = 0
        else:
            if self.settings_retry_count < 3:
                self.settings_retry_count += 1
                QTimer.singleShot(1500, self.load_contact_settings)

    def _load_cached_settings(self):
        kesh = self.msg_cache.load_contact_settings_cache()
        obnovleno = False
        for login, imya in kesh.items():
            if login in self.contacts and self.contacts[login].display_name != imya:
                self.contacts[login].display_name = imya
                obnovleno = True
        if obnovleno:
            self._update_contacts_js()
            if self.cur_contact and self.cur_contact.login in kesh:
                self._safe_run_js(
                    f'document.getElementById("chatName").textContent = '
                    f'"{html.escape(kesh[self.cur_contact.login])}";')

    def _save_settings_cache(self):
        self.msg_cache.save_contact_settings_cache({
            login: c.display_name
            for login, c in self.contacts.items()
            if c.display_name and c.display_name != c.username
        })

    def prepare_msg_for_display(self, msg):
        kopiya = dict(msg)
        tekst = kopiya.get('decrypted_text', kopiya.get('message_text', ''))
        if _is_legacy(tekst):
            tekst = ''
        if tekst and not tekst.startswith('['):
            html_tekst = markdown.markdown(tekst, extensions=['nl2br', 'tables'])
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a', 'ul', 'ol', 'li',
                            'blockquote', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
            allowed_attrs = {'a': ['href', 'title']}
            kopiya['message_text'] = bleach.clean(
                html_tekst, tags=allowed_tags, attributes=allowed_attrs,
                strip=True, protocols=['http', 'https', 'mailto'])
        else:
            kopiya['message_text'] = tekst or ''

        if kopiya.get('has_file') and kopiya.get('file_info'):
            fi = kopiya['file_info']
            fi['sender_login'] = kopiya.get('sender_login', '')
            fi.setdefault('is_encrypted', True)
            fi.setdefault('encrypted_key', None)
            fi.setdefault('nonce_file', None)
            kopiya['is_image_only'] = fi.get('is_image_only', False)
            if fi.get('is_image_only') and fi['type'].startswith('image/'):
                if messenger_api.file_cache:
                    dannyye = messenger_api.file_cache.get_file_data(fi['id'])
                    if dannyye:
                        prevyu = messenger_api.file_cache.get_thumbnail_data(fi['id'])
                        if prevyu:
                            fi['thumbnail'] = base64.b64encode(prevyu).decode('utf-8')
            else:
                fi['icon'] = self.get_file_icon(fi['type'])
                fi['size_kb'] = round(fi['size'] / 1024, 1)

        if kopiya.get('timestamp'):
            try:
                dt = datetime.fromisoformat(kopiya.get('timestamp', '').replace('Z', '+00:00'))
                kopiya['display_time'] = (dt + timedelta(hours=3)).strftime("%d.%m %H:%M")
            except (ValueError, TypeError):
                kopiya['display_time'] = ''
        else:
            kopiya['display_time'] = ''
        return kopiya

    def get_file_icon(self, file_type):
        if file_type.startswith('image/'):
            return '🖼'
        if file_type.startswith('video/'):
            return '🎬'
        if file_type.startswith('audio/'):
            return '🎵'
        if file_type == 'application/pdf':
            return '📕'
        if 'word' in file_type or 'document' in file_type:
            return '📘'
        if 'excel' in file_type or 'sheet' in file_type:
            return '📗'
        if 'presentation' in file_type or 'powerpoint' in file_type:
            return '📙'
        if 'text' in file_type:
            return '📄'
        return '📎'

    def _gen_thumbnail(self, image_data, max_size=(400, 400)):
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(image_data))
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        vyvod = io.BytesIO()
        img.save(vyvod, format='JPEG', quality=70, optimize=True)
        return vyvod.getvalue()

    def _update_contacts_js(self):
        if not self.page_loaded:
            self.contacts_need_update = True
            return
        spisok = [
            {
                'login': c.login,
                'username': c.username,
                'display_name': html.escape(c.get_display_name()) if c.get_display_name() else c.login,
                'avatar': self._get_avatar_data(c.login)
            }
            for c in self.contacts.values()
        ]
        self._safe_run_js(f'setContacts({json.dumps(spisok)});')
        self.contacts_need_update = False

    def _update_avatar_in_js(self, login):
        if not self.page_loaded:
            return
        dannyye = self._get_avatar_data(login)
        if dannyye:
            self._safe_run_js(f'updateContactAvatar("{login}", "{dannyye}");')

    def _get_avatar_data(self, login):
        pixmap = self.contact_avatars.get(login)
        if pixmap and not pixmap.isNull():
            byte_array = QByteArray()
            buf = QBuffer(byte_array)
            buf.open(QBuffer.OpenModeFlag.WriteOnly)
            pixmap.save(buf, "PNG")
            return 'data:image/png;base64,' + byte_array.toBase64().data().decode()
        return self._get_default_avatar_data()

    def _get_default_avatar_data(self):
        default_path = self.script_dir / "images" / "default_avatar.jpg"
        pixmap = QPixmap(str(default_path)) if default_path.exists() else QPixmap(60, 60)
        if not default_path.exists():
            pixmap.fill(Qt.GlobalColor.gray)
        byte_array = QByteArray()
        buf = QBuffer(byte_array)
        buf.open(QBuffer.OpenModeFlag.WriteOnly)
        pixmap.save(buf, "PNG")
        return 'data:image/png;base64,' + byte_array.toBase64().data().decode()

    def closeEvent(self, event):
        self._destroyed = True
        self.avatar_timer.stop()
        self.sync_timer.stop()
        super().closeEvent(event)