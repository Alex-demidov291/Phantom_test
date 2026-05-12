import base64
import datetime
import hashlib
import hmac
import io
import os
import json
import queue
import secrets
import sqlite3
import threading
import time
import uuid
from collections import defaultdict

import opaque_ke_py
from PIL import Image
from flask import Flask, request, jsonify, Response, stream_with_context
import settings


def adapt_datetime(dt):
    return dt.isoformat()


sqlite3.register_adapter(datetime.datetime, adapt_datetime)

SERVER_HOST = settings.SERVER_HOST
SERVER_PORT = settings.RUNNING_PORT
SESSION_HASH_SALT = settings.SESSION_HASH_SALT

_SECRET_KEY_FILE = "secret_key.bin"
if os.path.exists(_SECRET_KEY_FILE):
    with open(_SECRET_KEY_FILE, "rb") as _f:
        SECRET_KEY = _f.read()
else:
    SECRET_KEY = secrets.token_bytes(32)
    with open(_SECRET_KEY_FILE, "wb") as _f:
        _f.write(SECRET_KEY)

TOKEN_LIFETIME = 86400
app = Flask(__name__)

_SERVER_SETUP_FILE = "server_setup.bin"
if os.path.exists(_SERVER_SETUP_FILE):
    with open(_SERVER_SETUP_FILE, "rb") as _f:
        SERVER_SETUP_BYTES = _f.read()
else:
    SERVER_SETUP_BYTES = opaque_ke_py.server_setup().to_bytes()
    with open(_SERVER_SETUP_FILE, "wb") as _f:
        _f.write(SERVER_SETUP_BYTES)

import collections

RATE_BUCKET_CAPACITY = 20
RATE_BUCKET_REFILL_PER_SEC = 20
RATE_BUCKET_LRU_CAP = 20000
BLOCK_ATTEMPTS = 8
BLOCK_DURATION = 3600

_rate_lock = threading.Lock()
_rate_buckets = collections.OrderedDict()


def _bucket_key(raw):
    h = hashlib.blake2b(raw.encode('utf-8'), digest_size=16,
                        key=SECRET_KEY[:64]).digest()
    return h


def _take_token(raw_key):
    key = _bucket_key(raw_key)
    now = time.time()
    with _rate_lock:
        entry = _rate_buckets.get(key)
        if entry is None:
            tokens = float(RATE_BUCKET_CAPACITY)
            last = now
        else:
            tokens, last = entry
            tokens = min(
                RATE_BUCKET_CAPACITY,
                tokens + (now - last) * RATE_BUCKET_REFILL_PER_SEC,
            )
            last = now
        if tokens < 1.0:
            _rate_buckets[key] = (tokens, last)
            _rate_buckets.move_to_end(key)
            return False
        tokens -= 1.0
        _rate_buckets[key] = (tokens, last)
        _rate_buckets.move_to_end(key)
        while len(_rate_buckets) > RATE_BUCKET_LRU_CAP:
            _rate_buckets.popitem(last=False)
        return True


def rate_limit(f):
    def decorated(*args, **kwargs):
        device_id = request.headers.get('X-Device-ID')
        if not device_id:
            return jsonify({'success': False, 'error': 'Device ID required'}), 400
        if not _take_token(device_id):
            return jsonify({'success': False, 'error': 'Too many requests'}), 429
        return f(*args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


def anonymous_rate_limit(f):
    def decorated(*args, **kwargs):
        key = (request.headers.get('X-Device-ID')
               or request.remote_addr or 'anon')
        if not _take_token(key):
            return jsonify({'success': False,
                            'error': 'Too many requests'}), 429
        return f(*args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


class Database:
    def __init__(self, db_path='messenger.db'):
        self.db_path = db_path
        self.init_db()
        self.start_cleanup_thread()
        self.start_status_cleanup_thread()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.executescript('''
            DROP TABLE IF EXISTS user_signed_prekeys;
            DROP TABLE IF EXISTS user_one_time_prekeys;
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                login TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                user_id INTEGER UNIQUE,
                avatar_version INTEGER DEFAULT 0,
                opaque_password_file BLOB NOT NULL,
                e2ee_salt TEXT,
                encrypted_master_key TEXT,
                master_key_salt TEXT,
                master_key_binding_sig TEXT,
                master_key_binding_sik_pub TEXT
            )
        ''')
        for col, ddl in (
            ('master_key_binding_sig',
             'ALTER TABLE users ADD COLUMN master_key_binding_sig TEXT'),
            ('master_key_binding_sik_pub',
             'ALTER TABLE users ADD COLUMN master_key_binding_sik_pub TEXT'),
        ):
            try:
                cursor.execute(ddl)
            except sqlite3.OperationalError:
                pass
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                device_label TEXT,
                device_ik TEXT,
                device_ik_signature TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, device_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        for col, ddl in (
            ('device_ik', 'ALTER TABLE devices ADD COLUMN device_ik TEXT'),
            ('device_ik_signature', 'ALTER TABLE devices ADD COLUMN device_ik_signature TEXT'),
        ):
            try:
                cursor.execute(ddl)
            except sqlite3.OperationalError:
                pass
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_signed_prekeys (
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                spk_id INTEGER NOT NULL,
                public_key TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, device_id, spk_id),
                FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id)
            )
        ''')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_spk_device '
            'ON device_signed_prekeys (user_id, device_id, spk_id)'
        )
        try:
            cursor.execute('PRAGMA index_list("device_signed_prekeys")')
            pk_cols = []
            for idx in cursor.fetchall():
                idx_name, _, _, origin, _ = (
                    idx[0], idx[1], idx[2], idx[3], idx[4]
                )
                if origin == 'pk':
                    cursor.execute(f'PRAGMA index_info("{idx_name}")')
                    pk_cols = [r[2] for r in cursor.fetchall()]
                    break
            if pk_cols == ['user_id', 'device_id']:
                cursor.executescript('''
                    ALTER TABLE device_signed_prekeys RENAME TO _spk_old;
                    CREATE TABLE device_signed_prekeys (
                        user_id INTEGER NOT NULL,
                        device_id TEXT NOT NULL,
                        spk_id INTEGER NOT NULL,
                        public_key TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (user_id, device_id, spk_id),
                        FOREIGN KEY (user_id, device_id)
                          REFERENCES devices(user_id, device_id)
                    );
                    INSERT INTO device_signed_prekeys
                        (user_id, device_id, spk_id, public_key, signature,
                         created_at)
                    SELECT user_id, device_id, spk_id, public_key, signature,
                           created_at
                    FROM _spk_old;
                    DROP TABLE _spk_old;
                    CREATE INDEX IF NOT EXISTS idx_spk_device
                      ON device_signed_prekeys (user_id, device_id, spk_id);
                ''')
        except sqlite3.OperationalError:
            pass
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_one_time_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                opk_id INTEGER NOT NULL,
                public_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, device_id, opk_id),
                FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id)
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_dopk_owner ON device_one_time_prekeys (user_id, device_id)')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_group_id TEXT NOT NULL,
                sender_user_id INTEGER NOT NULL,
                sender_login TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                receiver_user_id INTEGER NOT NULL,
                receiver_login TEXT NOT NULL,
                target_device_id TEXT NOT NULL,
                wire TEXT NOT NULL,
                file_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_timestamp TEXT,
                nonce TEXT
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_msg_recv ON messages (receiver_user_id, target_device_id, id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_msg_group ON messages (message_group_id)')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_data BLOB NOT NULL,
                thumbnail_data BLOB,
                nonce_file TEXT NOT NULL,
                nonce_thumbnail TEXT,
                uploaded_by TEXT NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_image_only INTEGER DEFAULT 0,
                FOREIGN KEY (uploaded_by) REFERENCES users(login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS archive (
                archive_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                peer_user_id INTEGER,
                peer_login TEXT,
                peer_handle TEXT,
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                message_group_id TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        for col, ddl in (
            ('peer_handle', 'ALTER TABLE archive ADD COLUMN peer_handle TEXT'),
        ):
            try:
                cursor.execute(ddl)
            except sqlite3.OperationalError:
                pass
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_archive_owner ON archive (user_id, peer_user_id, archive_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_archive_handle ON archive (user_id, peer_handle, archive_id)')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_pairings (
                pair_id TEXT PRIMARY KEY,
                code_hash TEXT NOT NULL,
                primary_user_id INTEGER NOT NULL,
                epk_a_pub TEXT NOT NULL,
                epk_b_pub TEXT,
                sealed_bundle TEXT,
                attempts INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            )
        ''')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_pairings_hash '
            'ON device_pairings (code_hash)'
        )
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                extra TEXT
            )
        ''')
        cursor.execute(
            'CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts)'
        )
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_encrypted_blobs (
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                nonce TEXT NOT NULL,
                version INTEGER DEFAULT 1,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, kind)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_owner TEXT NOT NULL,
                contact_login TEXT NOT NULL,
                FOREIGN KEY (contact_owner) REFERENCES users(login),
                FOREIGN KEY (contact_login) REFERENCES users(login),
                UNIQUE(contact_owner, contact_login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contact_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_login TEXT NOT NULL,
                contact_login TEXT NOT NULL,
                display_name TEXT,
                FOREIGN KEY (user_login) REFERENCES users(login),
                FOREIGN KEY (contact_login) REFERENCES users(login),
                UNIQUE(user_login, contact_login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                user_login TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (user_login) REFERENCES users(login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cleanup_settings (
                user_id INTEGER PRIMARY KEY,
                cleanup_interval INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_avatars (
                user_id INTEGER PRIMARY KEY,
                avatar_data BLOB NOT NULL,
                file_size INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS opaque_login_states (
                state_id TEXT PRIMARY KEY,
                login TEXT NOT NULL,
                server_state BLOB NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY (login) REFERENCES users(login)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL,
                device_id TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                blocked_until TIMESTAMP,
                UNIQUE(login, device_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_public_keys (
                user_id INTEGER PRIMARY KEY,
                public_key TEXT NOT NULL,
                signature TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at DATETIME NOT NULL,
                PRIMARY KEY (nonce, user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_status (
                user_id INTEGER PRIMARY KEY,
                status TEXT DEFAULT 'offline',
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                current_device_id TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_connections (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_ping DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_online INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        conn.commit()
        conn.close()

    def start_cleanup_thread(self):
        def fast_worker():
            while True:
                time.sleep(15)
                self.cleanup_used_nonces()
                self.cleanup_expired_pairings()
                self.cleanup_expired_opaque_login_states()

        def slow_worker():
            while True:
                time.sleep(300)
                self.cleanup_expired_sessions()
                self.cleanup_old_signed_prekeys()

        threading.Thread(target=fast_worker, daemon=True).start()
        threading.Thread(target=slow_worker, daemon=True).start()

    def start_status_cleanup_thread(self):
        def status_cleanup_worker():
            while True:
                time.sleep(60)
                self.cleanup_offline_connections()

        thread = threading.Thread(target=status_cleanup_worker, daemon=True)
        thread.start()

    def cleanup_expired_sessions(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT user_id FROM user_sessions 
            WHERE expires_at < datetime('now') AND is_active = 1
        ''')
        expired_users = cursor.fetchall()
        for user in expired_users:
            user_id = user[0]
            cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
            cleanup = cursor.fetchone()
            if cleanup and cleanup[0] == 0:
                cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND expires_at < datetime("now")',
                               (user_id,))
            else:
                cursor.execute('''
                    UPDATE user_sessions SET is_active = 0 
                    WHERE user_id = ? AND expires_at < datetime("now")
                ''', (user_id,))
        conn.commit()
        conn.close()

    def cleanup_used_nonces(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM used_nonces WHERE expires_at < datetime('now')")
        conn.commit()
        conn.close()

    def cleanup_expired_pairings(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM device_pairings WHERE expires_at < datetime('now')"
            )
            conn.commit()
        except sqlite3.OperationalError:
            pass
        conn.close()

    def cleanup_expired_opaque_login_states(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM opaque_login_states WHERE expires_at < datetime('now')"
        )
        conn.commit()
        conn.close()

    def cleanup_old_signed_prekeys(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                DELETE FROM device_signed_prekeys
                WHERE created_at < datetime('now', '-14 days')
                  AND (user_id, device_id, spk_id) NOT IN (
                    SELECT user_id, device_id, MAX(spk_id)
                    FROM device_signed_prekeys
                    GROUP BY user_id, device_id
                  )
            """)
            conn.commit()
        except sqlite3.OperationalError:
            pass
        conn.close()

    def cleanup_offline_connections(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_connections WHERE last_ping < datetime('now', '-5 minutes')")
        conn.commit()
        conn.close()

    def get_login_attempt(self, login, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT attempts, last_attempt, blocked_until FROM login_attempts WHERE login = ? AND device_id = ?',
            (login, device_id))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    def increment_login_attempt(self, login, device_id):
        now = datetime.datetime.now().isoformat()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO login_attempts (login, device_id, attempts, last_attempt)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(login, device_id) DO UPDATE SET
                attempts = attempts + 1,
                last_attempt = ?
        ''', (login, device_id, now, now))
        conn.commit()
        cursor.execute('SELECT attempts FROM login_attempts WHERE login = ? AND device_id = ?', (login, device_id))
        attempts = cursor.fetchone()[0]
        if attempts >= BLOCK_ATTEMPTS:
            blocked_until = (datetime.datetime.now() + datetime.timedelta(seconds=BLOCK_DURATION)).isoformat()
            cursor.execute(
                'UPDATE login_attempts SET blocked_until = ?, attempts = 0 WHERE login = ? AND device_id = ?',
                (blocked_until, login, device_id))
            conn.commit()
        conn.close()
        return True

    def reset_login_attempt(self, login, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM login_attempts WHERE login = ? AND device_id = ?', (login, device_id))
        conn.commit()
        conn.close()
        return True

    def is_login_blocked(self, login, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT blocked_until FROM login_attempts WHERE login = ? AND device_id = ?', (login, device_id))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            blocked_until = datetime.datetime.fromisoformat(row[0])
            if blocked_until > datetime.datetime.now():
                seconds = (blocked_until - datetime.datetime.now()).seconds
                return True, seconds
        return False, 0

    def get_user_by_login(self, login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE login = ?', (login,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return dict(user)
        return None

    def get_user_avatar_version(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT avatar_version FROM users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else 0

    def get_avatar_versions(self, user_ids):
        if not user_ids:
            return {}
        conn = self.get_connection()
        cursor = conn.cursor()
        placeholders = ','.join(['?'] * len(user_ids))
        query = 'SELECT user_id, avatar_version FROM users WHERE user_id IN (' + placeholders + ')'
        cursor.execute(query, user_ids)
        rows = cursor.fetchall()
        conn.close()
        return {row[0]: row[1] for row in rows}

    def get_avatar_data(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT avatar_data FROM user_avatars WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def update_user_avatar(self, user_id, avatar_data):
        compressed = self._compress_avatar(avatar_data)
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET avatar_version = avatar_version + 1 WHERE user_id = ?', (user_id,))
        cursor.execute('''
            INSERT OR REPLACE INTO user_avatars (user_id, avatar_data, file_size)
            VALUES (?, ?, ?)
        ''', (user_id, compressed, len(compressed)))
        conn.commit()
        new_version = cursor.execute('SELECT avatar_version FROM users WHERE user_id = ?', (user_id,)).fetchone()[0]
        conn.close()
        return True, new_version

    def _compress_avatar(self, image_data):
        img = Image.open(io.BytesIO(image_data))
        if img.width > 8000 or img.height > 5000:
            raise ValueError("Изображение слишком большое (максимум 8000x5000)")
        if len(image_data) > 150 * 1024:
            raise ValueError("Изображение слишком тяжелое (максимум 150KB)")
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=85, optimize=True, progressive=True)
        compressed = output.getvalue()
        if len(compressed) > 150 * 1024:
            output = io.BytesIO()
            quality = 70
            while len(compressed) > 150 * 1024 and quality >= 30:
                img.save(output, format='JPEG', quality=quality, optimize=True, progressive=True)
                compressed = output.getvalue()
                quality -= 10
        return compressed

    def save_file(self, file_data, file_name, file_type, uploaded_by,
                  nonce_file, is_image_only=False,
                  thumbnail_data=None, nonce_thumbnail=None):
        file_size = len(file_data)
        if file_size > 10 * 1024 * 1024:
            return False, "Файл слишком большой (максимум 10MB)"

        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO files (
                file_name, file_type, file_size, file_data, thumbnail_data,
                nonce_file, nonce_thumbnail, uploaded_by, is_image_only
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (file_name, file_type, file_size, file_data, thumbnail_data,
              nonce_file, nonce_thumbnail, uploaded_by,
              1 if is_image_only else 0))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return True, file_id

    def _generate_thumbnail(self, image_data, max_size=(200, 200)):
        img = Image.open(io.BytesIO(image_data))
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=70, optimize=True)
        return output.getvalue()

    def get_file(self, file_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
        file = cursor.fetchone()
        conn.close()
        if file:
            return dict(file)
        return None

    def get_file_thumbnail(self, file_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT thumbnail_data FROM files WHERE id = ?', (file_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def insert_envelope(self, message_group_id, sender_user_id, sender_login,
                        sender_device_id, receiver_user_id, receiver_login,
                        target_device_id, wire, file_id=None,
                        client_timestamp=None, nonce=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (
                message_group_id, sender_user_id, sender_login, sender_device_id,
                receiver_user_id, receiver_login, target_device_id,
                wire, file_id, client_timestamp, nonce
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (message_group_id, sender_user_id, sender_login, sender_device_id,
              receiver_user_id, receiver_login, target_device_id,
              wire, file_id, client_timestamp, nonce))
        msg_id = cursor.lastrowid
        cursor.execute('SELECT * FROM messages WHERE id = ?', (msg_id,))
        msg = dict(cursor.fetchone())
        conn.commit()
        conn.close()
        return msg

    def get_sealed_messages_for_device(self, viewer_user_id, viewer_device_id,
                                       since_id=0, limit=500):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM messages
            WHERE id > ?
              AND target_device_id = ?
              AND receiver_user_id = ?
              AND sender_user_id = 0
            ORDER BY id ASC
            LIMIT ?
        ''', (since_id, viewer_device_id, viewer_user_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def get_messages_for_device(self, viewer_user_id, viewer_device_id,
                                peer_user_id, since_id=0, limit=200):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT m.*, su.username AS sender_name
            FROM messages m
            JOIN users su ON m.sender_user_id = su.user_id
            WHERE m.id > ?
              AND m.target_device_id = ?
              AND ((m.receiver_user_id = ? AND m.sender_user_id = ?)
                OR (m.receiver_user_id = ? AND m.sender_user_id = ?))
            ORDER BY m.id ASC
            LIMIT ?
        ''', (since_id, viewer_device_id,
              viewer_user_id, peer_user_id,
              peer_user_id, viewer_user_id,
              limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def register_device(self, user_id, device_id, device_label,
                        dev_ik=None, dev_ik_signature=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO devices (user_id, device_id, device_label,
                                 device_ik, device_ik_signature)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, device_id) DO UPDATE SET
                device_label = excluded.device_label,
                device_ik = COALESCE(excluded.device_ik, device_ik),
                device_ik_signature = COALESCE(excluded.device_ik_signature,
                                               device_ik_signature),
                last_seen_at = CURRENT_TIMESTAMP
        ''', (user_id, device_id, device_label, dev_ik, dev_ik_signature))
        conn.commit()
        conn.close()
        return True

    def touch_device(self, user_id, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE devices SET last_seen_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND device_id = ?
        ''', (user_id, device_id))
        conn.commit()
        conn.close()

    def list_devices_for_user(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT device_id, device_label, device_ik, device_ik_signature,
                   created_at, last_seen_at
            FROM devices WHERE user_id = ? ORDER BY created_at ASC
        ''', (user_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def device_exists(self, user_id, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?',
                       (user_id, device_id))
        ok = cursor.fetchone() is not None
        conn.close()
        return ok

    def unlink_device(self, user_id, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM device_one_time_prekeys WHERE user_id = ? AND device_id = ?',
                       (user_id, device_id))
        cursor.execute('DELETE FROM device_signed_prekeys WHERE user_id = ? AND device_id = ?',
                       (user_id, device_id))
        cursor.execute('DELETE FROM messages WHERE receiver_user_id = ? AND target_device_id = ?',
                       (user_id, device_id))
        cursor.execute('DELETE FROM devices WHERE user_id = ? AND device_id = ?',
                       (user_id, device_id))
        conn.commit()
        conn.close()
        return True

    def archive_insert(self, user_id, peer_handle, ciphertext, nonce,
                       message_group_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO archive (user_id, peer_handle, ciphertext, nonce,
                                 message_group_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, peer_handle, ciphertext, nonce, message_group_id))
        archive_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return archive_id

    def archive_fetch(self, user_id, peer_handle=None, since_archive_id=0, limit=500):
        conn = self.get_connection()
        cursor = conn.cursor()
        if peer_handle is None:
            cursor.execute('''
                SELECT archive_id, peer_handle, peer_login, peer_user_id,
                       ciphertext, nonce, message_group_id, created_at
                FROM archive WHERE user_id = ? AND archive_id > ?
                ORDER BY archive_id ASC LIMIT ?
            ''', (user_id, since_archive_id, limit))
        else:
            cursor.execute('''
                SELECT archive_id, peer_handle, peer_login, peer_user_id,
                       ciphertext, nonce, message_group_id, created_at
                FROM archive WHERE user_id = ? AND peer_handle = ? AND archive_id > ?
                ORDER BY archive_id ASC LIMIT ?
            ''', (user_id, peer_handle, since_archive_id, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def add_contact(self, owner_login, contact_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO contacts (contact_owner, contact_login) VALUES (?, ?)
        ''', (owner_login, contact_login))
        conn.commit()
        conn.close()
        return True

    def remove_contact(self, owner_login, contact_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM contacts WHERE contact_owner = ? AND contact_login = ?
        ''', (owner_login, contact_login))
        conn.commit()
        conn.close()
        return True

    def get_contacts(self, owner_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.login, u.username, u.user_id, u.avatar_version
            FROM contacts c
            JOIN users u ON c.contact_login = u.login
            WHERE c.contact_owner = ?
            ORDER BY u.username
        ''', (owner_login,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def is_contact(self, owner_login, contact_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM contacts WHERE contact_owner = ? AND contact_login = ?',
                       (owner_login, contact_login))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def search_users(self, query, current_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        pattern = f'%{query}%'
        cursor.execute('''
            SELECT login, username, user_id, avatar_version
            FROM users
            WHERE (login LIKE ? OR username LIKE ?) AND login != ?
            LIMIT 20
        ''', (pattern, pattern, current_login))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def get_contact_settings(self, user_login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT contact_login, display_name FROM contact_settings WHERE user_login = ?
        ''', (user_login,))
        rows = cursor.fetchall()
        conn.close()
        return {row[0]: {'display_name': row[1]} for row in rows}

    def save_contact_settings(self, user_login, contact_login, display_name):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO contact_settings (user_login, contact_login, display_name)
            VALUES (?, ?, ?)
        ''', (user_login, contact_login, display_name))
        conn.commit()
        conn.close()
        return True

    def save_opaque_password_file(self, login, password_file):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET opaque_password_file = ? WHERE login = ?', (password_file, login))
        conn.commit()
        conn.close()
        return True

    def get_opaque_password_file(self, login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT opaque_password_file FROM users WHERE login = ?', (login,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def save_login_state(self, login, server_state):
        state_id = str(uuid.uuid4())
        expires_at = datetime.datetime.now() + datetime.timedelta(minutes=5)
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO opaque_login_states (state_id, login, server_state, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (state_id, login, server_state, expires_at))
        conn.commit()
        conn.close()
        return state_id

    def get_login_state(self, state_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT login, server_state, expires_at FROM opaque_login_states WHERE state_id = ?',
                       (state_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return dict(row)
        return None

    def delete_login_state(self, state_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM opaque_login_states WHERE state_id = ?', (state_id,))
        conn.commit()
        conn.close()
        return True

    def get_user_public_key(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT public_key, signature FROM user_public_keys WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {'public_key': row[0], 'signature': row[1]}
        return None

    def save_user_public_key(self, user_id, public_key, signature):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO user_public_keys (user_id, public_key, signature, updated_at)
            VALUES (?, ?, ?, datetime('now'))
        ''', (user_id, public_key, signature))
        conn.commit()
        conn.close()
        return True

    def save_signed_prekey(self, user_id, device_id, spk_id, public_key, signature):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO device_signed_prekeys
                (user_id, device_id, spk_id, public_key, signature, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(user_id, device_id, spk_id) DO UPDATE SET
                public_key = excluded.public_key,
                signature = excluded.signature,
                created_at = excluded.created_at
        ''', (user_id, device_id, spk_id, public_key, signature))
        conn.commit()
        conn.close()
        return True

    def get_signed_prekey(self, user_id, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT spk_id, public_key, signature FROM device_signed_prekeys '
            'WHERE user_id = ? AND device_id = ? '
            'ORDER BY spk_id DESC LIMIT 1',
            (user_id, device_id),
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return {'spk_id': row[0], 'public_key': row[1], 'signature': row[2]}
        return None

    def save_one_time_prekeys(self, user_id, device_id, prekeys):
        if not prekeys:
            return 0
        conn = self.get_connection()
        cursor = conn.cursor()
        inserted = 0
        for opk_id, pub in prekeys:
            try:
                cursor.execute('''
                    INSERT INTO device_one_time_prekeys (user_id, device_id, opk_id, public_key)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, device_id, opk_id, pub))
                inserted += 1
            except sqlite3.IntegrityError:
                continue
        conn.commit()
        conn.close()
        return inserted

    def take_one_time_prekey(self, user_id, device_id):
        conn = self.get_connection()
        try:
            conn.execute('BEGIN IMMEDIATE')
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, opk_id, public_key
                FROM device_one_time_prekeys
                WHERE user_id = ? AND device_id = ?
                ORDER BY id ASC
                LIMIT 1
            ''', (user_id, device_id))
            row = cursor.fetchone()
            if not row:
                conn.commit()
                return None
            row_id, opk_id, pub = row[0], row[1], row[2]
            cursor.execute('DELETE FROM device_one_time_prekeys WHERE id = ?', (row_id,))
            conn.commit()
            return {'opk_id': opk_id, 'public_key': pub}
        finally:
            conn.close()

    def count_one_time_prekeys(self, user_id, device_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT COUNT(*) FROM device_one_time_prekeys WHERE user_id = ? AND device_id = ?',
            (user_id, device_id),
        )
        n = cursor.fetchone()[0]
        conn.close()
        return n

    def get_user_e2ee_salt(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT e2ee_salt FROM users WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    def save_user_e2ee_salt(self, user_id, salt):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET e2ee_salt = ? WHERE user_id = ?', (salt, user_id))
        conn.commit()
        conn.close()
        return True

    def save_encrypted_master_key(self, login, encrypted_master_key,
                                  binding_sig=None, binding_sik_pub=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        if binding_sig is not None or binding_sik_pub is not None:
            cursor.execute(
                'UPDATE users SET encrypted_master_key = ?, '
                'master_key_binding_sig = ?, master_key_binding_sik_pub = ? '
                'WHERE login = ?',
                (encrypted_master_key, binding_sig, binding_sik_pub, login),
            )
        else:
            cursor.execute(
                'UPDATE users SET encrypted_master_key = ? WHERE login = ?',
                (encrypted_master_key, login),
            )
        conn.commit()
        conn.close()
        return True

    def get_encrypted_master_key(self, login):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT encrypted_master_key, master_key_binding_sig, '
            'master_key_binding_sik_pub FROM users WHERE login = ?',
            (login,),
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return {
            'encrypted_master_key': row[0],
            'binding_sig': row[1],
            'binding_sik_pub': row[2],
        }

    def get_user_by_session(self, session_id, user_id):
        hashed = hashlib.sha256((SESSION_HASH_SALT + session_id).encode('utf-8')).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.* FROM users u
            JOIN user_sessions s ON u.user_id = s.user_id
            WHERE s.session_id = ? AND u.user_id = ?
            AND s.is_active = 1 AND s.expires_at > datetime('now')
        ''', (hashed, user_id))
        user = cursor.fetchone()
        conn.close()
        if user:
            return dict(user)
        return None

    def is_session_active(self, session_id, user_id):
        hashed = hashlib.sha256((SESSION_HASH_SALT + session_id).encode('utf-8')).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 1 FROM user_sessions
            WHERE session_id = ? AND user_id = ?
            AND is_active = 1 AND expires_at > datetime('now')
        ''', (hashed, user_id))
        result = cursor.fetchone() is not None
        conn.close()
        return result

    def create_user_session(self, user_id, user_login, session_id):
        hashed = hashlib.sha256((SESSION_HASH_SALT + session_id).encode('utf-8')).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM user_sessions WHERE user_id = ? AND is_active = 1', (user_id,))
        if cursor.fetchone()[0] >= 10:
            conn.close()
            return False
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=TOKEN_LIFETIME)
        cursor.execute('''
            INSERT INTO user_sessions (session_id, user_id, user_login, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (hashed, user_id, user_login, expires_at))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_session(self, session_id, user_id):
        hashed = hashlib.sha256((SESSION_HASH_SALT + session_id).encode('utf-8')).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions SET is_active = 0 WHERE session_id = ? AND user_id = ?
        ''', (hashed, user_id))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_all_sessions_except(self, user_id, except_session_id):
        hashed_except = hashlib.sha256((SESSION_HASH_SALT + except_session_id).encode('utf-8')).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions SET is_active = 0
            WHERE user_id = ? AND session_id != ? AND expires_at > datetime('now')
        ''', (user_id, hashed_except))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_all_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE user_id = ?', (user_id,))
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def update_session_last_used(self, session_id):
        hashed = hashlib.sha256((SESSION_HASH_SALT + session_id).encode('utf-8')).hexdigest()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions SET last_used_at = datetime('now')
            WHERE session_id = ?
        ''', (hashed,))
        conn.commit()
        conn.close()
        return True

    def update_connection_ping(self, session_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE active_connections SET last_ping = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
        conn.close()

    def get_user_sessions(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id, created_at, last_used_at, expires_at, is_active
            FROM user_sessions WHERE user_id = ? ORDER BY last_used_at DESC
        ''', (user_id,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows] if rows else []

    def get_cleanup_interval(self, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else 0

    def set_cleanup_interval(self, user_id, interval):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO cleanup_settings (user_id, cleanup_interval) VALUES (?, ?)
        ''', (user_id, interval))
        if interval == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def deactivate_session_by_hash(self, hashed_session_id, user_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE user_sessions SET is_active = 0 WHERE session_id = ? AND user_id = ?',
            (hashed_session_id, user_id)
        )
        cursor.execute('SELECT cleanup_interval FROM cleanup_settings WHERE user_id = ?', (user_id,))
        cleanup = cursor.fetchone()
        if cleanup and cleanup[0] == 0:
            cursor.execute('DELETE FROM user_sessions WHERE user_id = ? AND is_active = 0', (user_id,))
        conn.commit()
        conn.close()
        return True

    def audit_log_event(self, event_type, user_id=None, extra=None):
        if extra is not None and not isinstance(extra, str):
            extra = json.dumps(extra, separators=(',', ':'))
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO audit_log (event_type, user_id, extra) '
            'VALUES (?, ?, ?)',
            (event_type, user_id, extra),
        )
        conn.commit()
        conn.close()

    def user_blob_get(self, user_id, kind):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT ciphertext, nonce, version, updated_at '
            'FROM user_encrypted_blobs WHERE user_id = ? AND kind = ?',
            (user_id, kind),
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return {'ciphertext': row[0], 'nonce': row[1],
                'version': row[2], 'updated_at': row[3]}

    def user_blob_put(self, user_id, kind, ciphertext, nonce, expected_version):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT version FROM user_encrypted_blobs '
            'WHERE user_id = ? AND kind = ?',
            (user_id, kind),
        )
        row = cursor.fetchone()
        cur_version = row[0] if row else 0
        if cur_version != expected_version:
            conn.close()
            return False, cur_version
        new_version = cur_version + 1
        cursor.execute('''
            INSERT INTO user_encrypted_blobs
                (user_id, kind, ciphertext, nonce, version, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(user_id, kind) DO UPDATE SET
                ciphertext = excluded.ciphertext,
                nonce = excluded.nonce,
                version = excluded.version,
                updated_at = excluded.updated_at
        ''', (user_id, kind, ciphertext, nonce, new_version))
        conn.commit()
        conn.close()
        return True, new_version

    def mark_nonce_used(self, nonce, user_id):
        expires_at = datetime.datetime.now() + datetime.timedelta(hours=72)
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO used_nonces (nonce, user_id, expires_at) VALUES (?, ?, ?)",
                (nonce, user_id, expires_at)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False


db = Database()


def create_session_token(session_id, user_id):
    data = f"{session_id}:{user_id}"
    sig = hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()
    token = f"{session_id}:{sig}"
    return base64.b64encode(token.encode()).decode()


def verify_session_token(token, user_id):
    decoded = base64.b64decode(token.encode()).decode()
    session_id, sig = decoded.split(':', 1)
    expected = f"{session_id}:{user_id}"
    expected_sig = hmac.new(SECRET_KEY, expected.encode(), hashlib.sha256).hexdigest()
    if sig != expected_sig:
        return None
    return session_id


event_queues = {}
event_queues_lock = threading.Lock()


def _device_key(user_id, device_id):
    return (int(user_id), str(device_id))


def add_event_to_device(user_id, device_id, event_type, data):
    key = _device_key(user_id, device_id)
    with event_queues_lock:
        if key not in event_queues:
            event_queues[key] = queue.Queue()
        event_queues[key].put((event_type, data))


def add_event_to_user_devices(user_id, event_type, data):
    devices = db.list_devices_for_user(user_id)
    for d in devices:
        add_event_to_device(user_id, d['device_id'], event_type, data)


def get_event_queue_for_device(user_id, device_id):
    key = _device_key(user_id, device_id)
    with event_queues_lock:
        return event_queues.get(key)


def remove_event_queue_for_device(user_id, device_id):
    key = _device_key(user_id, device_id)
    with event_queues_lock:
        event_queues.pop(key, None)


def remove_event_queues_for_user(user_id):
    with event_queues_lock:
        stale = [k for k in event_queues.keys() if k[0] == int(user_id)]
        for k in stale:
            del event_queues[k]


def login_required(f):
    def decorated(*args, **kwargs):
        session_token = request.headers.get('X-Session-Token')
        user_token = request.headers.get('X-User-Token')
        user_id_str = request.headers.get('X-User-Id')
        if not user_id_str:
            return jsonify({'success': False, 'error': 'Missing credentials'}), 401
        try:
            user_id = int(user_id_str)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid user ID'}), 401

        session_id = None
        if session_token:
            session_id = verify_session_token(session_token, user_id)
        if not session_id and user_token:
            session_id = user_token

        if not session_id:
            return jsonify({'success': False, 'error': 'Missing credentials'}), 401

        user = db.get_user_by_session(session_id, user_id)
        if not user:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        db.update_session_last_used(session_id)
        db.update_connection_ping(session_id)
        data = request.get_json(silent=True) or {}
        return f(user, data, *args, **kwargs)

    decorated.__name__ = f.__name__
    return decorated


@app.route('/api/opaque/register/start', methods=['POST'])
@rate_limit
def opaque_register_start():
    data = request.get_json()
    login = data.get('login')
    username = data.get('username')
    if not login or not username:
        return jsonify({'success': False, 'error': 'Не указан логин или имя'})
    if db.get_user_by_login(login):
        return jsonify({'success': False, 'error': 'Логин уже занят'})
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE username = ?', (username,))
    exists = cur.fetchone()
    conn.close()
    if exists:
        return jsonify({'success': False, 'error': 'Имя пользователя уже занято'})
    return jsonify({'success': True})


@app.route('/api/opaque/register/finish', methods=['POST'])
@rate_limit
def opaque_register_finish():
    data = request.get_json()
    login = data.get('login')
    username = data.get('username')
    registration_request = base64.b64decode(data.get('registration_request'))
    if not login or not username or not registration_request:
        return jsonify({'success': False, 'error': 'Все поля обязательны'})
    if db.get_user_by_login(login):
        return jsonify({'success': False, 'error': 'Логин уже занят'})
    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_reg_start = opaque_ke_py.server_registration_start(
        server_setup,
        registration_request,
        login.encode('utf-8')
    )
    server_response = server_reg_start.get_message()
    return jsonify({
        'success': True,
        'server_response': base64.b64encode(server_response).decode('utf-8')
    })


@app.route('/api/opaque/register/upload', methods=['POST'])
@rate_limit
def opaque_register_upload():
    data = request.get_json()
    login = data.get('login')
    username = data.get('username')
    registration_upload = base64.b64decode(data.get('registration_upload'))
    encrypted_master_key = data.get('encrypted_master_key')
    binding_sig = data.get('master_key_binding_sig')
    binding_sik_pub = data.get('master_key_binding_sik_pub')
    if (not login or not username or not registration_upload
            or not encrypted_master_key
            or not binding_sig or not binding_sik_pub):
        return jsonify({'success': False, 'error': 'Все поля обязательны'})
    if db.get_user_by_login(login):
        return jsonify({'success': False, 'error': 'Логин уже занят'})
    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_reg_finish = opaque_ke_py.server_registration_finish(registration_upload)
    password_file = server_reg_finish.get_password_file()
    user_id = int(datetime.datetime.now().timestamp() * 1000000) % 1000000000
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO users (login, username, user_id, opaque_password_file,
                           encrypted_master_key,
                           master_key_binding_sig,
                           master_key_binding_sik_pub)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (login, username, user_id, password_file, encrypted_master_key,
          binding_sig, binding_sik_pub))
    conn.commit()
    db.set_cleanup_interval(user_id, 0)
    conn.close()

    session_id = str(uuid.uuid4())
    if not db.create_user_session(user_id, login, session_id):
        return jsonify({'success': False, 'error': 'Не удалось создать сессию'})
    session_token = create_session_token(session_id, user_id)

    return jsonify({
        'success': True,
        'user_id': user_id,
        'session_token': session_token,
        'user_token': session_id,
        'username': username,
        'encrypted_master_key': encrypted_master_key
    })


@app.route('/api/opaque/login/start', methods=['POST'])
@rate_limit
def opaque_login_start():
    data = request.get_json()
    login = data.get('login')
    credential_request = base64.b64decode(data.get('credential_request'))
    device_id = request.headers.get('X-Device-ID')
    if not login or not credential_request:
        return jsonify({'success': False, 'error': 'Не указан логин или данные'})
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400

    blocked, seconds = db.is_login_blocked(login, device_id)
    if blocked:
        return jsonify({'success': False, 'error': f'Слишком много попыток. Попробуйте через {seconds} секунд.'}), 429

    user = db.get_user_by_login(login)
    if not user:
        db.increment_login_attempt(login, device_id)
        return jsonify({'success': False, 'error': 'Пользователь не найден'}), 401

    password_file = db.get_opaque_password_file(login)
    if not password_file:
        db.increment_login_attempt(login, device_id)
        return jsonify({'success': False, 'error': 'Пользователь не зарегистрирован'}), 401

    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_login_start = opaque_ke_py.server_login_start(
        server_setup,
        password_file,
        credential_request,
        login.encode('utf-8')
    )

    credential_response = server_login_start.get_message()
    server_state = server_login_start.get_state()
    state_id = db.save_login_state(login, server_state)

    return jsonify({
        'success': True,
        'state_id': state_id,
        'credential_response': base64.b64encode(credential_response).decode('utf-8')
    })


@app.route('/api/opaque/login/finish', methods=['POST'])
@rate_limit
def opaque_login_finish():
    data = request.get_json()
    state_id = data.get('state_id')
    credential_finalization = base64.b64decode(data.get('credential_finalization'))
    device_id = request.headers.get('X-Device-ID')
    if not state_id or not credential_finalization:
        return jsonify({'success': False, 'error': 'Не указаны данные'})
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400

    state = db.get_login_state(state_id)
    if not state:
        return jsonify({'success': False, 'error': 'Сессия не найдена'})
    expires_at = datetime.datetime.fromisoformat(state['expires_at'])
    if expires_at < datetime.datetime.now():
        db.delete_login_state(state_id)
        return jsonify({'success': False, 'error': 'Сессия истекла'})

    login = state['login']
    server_state = state['server_state']

    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_login_finish = opaque_ke_py.server_login_finish(server_state, credential_finalization)
    server_session_key = server_login_finish.get_session_key()

    db.delete_login_state(state_id)

    user = db.get_user_by_login(login)
    if not user:
        return jsonify({'success': False, 'error': 'Пользователь не найден'})

    db.reset_login_attempt(login, device_id)

    session_id = str(uuid.uuid4())
    session_token = create_session_token(session_id, user['user_id'])
    db.create_user_session(user['user_id'], user['login'], session_id)

    blob = db.get_encrypted_master_key(user['login']) or {}

    return jsonify({
        'success': True,
        'session_token': session_token,
        'user_token': session_id,
        'user_id': user['user_id'],
        'username': user['username'],
        'encrypted_master_key': blob.get('encrypted_master_key'),
        'master_key_binding_sig': blob.get('binding_sig'),
        'master_key_binding_sik_pub': blob.get('binding_sik_pub'),
        'e2ee_salt': user.get('e2ee_salt')
    })


@app.route('/api/opaque/change_password/get_server_response', methods=['POST'])
@rate_limit
@login_required
def opaque_change_password_get_server_response(user, data):
    registration_request = base64.b64decode(data.get('registration_request'))
    if not registration_request:
        return jsonify({'success': False, 'error': 'Не указан registration_request'})
    server_setup = opaque_ke_py.ServerSetupData.from_bytes(SERVER_SETUP_BYTES)
    server_reg_start = opaque_ke_py.server_registration_start(
        server_setup,
        registration_request,
        user['login'].encode('utf-8')
    )
    server_response = server_reg_start.get_message()
    return jsonify({
        'success': True,
        'server_response': base64.b64encode(server_response).decode('utf-8')
    })


@app.route('/api/opaque/change_password/upload', methods=['POST'])
@rate_limit
@login_required
def opaque_change_password_upload(user, data):
    registration_upload = base64.b64decode(data.get('registration_upload'))
    encrypted_master_key = data.get('encrypted_master_key')
    if not registration_upload:
        return jsonify({'success': False, 'error': 'Не указан registration_upload'})
    server_reg_finish = opaque_ke_py.server_registration_finish(registration_upload)
    new_password_file = server_reg_finish.get_password_file()
    db.save_opaque_password_file(user['login'], new_password_file)
    if encrypted_master_key:
        binding_sig = data.get('master_key_binding_sig')
        binding_sik_pub = data.get('master_key_binding_sik_pub')
        if not binding_sig or not binding_sik_pub:
            return jsonify({
                'success': False,
                'error': 'Не указана подпись master_key_binding'
            })
        db.save_encrypted_master_key(
            user['login'], encrypted_master_key,
            binding_sig=binding_sig,
            binding_sik_pub=binding_sik_pub,
        )
    current_session = None
    session_token = request.headers.get('X-Session-Token')
    if session_token:
        current_session = verify_session_token(session_token, user['user_id'])
    if current_session:
        db.deactivate_all_sessions_except(user['user_id'], current_session)
    else:
        user_token = request.headers.get('X-User-Token')
        if user_token:
            db.deactivate_all_sessions_except(user['user_id'], user_token)
    return jsonify({'success': True})


@app.route('/api/auth', methods=['POST'])
@rate_limit
@login_required
def auth(user, data):
    return jsonify({'success': True, 'message': 'Аутентификация успешна'})


@app.route('/api/logout_current', methods=['POST'])
@rate_limit
@login_required
def logout_current(user, data):
    session_token = request.headers.get('X-Session-Token')
    session_id = None
    if session_token:
        session_id = verify_session_token(session_token, user['user_id'])
    if session_id:
        db.deactivate_session(session_id, user['user_id'])
    else:
        user_token = request.headers.get('X-User-Token')
        if user_token:
            db.deactivate_session(user_token, user['user_id'])
    device_id = request.headers.get('X-Device-ID')
    if device_id:
        remove_event_queue_for_device(user['user_id'], device_id)
    return jsonify({'success': True})


@app.route('/api/info', methods=['GET', 'POST'])
@rate_limit
@login_required
def info(user, data):
    if request.method == 'GET':
        include_avatar = request.args.get('include_avatar', 'false').lower() == 'true'
    else:
        include_avatar = data.get('include_avatar', False)
    avatar_version = db.get_user_avatar_version(user['user_id'])
    response = {
        'success': True,
        'user_id': user['user_id'],
        'username': user['username'],
        'avatar_version': avatar_version
    }
    if include_avatar:
        avatar_data = db.get_avatar_data(user['user_id'])
        if avatar_data:
            response['avatar'] = base64.b64encode(avatar_data).decode('utf-8')
    return jsonify(response)


@app.route('/api/get_sessions', methods=['POST'])
@rate_limit
@login_required
def get_sessions(user, data):
    sessions = db.get_user_sessions(user['user_id'])
    raw_session = None
    if request.headers.get('X-Session-Token'):
        raw_session = verify_session_token(request.headers.get('X-Session-Token'), user['user_id'])
    if not raw_session:
        raw_session = request.headers.get('X-User-Token')
    current_hashed = (
        hashlib.sha256((SESSION_HASH_SALT + raw_session).encode('utf-8')).hexdigest()
        if raw_session else None
    )
    formatted = []
    for s in sessions:
        expires_at = datetime.datetime.fromisoformat(s['expires_at'])
        expires_in = max(0, (expires_at - datetime.datetime.now()).total_seconds())
        formatted.append({
            'session_id': s['session_id'],
            'created_at': s['created_at'],
            'last_used_at': s['last_used_at'],
            'expires_at': s['expires_at'],
            'expires_in': int(expires_in),
            'is_active': bool(s['is_active']),
            'is_current': s['session_id'] == current_hashed
        })
    return jsonify({'success': True, 'sessions': formatted})


@app.route('/api/logout_session', methods=['POST'])
@rate_limit
@login_required
def logout_session(user, data):
    target = data.get('target_session_id')
    if not target:
        return jsonify({'success': False, 'error': 'Не указана сессия'})
    db.deactivate_session_by_hash(target, user['user_id'])
    return jsonify({'success': True})


@app.route('/api/logout_all_sessions', methods=['POST'])
@rate_limit
@login_required
def logout_all_sessions(user, data):
    current = request.headers.get('X-User-Token') or verify_session_token(request.headers.get('X-Session-Token'),
                                                                          user['user_id']) if request.headers.get(
        'X-Session-Token') else None
    if current:
        db.deactivate_all_sessions_except(user['user_id'], current)
    else:
        db.deactivate_all_sessions(user['user_id'])
    return jsonify({'success': True})


@app.route('/api/get_cleanup_interval', methods=['POST'])
@rate_limit
@login_required
def get_cleanup_interval(user, data):
    interval = db.get_cleanup_interval(user['user_id'])
    return jsonify({'success': True, 'cleanup_interval': interval})


@app.route('/api/set_cleanup_interval', methods=['POST'])
@rate_limit
@login_required
def set_cleanup_interval(user, data):
    interval = data.get('interval')
    if interval is None or interval < 0:
        return jsonify({'success': False, 'error': 'Интервал не может быть отрицательным'})
    db.set_cleanup_interval(user['user_id'], interval)
    return jsonify({'success': True})


@app.route('/api/search_users', methods=['POST'])
@rate_limit
@login_required
def search_users(user, data):
    query = data.get('search_query', '').strip()
    if not query:
        return jsonify({'success': True, 'users': []})
    users = db.search_users(query, user['login'])
    return jsonify({'success': True, 'users': users})


@app.route('/api/get_user_info', methods=['POST'])
@rate_limit
@login_required
def get_user_info(user, data):
    target = data.get('target_login')
    if not target:
        return jsonify({'success': False, 'error': 'Не указан логин'})
    target_user = db.get_user_by_login(target)
    if not target_user:
        return jsonify({'success': False, 'error': 'Пользователь не найден'})
    is_contact = db.is_contact(user['login'], target)
    return jsonify({
        'success': True,
        'user': {
            'login': target_user['login'],
            'username': target_user['username'],
            'user_id': target_user['user_id'],
            'avatar_version': target_user['avatar_version'],
            'is_contact': is_contact
        }
    })


@app.route('/api/opaque/login/failed', methods=['POST'])
@rate_limit
def opaque_login_failed():
    data = request.get_json()
    login = data.get('login')
    device_id = request.headers.get('X-Device-ID')

    if not login or not device_id:
        return jsonify({'success': False, 'error': 'Не указан логин или device ID'}), 400

    db.increment_login_attempt(login, device_id)
    blocked, seconds = db.is_login_blocked(login, device_id)
    db.audit_log_event('login_failed', extra={'login': login,
                                              'blocked': blocked})
    if blocked:
        return jsonify({
            'success': False,
            'error': f'Слишком много попыток. Попробуйте через {seconds} секунд.',
            'blocked': True,
            'seconds': seconds
        }), 429

    return jsonify({'success': True})


MAX_VIDEO_BYTES = 1024 * 1024 * 1000
MAX_FILE_BYTES = 100 * 1024 * 1024


def _file_info_dict(file):
    if not file:
        return None
    return {
        'id': file['id'],
        'name': file['file_name'],
        'type': file['file_type'],
        'size': file['file_size'],
        'is_image_only': bool(file['is_image_only']),
        'nonce_file': file['nonce_file'],
        'nonce_thumbnail': file['nonce_thumbnail'],
    }


@app.route('/api/upload_file', methods=['POST'])
@rate_limit
@login_required
def upload_file(user, data):
    file_data = data.get('file_data')
    file_name = data.get('file_name')
    file_type = data.get('file_type')
    is_image_only = data.get('is_image_only', False)
    nonce_file = data.get('nonce_file')
    thumbnail = data.get('thumbnail')
    nonce_thumbnail = data.get('nonce_thumbnail')

    if not file_data or not file_name or not file_type or not nonce_file:
        return jsonify({'success': False, 'error': 'Missing file data'})

    file_bytes = base64.b64decode(file_data)
    if len(file_bytes) > MAX_FILE_BYTES:
        return jsonify({'success': False, 'error': 'File too large'}), 413
    if isinstance(file_type, str) and file_type.lower().startswith('video/') \
            and len(file_bytes) > MAX_VIDEO_BYTES:
        return jsonify({'success': False, 'error': 'Video must be 1 MB or smaller'}), 413
    thumb_bytes = base64.b64decode(thumbnail) if thumbnail else None
    success, result = db.save_file(
        file_bytes, file_name, file_type, user['login'],
        nonce_file=nonce_file,
        is_image_only=is_image_only,
        thumbnail_data=thumb_bytes,
        nonce_thumbnail=nonce_thumbnail
    )
    if success:
        return jsonify({'success': True, 'file_id': result})
    else:
        return jsonify({'success': False, 'error': result})


@app.route('/api/get_file', methods=['POST'])
@rate_limit
@login_required
def get_file(user, data):
    file_id = data.get('file_id')
    include_data = data.get('include_data', True)
    include_thumbnail = data.get('include_thumbnail', False)
    if not file_id:
        return jsonify({'success': False, 'error': 'Missing file_id'})

    file = db.get_file(file_id)
    if not file:
        return jsonify({'success': False, 'error': 'File not found'})

    response = {
        'success': True,
        'file_id': file['id'],
        'file_name': file['file_name'],
        'file_type': file['file_type'],
        'file_size': file['file_size'],
        'is_image_only': bool(file['is_image_only']),
        'nonce_file': file['nonce_file'],
        'nonce_thumbnail': file['nonce_thumbnail']
    }

    if include_data and file['file_data']:
        response['file_data'] = base64.b64encode(file['file_data']).decode('utf-8')
    if include_thumbnail and file.get('thumbnail_data'):
        response['thumbnail'] = base64.b64encode(file['thumbnail_data']).decode('utf-8')

    return jsonify(response)


@app.route('/api/send_message', methods=['POST'])
@rate_limit
@login_required
def send_message(user, data):
    sender_device_id = request.headers.get('X-Device-ID')
    if not sender_device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    if not db.device_exists(user['user_id'], sender_device_id):
        return jsonify({'success': False, 'error': 'Sender device not registered'}), 400

    receiver = data.get('receiver_login')
    envelopes = data.get('envelopes')
    file_id = data.get('file_id')
    client_timestamp = data.get('client_timestamp')
    nonce = data.get('nonce')
    archive_self = data.get('archive_self')
    message_group_id = data.get('message_group_id') or str(uuid.uuid4())

    if not receiver:
        return jsonify({'success': False, 'error': 'Не указан получатель'})
    if not isinstance(envelopes, list) or not envelopes:
        return jsonify({'success': False, 'error': 'Пустые envelopes'})

    receiver_user = db.get_user_by_login(receiver)
    if not receiver_user:
        return jsonify({'success': False, 'error': 'Получатель не найден'})

    if nonce and not db.mark_nonce_used(nonce, user['user_id']):
        return jsonify({'success': False, 'error': 'Дублирующееся сообщение отклонено'}), 409

    allowed_user_ids = {user['user_id'], receiver_user['user_id']}
    inserted = []
    seen = set()
    for env in envelopes:
        if not isinstance(env, dict):
            return jsonify({'success': False, 'error': 'envelope must be object'}), 400
        target_user_id = env.get('target_user_id')
        target_device_id = env.get('target_device_id')
        wire = env.get('wire')
        if target_user_id not in allowed_user_ids:
            return jsonify({'success': False,
                            'error': 'envelope target_user_id not allowed'}), 400
        if not target_device_id or wire is None:
            return jsonify({'success': False,
                            'error': 'envelope missing target_device_id or wire'}), 400
        if not db.device_exists(target_user_id, target_device_id):
            continue
        if (target_user_id, target_device_id) == (user['user_id'], sender_device_id):
            continue
        key_pair = (target_user_id, target_device_id)
        if key_pair in seen:
            continue
        seen.add(key_pair)
        target_login = (user['login'] if target_user_id == user['user_id']
                        else receiver_user['login'])
        wire_str = wire if isinstance(wire, str) else json.dumps(wire, separators=(',', ':'))
        msg_row = db.insert_envelope(
            message_group_id=message_group_id,
            sender_user_id=user['user_id'],
            sender_login=user['login'],
            sender_device_id=sender_device_id,
            receiver_user_id=target_user_id,
            receiver_login=target_login,
            target_device_id=target_device_id,
            wire=wire_str,
            file_id=file_id,
            client_timestamp=client_timestamp,
            nonce=nonce,
        )
        file_info = _file_info_dict(db.get_file(file_id)) if file_id else None
        msg_row['file_info'] = file_info
        inserted.append(msg_row)
        add_event_to_device(target_user_id, target_device_id, 'new_message', msg_row)

    if archive_self and isinstance(archive_self, dict):
        ct = archive_self.get('ciphertext')
        nn = archive_self.get('nonce')
        peer_handle = archive_self.get('peer_handle')
        if ct and nn and peer_handle:
            db.archive_insert(
                user_id=user['user_id'],
                peer_handle=peer_handle,
                ciphertext=ct,
                nonce=nn,
                message_group_id=message_group_id,
            )

    return jsonify({
        'success': True,
        'message_group_id': message_group_id,
        'inserted_count': len(inserted),
        'envelopes': inserted,
    })


@app.route('/api/get_messages', methods=['POST'])
@rate_limit
@login_required
def get_messages(user, data):
    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    other = data.get('other_user_login')
    if not other:
        return jsonify({'success': False, 'error': 'Не указан пользователь'})
    other_user = db.get_user_by_login(other)
    if not other_user:
        return jsonify({'success': False, 'error': 'Пользователь не найден'})
    messages = db.get_messages_for_device(
        viewer_user_id=user['user_id'], viewer_device_id=device_id,
        peer_user_id=other_user['user_id'], since_id=0,
    )
    for msg in messages:
        if msg.get('file_id'):
            msg['file_info'] = _file_info_dict(db.get_file(msg['file_id']))
    return jsonify({'success': True, 'messages': messages})


@app.route('/api/get_messages_since', methods=['POST'])
@rate_limit
@login_required
def get_messages_since(user, data):
    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    contact_login = data.get('contact_login')
    since_id = data.get('since_id', 0)
    if not contact_login:
        return jsonify({'success': False, 'error': 'Не указан контакт'})
    contact = db.get_user_by_login(contact_login)
    if not contact:
        return jsonify({'success': False, 'error': 'Контакт не найден'})
    messages = db.get_messages_for_device(
        viewer_user_id=user['user_id'], viewer_device_id=device_id,
        peer_user_id=contact['user_id'], since_id=since_id,
    )
    for msg in messages:
        if msg.get('file_id'):
            msg['file_info'] = _file_info_dict(db.get_file(msg['file_id']))
    return jsonify({'success': True, 'messages': messages})


@app.route('/api/update_profile', methods=['POST'])
@rate_limit
@login_required
def update_profile(user, data):
    username = data.get('username')
    avatar = data.get('avatar')
    if username:
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ? AND login != ?', (username, user['login']))
        if cur.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Имя пользователя уже занято'})
        conn.close()
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('UPDATE users SET username = ? WHERE login = ?', (username, user['login']))
        conn.commit()
        conn.close()
    if avatar:
        avatar_bytes = base64.b64decode(avatar)
        success, res = db.update_user_avatar(user['user_id'], avatar_bytes)
        if not success:
            return jsonify({'success': False, 'error': res})
        avatar_version = res
        conn = db.get_connection()
        cur = conn.cursor()
        cur.execute('SELECT contact_owner FROM contacts WHERE contact_login = ?', (user['login'],))
        owners = cur.fetchall()
        conn.close()
        for owner in owners:
            owner_user = db.get_user_by_login(owner[0])
            if owner_user:
                add_event_to_user_devices(owner_user['user_id'], 'avatar_updated', {
                    'user_id': user['user_id'],
                    'new_version': avatar_version
                })
        avatar_data = db.get_avatar_data(user['user_id'])
        if avatar_data:
            return jsonify({
                'success': True,
                'avatar_version': avatar_version,
                'avatar': base64.b64encode(avatar_data).decode('utf-8')
            })
        else:
            return jsonify({'success': True, 'avatar_version': avatar_version})
    return jsonify({'success': True})


@app.route('/api/add_contact', methods=['POST'])
@rate_limit
@login_required
def add_contact(user, data):
    contact = data.get('contact_login')
    if not contact:
        return jsonify({'success': False, 'error': 'Не указан логин контакта'})
    if contact == user['login']:
        return jsonify({'success': False, 'error': 'Нельзя добавить самого себя'})
    target = db.get_user_by_login(contact)
    if not target:
        return jsonify({'success': False, 'error': 'Пользователь не найден'})
    if db.add_contact(user['login'], contact):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Контакт уже добавлен'})


@app.route('/api/remove_contact', methods=['POST'])
@rate_limit
@login_required
def remove_contact(user, data):
    contact = data.get('contact_login')
    if not contact:
        return jsonify({'success': False, 'error': 'Не указан логин'})
    db.remove_contact(user['login'], contact)
    return jsonify({'success': True})


@app.route('/api/get_contacts', methods=['POST'])
@rate_limit
@login_required
def get_contacts(user, data):
    contacts = db.get_contacts(user['login'])
    return jsonify({'success': True, 'contacts': contacts})


@app.route('/api/get_avatar_versions', methods=['POST'])
@rate_limit
@login_required
def get_avatar_versions(user, data):
    user_ids = data.get('user_ids', [])
    versions = db.get_avatar_versions(user_ids)
    return jsonify({'success': True, 'versions': versions})


@app.route('/api/get_avatar', methods=['POST'])
@rate_limit
@login_required
def get_avatar(user, data):
    target_id = data.get('target_user_id')
    if not target_id:
        return jsonify({'success': False, 'error': 'Не указан ID'})
    avatar_data = db.get_avatar_data(target_id)
    if avatar_data:
        return jsonify({
            'success': True,
            'avatar': base64.b64encode(avatar_data).decode('utf-8')
        })
    else:
        return jsonify({'success': False, 'error': 'Аватар не найден'})


@app.route('/api/save_contact_settings', methods=['POST'])
@rate_limit
@login_required
def save_contact_settings(user, data):
    contact = data.get('contact_login')
    display_name = data.get('display_name')
    if not contact:
        return jsonify({'success': False, 'error': 'Не указан контакт'})
    db.save_contact_settings(user['login'], contact, display_name)
    return jsonify({'success': True})


@app.route('/api/get_contact_settings', methods=['POST'])
@rate_limit
@login_required
def get_contact_settings(user, data):
    settings = db.get_contact_settings(user['login'])
    return jsonify({'success': True, 'settings': settings})


@app.route('/api/publish_public_key', methods=['POST'])
@rate_limit
@login_required
def publish_public_key(user, data):
    public_key = data.get('public_key')
    signature = data.get('signature')
    if not public_key or not signature:
        return jsonify({'success': False, 'error': 'Missing public key or signature'})
    db.save_user_public_key(user['user_id'], public_key, signature)
    return jsonify({'success': True})


@app.route('/api/get_public_key', methods=['POST'])
@rate_limit
@login_required
def get_public_key(user, data):
    contact_login = data.get('contact_login')
    if not contact_login:
        return jsonify({'success': False, 'error': 'Missing contact_login'})
    contact = db.get_user_by_login(contact_login)
    if not contact:
        return jsonify({'success': False, 'error': 'Contact not found'})
    key_data = db.get_user_public_key(contact['user_id'])
    if key_data:
        return jsonify({'success': True, 'public_key': key_data['public_key'], 'signature': key_data['signature']})
    else:
        return jsonify({'success': False, 'error': 'Public key not found'})


@app.route('/api/register_device', methods=['POST'])
@rate_limit
@login_required
def register_device(user, data):
    device_id = request.headers.get('X-Device-ID')
    device_label = (data.get('device_label') or '').strip()[:100]
    dev_ik = data.get('dev_ik')
    dev_ik_signature = data.get('dev_ik_signature')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    db.register_device(user['user_id'], device_id, device_label or None,
                       dev_ik=dev_ik, dev_ik_signature=dev_ik_signature)
    return jsonify({'success': True, 'device_id': device_id})


@app.route('/api/list_my_devices', methods=['POST'])
@rate_limit
@login_required
def list_my_devices(user, data):
    devices = db.list_devices_for_user(user['user_id'])
    return jsonify({'success': True, 'devices': devices})


@app.route('/api/unlink_device', methods=['POST'])
@rate_limit
@login_required
def unlink_device(user, data):
    target_device = data.get('device_id')
    if not target_device:
        return jsonify({'success': False, 'error': 'Не указано устройство'})
    db.unlink_device(user['user_id'], target_device)
    remove_event_queue_for_device(user['user_id'], target_device)
    return jsonify({'success': True})


@app.route('/api/upload_signed_prekey', methods=['POST'])
@rate_limit
@login_required
def upload_signed_prekey(user, data):
    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    if not db.device_exists(user['user_id'], device_id):
        return jsonify({'success': False, 'error': 'Device not registered'}), 400
    spk_id = data.get('spk_id')
    public_key = data.get('public_key')
    signature = data.get('signature')
    if spk_id is None or not public_key or not signature:
        return jsonify({'success': False, 'error': 'Missing fields'})
    try:
        spk_id = int(spk_id)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid spk_id'})
    db.save_signed_prekey(user['user_id'], device_id, spk_id, public_key, signature)
    return jsonify({'success': True})


@app.route('/api/upload_one_time_prekeys', methods=['POST'])
@rate_limit
@login_required
def upload_one_time_prekeys(user, data):
    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    if not db.device_exists(user['user_id'], device_id):
        return jsonify({'success': False, 'error': 'Device not registered'}), 400
    keys = data.get('prekeys')
    if not isinstance(keys, list) or not keys:
        return jsonify({'success': False, 'error': 'prekeys must be a non-empty list'})
    if len(keys) > 200:
        return jsonify({'success': False, 'error': 'Too many prekeys in single batch'})
    pairs = []
    for entry in keys:
        if not isinstance(entry, dict):
            return jsonify({'success': False, 'error': 'Invalid prekey entry'})
        opk_id = entry.get('opk_id')
        pub = entry.get('public_key')
        if opk_id is None or not pub:
            return jsonify({'success': False, 'error': 'Missing opk_id or public_key'})
        try:
            opk_id_int = int(opk_id)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid opk_id'})
        pairs.append((opk_id_int, pub))
    inserted = db.save_one_time_prekeys(user['user_id'], device_id, pairs)
    return jsonify({'success': True, 'inserted': inserted,
                    'total': db.count_one_time_prekeys(user['user_id'], device_id)})


@app.route('/api/get_one_time_prekey_count', methods=['POST'])
@rate_limit
@login_required
def get_one_time_prekey_count(user, data):
    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    return jsonify({'success': True,
                    'count': db.count_one_time_prekeys(user['user_id'], device_id)})


@app.route('/api/get_prekey_bundle', methods=['POST'])
@rate_limit
@login_required
def get_prekey_bundle(user, data):
    contact_login = data.get('contact_login')
    if not contact_login:
        return jsonify({'success': False, 'error': 'Missing contact_login'})
    contact = db.get_user_by_login(contact_login)
    if not contact:
        return jsonify({'success': False, 'error': 'Contact not found'})

    identity = db.get_user_public_key(contact['user_id'])
    if not identity:
        return jsonify({'success': False, 'error': 'Identity key not published'})

    try:
        identity_bundle = json.loads(identity['public_key'])
        ik_b64 = identity_bundle['x25519']
        sik_b64 = identity_bundle['ed25519']
    except (KeyError, ValueError):
        return jsonify({'success': False, 'error': 'Identity key bundle malformed'})

    devices = db.list_devices_for_user(contact['user_id'])
    own_device_id = request.headers.get('X-Device-ID')

    device_bundles = []
    for d in devices:
        if contact['user_id'] == user['user_id'] and d['device_id'] == own_device_id:
            continue
        spk = db.get_signed_prekey(contact['user_id'], d['device_id'])
        if not spk:
            continue
        opk_row = db.take_one_time_prekey(contact['user_id'], d['device_id'])
        device_bundles.append({
            'device_id': d['device_id'],
            'device_label': d.get('device_label'),
            'spk_id': spk['spk_id'],
            'spk': spk['public_key'],
            'spk_signature': spk['signature'],
            'opk_id': opk_row['opk_id'] if opk_row else None,
            'opk': opk_row['public_key'] if opk_row else None,
            'dev_ik': d.get('device_ik'),
            'dev_ik_signature': d.get('device_ik_signature'),
        })

    return jsonify({
        'success': True,
        'user_id': contact['user_id'],
        'login': contact['login'],
        'identity': {
            'ik': ik_b64,
            'sik': sik_b64,
            'identity_signature': identity['signature'],
        },
        'devices': device_bundles,
    })


@app.route('/api/archive_upload', methods=['POST'])
@rate_limit
@login_required
def archive_upload(user, data):
    entries = data.get('entries')
    if not isinstance(entries, list) or not entries:
        return jsonify({'success': False, 'error': 'entries must be non-empty list'})
    if len(entries) > 200:
        return jsonify({'success': False, 'error': 'Too many entries in single batch'})
    inserted_ids = []
    for entry in entries:
        if not isinstance(entry, dict):
            return jsonify({'success': False, 'error': 'invalid entry'})
        peer_handle = entry.get('peer_handle')
        ciphertext = entry.get('ciphertext')
        nonce = entry.get('nonce')
        message_group_id = entry.get('message_group_id')
        if not peer_handle or not ciphertext or not nonce:
            return jsonify({'success': False,
                            'error': 'missing peer_handle/ciphertext/nonce'})
        if not isinstance(peer_handle, str) or len(peer_handle) > 128:
            return jsonify({'success': False, 'error': 'invalid peer_handle'})
        archive_id = db.archive_insert(
            user_id=user['user_id'],
            peer_handle=peer_handle,
            ciphertext=ciphertext,
            nonce=nonce,
            message_group_id=message_group_id,
        )
        inserted_ids.append(archive_id)
    return jsonify({'success': True, 'inserted': inserted_ids})


@app.route('/api/archive_fetch', methods=['POST'])
@rate_limit
@login_required
def archive_fetch(user, data):
    peer_handle = data.get('peer_handle')
    since_archive_id = int(data.get('since_archive_id') or 0)
    limit = int(data.get('limit') or 500)
    limit = max(1, min(limit, 1000))
    if peer_handle is not None and (not isinstance(peer_handle, str)
                                    or len(peer_handle) > 128):
        return jsonify({'success': False, 'error': 'invalid peer_handle'})
    entries = db.archive_fetch(user['user_id'], peer_handle,
                               since_archive_id, limit)
    return jsonify({'success': True, 'entries': entries})

SEALED_TOKEN_TTL = 600
SEALED_TOKEN_PREFIX = b'PCSealedToken/v1|'
SEALED_USED_TOKENS = set()
SEALED_USED_LOCK = threading.Lock()


def _make_sealed_token():
    nonce = secrets.token_bytes(16)
    expiry = int(time.time()) + SEALED_TOKEN_TTL
    body = nonce + expiry.to_bytes(8, 'big')
    sig = hmac.new(SECRET_KEY, SEALED_TOKEN_PREFIX + body,
                   hashlib.sha256).digest()
    raw = body + sig
    return base64.urlsafe_b64encode(raw).decode('ascii')


def _validate_sealed_token(token_str):
    try:
        raw = base64.urlsafe_b64decode(token_str.encode('ascii'))
    except Exception:
        return False, 'malformed token'
    if len(raw) != 16 + 8 + 32:
        return False, 'token wrong length'
    nonce = raw[:16]
    expiry = int.from_bytes(raw[16:24], 'big')
    sig = raw[24:]
    expected = hmac.new(SECRET_KEY, SEALED_TOKEN_PREFIX + raw[:24],
                        hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return False, 'token signature mismatch'
    if expiry < int(time.time()):
        return False, 'token expired'
    with SEALED_USED_LOCK:
        if nonce in SEALED_USED_TOKENS:
            return False, 'token already used'
        SEALED_USED_TOKENS.add(nonce)
        if len(SEALED_USED_TOKENS) > 50000:
            SEALED_USED_TOKENS.clear()
    return True, None


@app.route('/api/user_blob_get', methods=['POST'])
@rate_limit
@login_required
def user_blob_get(user, data):
    kind = data.get('kind')
    if not kind or not isinstance(kind, str):
        return jsonify({'success': False, 'error': 'kind required'}), 400
    if len(kind) > 64:
        return jsonify({'success': False, 'error': 'kind too long'}), 400
    blob = db.user_blob_get(user['user_id'], kind)
    return jsonify({'success': True, 'blob': blob})


@app.route('/api/user_blob_put', methods=['POST'])
@rate_limit
@login_required
def user_blob_put(user, data):
    kind = data.get('kind')
    ciphertext = data.get('ciphertext')
    nonce = data.get('nonce')
    expected_version = int(data.get('expected_version') or 0)
    if not kind or not ciphertext or not nonce:
        return jsonify({'success': False,
                        'error': 'kind/ciphertext/nonce required'}), 400
    if len(kind) > 64:
        return jsonify({'success': False, 'error': 'kind too long'}), 400
    if len(ciphertext) > 256 * 1024:
        return jsonify({'success': False, 'error': 'blob too large'}), 413
    ok, current_version = db.user_blob_put(
        user['user_id'], kind, ciphertext, nonce, expected_version,
    )
    return jsonify({
        'success': ok,
        'error': None if ok else 'version conflict',
        'current_version': current_version,
    })


PAIRING_ENTRY_ATTEMPT_LIMIT = 5
PAIRING_TTL_SECONDS = 600


@app.route('/api/device_pair_start', methods=['POST'])
@rate_limit
@login_required
def device_pair_start(user, data):
    code_hash = data.get('code_hash')
    epk_a_pub = data.get('epk_a_pub')
    if not code_hash or not epk_a_pub:
        return jsonify({'success': False,
                        'error': 'code_hash + epk_a_pub required'}), 400
    if not isinstance(code_hash, str) or len(code_hash) > 128:
        return jsonify({'success': False, 'error': 'invalid code_hash'}), 400
    if not isinstance(epk_a_pub, str) or len(epk_a_pub) > 64:
        return jsonify({'success': False, 'error': 'invalid epk_a_pub'}), 400
    pair_id = secrets.token_urlsafe(16)
    expires_at = (datetime.datetime.now()
                  + datetime.timedelta(seconds=PAIRING_TTL_SECONDS)).isoformat()
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO device_pairings
            (pair_id, code_hash, primary_user_id, epk_a_pub, expires_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (pair_id, code_hash, user['user_id'], epk_a_pub, expires_at))
    conn.commit()
    conn.close()
    db.audit_log_event('device_pair_start', user_id=user['user_id'])
    return jsonify({'success': True, 'pair_id': pair_id,
                    'ttl_seconds': PAIRING_TTL_SECONDS})


@app.route('/api/device_pair_enter', methods=['POST'])
@anonymous_rate_limit
def device_pair_enter():
    data = request.get_json(silent=True) or {}
    code_hash = data.get('code_hash')
    epk_b_pub = data.get('epk_b_pub')
    if not code_hash or not epk_b_pub:
        return jsonify({'success': False,
                        'error': 'code_hash + epk_b_pub required'}), 400
    if not isinstance(code_hash, str) or len(code_hash) > 128:
        return jsonify({'success': False, 'error': 'invalid code_hash'}), 400
    if not isinstance(epk_b_pub, str) or len(epk_b_pub) > 64:
        return jsonify({'success': False, 'error': 'invalid epk_b_pub'}), 400
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT pair_id, primary_user_id, epk_a_pub, attempts, expires_at
        FROM device_pairings
        WHERE code_hash = ? AND expires_at > datetime('now')
        ORDER BY created_at DESC LIMIT 1
    ''', (code_hash,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False,
                        'error': 'pairing not found or expired'}), 404
    if row['attempts'] >= PAIRING_ENTRY_ATTEMPT_LIMIT:
        conn.close()
        return jsonify({'success': False,
                        'error': 'too many attempts'}), 429
    cur.execute('''
        UPDATE device_pairings
        SET epk_b_pub = ?, attempts = attempts + 1
        WHERE pair_id = ?
    ''', (epk_b_pub, row['pair_id']))
    conn.commit()
    conn.close()
    db.audit_log_event('device_pair_enter', user_id=row['primary_user_id'])
    return jsonify({
        'success': True,
        'pair_id': row['pair_id'],
        'primary_user_id': row['primary_user_id'],
        'epk_a_pub': row['epk_a_pub'],
    })


@app.route('/api/device_pair_status', methods=['POST'])
@rate_limit
@login_required
def device_pair_status(user, data):
    pair_id = data.get('pair_id')
    if not pair_id:
        return jsonify({'success': False, 'error': 'pair_id required'}), 400
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT primary_user_id, epk_b_pub, sealed_bundle, expires_at
        FROM device_pairings WHERE pair_id = ?
    ''', (pair_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({'success': False, 'error': 'pairing not found'}), 404
    if row['primary_user_id'] != user['user_id']:
        return jsonify({'success': False, 'error': 'forbidden'}), 403
    return jsonify({
        'success': True,
        'epk_b_pub': row['epk_b_pub'],
        'has_sealed_bundle': bool(row['sealed_bundle']),
        'expires_at': row['expires_at'],
    })


@app.route('/api/device_pair_complete', methods=['POST'])
@rate_limit
@login_required
def device_pair_complete(user, data):
    pair_id = data.get('pair_id')
    sealed_bundle = data.get('sealed_bundle')
    if not pair_id or not sealed_bundle:
        return jsonify({'success': False,
                        'error': 'pair_id + sealed_bundle required'}), 400
    if not isinstance(sealed_bundle, dict):
        return jsonify({'success': False,
                        'error': 'sealed_bundle must be object'}), 400
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute(
        'SELECT primary_user_id FROM device_pairings WHERE pair_id = ?',
        (pair_id,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'pairing not found'}), 404
    if row['primary_user_id'] != user['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'forbidden'}), 403
    cur.execute(
        'UPDATE device_pairings SET sealed_bundle = ? WHERE pair_id = ?',
        (json.dumps(sealed_bundle, separators=(',', ':')), pair_id),
    )
    conn.commit()
    conn.close()
    db.audit_log_event('device_pair_complete', user_id=user['user_id'])
    return jsonify({'success': True})


@app.route('/api/device_pair_fetch', methods=['POST'])
@anonymous_rate_limit
def device_pair_fetch():
    data = request.get_json(silent=True) or {}
    code_hash = data.get('code_hash')
    if not code_hash:
        return jsonify({'success': False,
                        'error': 'code_hash required'}), 400
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute('''
        SELECT pair_id, primary_user_id, sealed_bundle, expires_at
        FROM device_pairings
        WHERE code_hash = ? AND expires_at > datetime('now')
        ORDER BY created_at DESC LIMIT 1
    ''', (code_hash,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False,
                        'error': 'pairing not found'}), 404
    if not row['sealed_bundle']:
        conn.close()
        return jsonify({'success': True, 'sealed_bundle': None,
                        'primary_user_id': row['primary_user_id']})
    cur.execute('DELETE FROM device_pairings WHERE pair_id = ?',
                (row['pair_id'],))
    conn.commit()
    conn.close()
    return jsonify({
        'success': True,
        'sealed_bundle': json.loads(row['sealed_bundle']),
        'primary_user_id': row['primary_user_id'],
    })


@app.route('/api/sealed_inbox_since', methods=['POST'])
@rate_limit
@login_required
def sealed_inbox_since(user, data):
    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    since_id = int(data.get('since_id') or 0)
    msgs = db.get_sealed_messages_for_device(
        viewer_user_id=user['user_id'],
        viewer_device_id=device_id,
        since_id=since_id,
    )
    return jsonify({'success': True, 'messages': msgs})


@app.route('/api/sealed_token', methods=['POST'])
@rate_limit
@login_required
def sealed_token(user, data):
    count = int(data.get('count') or 1)
    count = max(1, min(count, 64))
    tokens = [_make_sealed_token() for _ in range(count)]
    db.audit_log_event('sealed_token_issued', user_id=user['user_id'],
                       extra={'count': count})
    return jsonify({'success': True, 'tokens': tokens,
                    'ttl_seconds': SEALED_TOKEN_TTL})


@app.route('/api/sealed_send', methods=['POST'])
@anonymous_rate_limit
def sealed_send():
    data = request.get_json(silent=True) or {}
    token = data.get('sealed_token')
    if not token:
        return jsonify({'success': False, 'error': 'sealed_token required'}), 401
    ok, why = _validate_sealed_token(token)
    if not ok:
        return jsonify({'success': False, 'error': f'invalid token: {why}'}), 401

    receiver_login = data.get('receiver_login')
    envelopes = data.get('envelopes')
    file_id = data.get('file_id')
    client_timestamp = data.get('client_timestamp')
    nonce = data.get('nonce')
    message_group_id = data.get('message_group_id') or str(uuid.uuid4())

    if not receiver_login:
        return jsonify({'success': False, 'error': 'Не указан получатель'})
    if not isinstance(envelopes, list) or not envelopes:
        return jsonify({'success': False, 'error': 'Пустые envelopes'})

    receiver_user = db.get_user_by_login(receiver_login)
    if not receiver_user:
        return jsonify({'success': False, 'error': 'Получатель не найден'})

    if nonce and not db.mark_nonce_used(nonce, receiver_user['user_id']):
        return jsonify({'success': False, 'error': 'Дублирующийся envelope'}), 409

    inserted = []
    seen = set()
    for env in envelopes:
        if not isinstance(env, dict):
            return jsonify({'success': False,
                            'error': 'envelope must be object'}), 400
        target_user_id = env.get('target_user_id')
        target_device_id = env.get('target_device_id')
        sealed_blob = env.get('sealed')
        if target_user_id != receiver_user['user_id']:
            return jsonify({'success': False,
                            'error': 'sealed envelopes target the recipient only'}), 400
        if not target_device_id or sealed_blob is None:
            return jsonify({'success': False,
                            'error': 'envelope missing target_device_id or sealed'}), 400
        if not db.device_exists(target_user_id, target_device_id):
            continue
        key_pair = (target_user_id, target_device_id)
        if key_pair in seen:
            continue
        seen.add(key_pair)
        wire_str = json.dumps({'type': 'sealed', 'sealed': sealed_blob},
                              separators=(',', ':'))
        msg_row = db.insert_envelope(
            message_group_id=message_group_id,
            sender_user_id=0,
            sender_login='*sealed*',
            sender_device_id='*sealed*',
            receiver_user_id=target_user_id,
            receiver_login=receiver_user['login'],
            target_device_id=target_device_id,
            wire=wire_str,
            file_id=file_id,
            client_timestamp=client_timestamp,
            nonce=nonce,
        )
        file_info = _file_info_dict(db.get_file(file_id)) if file_id else None
        msg_row['file_info'] = file_info
        msg_row['_sealed'] = True
        inserted.append(msg_row)
        add_event_to_device(target_user_id, target_device_id,
                            'new_message', msg_row)

    return jsonify({
        'success': True,
        'message_group_id': message_group_id,
        'inserted_count': len(inserted),
    })


@app.route('/api/events')
@rate_limit
def events():
    session_token = request.headers.get('X-Session-Token')
    user_id = request.headers.get('X-User-Id')
    user_token = request.headers.get('X-User-Token')
    device_id = request.headers.get('X-Device-ID')
    if not device_id:
        return jsonify({'success': False, 'error': 'Device ID required'}), 400
    if not session_token and not user_token:
        return jsonify({'success': False, 'error': 'Missing credentials'}), 401
    try:
        uid_int = int(user_id) if user_id else None
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid user ID'}), 401
    if not uid_int:
        return jsonify({'success': False, 'error': 'Missing user ID'}), 401

    if session_token:
        session_id = verify_session_token(session_token, uid_int)
        if not session_id:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        user = db.get_user_by_session(session_id, uid_int)
    elif user_token:
        user = db.get_user_by_session(user_token, uid_int)
    else:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 401
    user_id = user['user_id']
    if not db.device_exists(user_id, device_id):
        return jsonify({'success': False, 'error': 'Device not registered'}), 400
    db.touch_device(user_id, device_id)
    key = _device_key(user_id, device_id)
    q = get_event_queue_for_device(user_id, device_id)
    if q is None:
        with event_queues_lock:
            if key not in event_queues:
                event_queues[key] = queue.Queue()
            q = event_queues[key]

    def generate():
        while True:
            try:
                event_type, event_data = q.get(timeout=30)
                yield f"event: {event_type}\ndata: {json.dumps(event_data, ensure_ascii=False)}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/', methods=['GET'])
def health():
    return 'Healthy aka running.'


if __name__ == '__main__':
    app.run(host=SERVER_HOST, port=SERVER_PORT, threaded=True)