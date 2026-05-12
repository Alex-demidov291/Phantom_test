import os
import secrets
# Client settings
SERVER_URL = 'http://localhost/'

# Server settings
RUNNING_PORT = 6666
SERVER_HOST = '0.0.0.0'

# Common settings
DEBUG = False

_SALT_FILE = "session_salt.bin"
SESSION_HASH_SALT = os.environ.get("SESSION_HASH_SALT")
if not SESSION_HASH_SALT:
    if os.path.exists(_SALT_FILE):
        with open(_SALT_FILE, "r") as _f:
            SESSION_HASH_SALT = _f.read().strip()
    else:
        SESSION_HASH_SALT = secrets.token_hex(32)
        with open(_SALT_FILE, "w") as _f:
            _f.write(SESSION_HASH_SALT)