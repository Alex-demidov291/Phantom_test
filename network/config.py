import os
SERVER_URL = os.environ.get('PHANTOM_SERVER_URL', 'http://localhost:6666/').rstrip('/') + '/'
