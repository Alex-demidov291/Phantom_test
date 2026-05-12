import time


class Contact:
    # -- контакт пользователя
    def __init__(self, login, username, user_id, avatar_version=0, display_name=None):
        self.login = login
        self.username = username
        self.user_id = user_id
        self.avatar_version = avatar_version
        self.display_name = display_name or username
        self.last_avatar_check = 0
        self.public_key = None

    def get_display_name(self):
        return self.display_name

    def needs_avatar_check(self):
        return time.time() - self.last_avatar_check > 60

    def update_avatar_check_time(self):
        self.last_avatar_check = time.time()