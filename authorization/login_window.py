from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtCore import QObject, pyqtSlot, QUrl
from pathlib import Path
from network import messenger_api
import html
from utils import BASE_PATH


class LoginBridge(QObject):
    # -- мост для входа

    def __init__(self, login_window):
        super().__init__()
        self.login_window = login_window

    @pyqtSlot(str, str)
    def login(self, login, password):
        # - вход в систему
        self.login_window.check_log(login, password)

    @pyqtSlot()
    def showRegister(self):
        # - показать регистрацию
        self.login_window.show_register_window()


class LoginWindow(QWidget):
    # -- окно входа
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.bridge = LoginBridge(self)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        self.web_view.setStyleSheet("border: none; background: transparent;")

        self.channel = QWebChannel(self.web_view.page())
        self.channel.registerObject("backend", self.bridge)
        self.web_view.page().setWebChannel(self.channel)

        html_path = Path(BASE_PATH) / "authorization" / "log_wind1.html"
        if html_path.exists():
            self.web_view.setUrl(QUrl.fromLocalFile(str(html_path.absolute())))
        else:
            self.web_view.setHtml("""
                <!DOCTYPE html>
                <html>
                <head><meta charset="UTF-8"><title>Ошибка</title></head>
                <body style="font-family: Arial; padding: 20px;">
                    <h2>Файл log_wind1.html не найден</h2>
                </body>
                </html>
            """)

        layout.addWidget(self.web_view)

    def check_log(self, login, password):
        if not login or not password:
            self.web_view.page().runJavaScript('showToast("Заполните все поля!", true);')
            return

        self.web_view.page().runJavaScript('setLoading(true);')

        def handle_login_response(response):
            self.web_view.page().runJavaScript('setLoading(false);')
            if response and response.get('success'):
                self.main_window.user_token = response['user_token']
                self.main_window.user_id = response['user_id']
                self.main_window.username = response['username']
                self.main_window.current_user = login
                self.main_window.session_token = response['session_token']
                messenger_api.set_user_credentials(response['session_token'], response['user_id'], login)
                self.main_window.show_chat_window()
                self.close()
            else:
                error_msg = response.get('error', 'Неверный логин или пароль') if response else 'Ошибка соединения'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("{safe_error}", true);')

        messenger_api.opaque_login_async(login, password, handle_login_response)

    def show_register_window(self):
        self.main_window.show_register_window()
