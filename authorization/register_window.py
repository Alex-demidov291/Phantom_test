from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtCore import QObject, pyqtSlot, QUrl
from pathlib import Path
from network import messenger_api
from utils import BASE_PATH
import html


class RegisterBridge(QObject):
    # -- мост для регистрации
    def __init__(self, register_window):
        super().__init__()
        self.register_window = register_window

    @pyqtSlot(str, str, str, str)
    def register(self, login, name, password, confirm):
        # - регистрация нового юзера
        self.register_window.check_reg(login, name, password, confirm)

    @pyqtSlot()
    def backToLogin(self):
        #  - возврат на вход
        self.register_window.show_login_window()


class RegisterWindow(QWidget):
    #  -- окно регистрации
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.bridge = RegisterBridge(self)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        self.web_view.setStyleSheet("border: none; background: transparent;")

        self.channel = QWebChannel(self.web_view.page())
        self.channel.registerObject("backend", self.bridge)
        self.web_view.page().setWebChannel(self.channel)

        html_path = Path(BASE_PATH) / "authorization" / "reg_wind1.html"
        if html_path.exists():
            self.web_view.setUrl(QUrl.fromLocalFile(str(html_path.absolute())))
        else:
            self.web_view.setHtml("""
                <!DOCTYPE html>
                <html>
                <head><meta charset="UTF-8"><title>Ошибка</title></head>
                <body style="font-family: Arial; padding: 20px;">
                    <h2>Файл reg_wind1.html не найден</h2>
                </body>
                </html>
            """)

        layout.addWidget(self.web_view)

    def check_reg(self, login, name, password, confirm):
        if not all([login, password, name, confirm]):
            self.web_view.page().runJavaScript('showToast("Заполните все поля!", true);')
            return

        if len(login) < 4 or len(login) > 20:
            self.web_view.page().runJavaScript('showToast("Логин должен быть от 4 до 20 символов!", true);')
            return

        if len(name) < 4 or len(name) > 20:
            self.web_view.page().runJavaScript('showToast("Имя должно быть от 4 до 20 символов!", true);')
            return

        if len(password) < 8 or len(password) > 25:
            self.web_view.page().runJavaScript('showToast("Пароль должен быть от 8 до 25 символов!", true);')
            return

        has_lower = False
        has_upper = False
        has_digit = False
        has_special = False

        for c in password:
            if c.islower():
                has_lower = True
            elif c.isupper():
                has_upper = True
            elif c.isdigit():
                has_digit = True
            elif not c.isalnum():
                has_special = True

        if not (has_lower and has_upper and has_digit and has_special):
            self.web_view.page().runJavaScript(
                'showToast("Пароль должен содержать заглавные и строчные буквы, цифры и спецсимволы!", true);')
            return

        if password != confirm:
            self.web_view.page().runJavaScript('showToast("Пароли не совпадают!", true);')
            return

        self.web_view.page().runJavaScript('setLoading(true);')

        def handle_register_response(response):
            self.web_view.page().runJavaScript('setLoading(false);')
            if response and response.get('success'):
                self.web_view.page().runJavaScript('showToast("Регистрация прошла успешно!");')
                self.show_login_window()
            else:
                error_msg = response.get('error', 'Ошибка регистрации') if response else 'Сервер не отвечает'
                safe_error = html.escape(error_msg).replace('"', '\\"').replace("'", "\\'")
                self.web_view.page().runJavaScript(f'showToast("{safe_error}", true);')

        messenger_api.opaque_register_async(login, name, password, handle_register_response)

    def show_login_window(self):
        self.main_window.show_login_window()