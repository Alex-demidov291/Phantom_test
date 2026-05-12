style_menu = """
QMenu {
    background-color: #ffffff;
    border: 1px solid #dee2e6;
    border-radius: 8px;
    padding: 5px;
    margin-top: 5px;
}
QMenu::item {
    padding: 8px 20px;
    border-radius: 4px;
    margin: 2px;
}
QMenu::item:selected {
    background-color: #007acc;
    color: #ffffff;
}
QMenu::separator {
    height: 1px;
    background-color: #dee2e6;
    margin: 5px 0px;
}
"""

style_tool_button = """
QToolButton {
    border-radius: 20px;
    border: none;
    padding: 8px;
    background: transparent;
}
QToolButton:hover {
    background: #e0e0e0;
}
QToolButton:pressed {
    background: #d0d0d0;
}
QToolButton::menu-indicator {
    width: 0px;
}
"""

style_input_field = """
QLineEdit {
    border-radius: 10px;
    border: 2px solid #cccccc;
    padding: 10px 15px;
    font-size: 14px;
    background: #ffffff;
    color: #000000;
}
QLineEdit:focus {
    border: 2px solid #007acc;
}
"""

style_reg_button = """
QPushButton {
    border-radius: 10px;
    border: 2px solid #007acc;
    background: #007acc;
    padding: 12px 20px;
    font-size: 16px;
    font-weight: bold;
    color: #ffffff;
}
QPushButton:hover {
    background: #005a9e;
    border: 2px solid #005a9e;
}
QPushButton:pressed {
    background: #004a80;
}
"""

style_login_button = """
QPushButton {
    border-radius: 10px;
    border: 2px solid #28a745;
    background: #28a745;
    padding: 12px 20px;
    font-size: 16px;
    font-weight: bold;
    color: #ffffff;
}
QPushButton:hover {
    background: #218838;
    border: 2px solid #218838;
}
QPushButton:pressed {
    background: #1e7e34;
}
"""

style_red_button = """
QPushButton {
    border-radius: 10px;
    border: 2px solid #ff0015;
    background: #ff0015;
    padding: 12px 20px;
    font-size: 16px;
    font-weight: bold;
    color: #ffffff;
}
QPushButton:hover {
    background: #dd0013;
    border: 2px solid #dd0013;
}
QPushButton:pressed {
    background: #bb0010;
}
"""
style_round_btn = """
QPushButton {
    border-radius: 15px;
    border: 1px solid #cccccc;
    background: #ffffff;
    padding: 8px 12px;
    transition: all 0.1s ease;
}
QPushButton:hover {
    border: 2px solid #007acc;
    background: #f5f5f5;
}
QPushButton:pressed {
    background: #e0e0e0;
    border: 2px solid #005a9e;
    padding: 9px 11px 7px 13px;  /* Эффект нажатия */
}
QPushButton:disabled {
    background: #f0f0f0;
    border: 1px solid #dddddd;
    color: #999999;
}
"""
style_mesg = """
QTextEdit {
    border-radius: 15px;
    border: 1px solid #cccccc;
    padding: 8px 12px;
    font-size: 14px;
    background: #ffffff;
}
QTextEdit:focus {
    border: 2px solid #007acc;
}
QTextEdit QScrollBar:vertical {
    border: none;
    background: #f0f0f0;
    width: 8px;
    border-radius: 4px;
    margin: 0px;
}
QTextEdit QScrollBar::handle:vertical {
    background: #c0c0c0;
    border-radius: 4px;
    min-height: 20px;
}
QTextEdit QScrollBar::handle:vertical:hover {
    background: #a0a0a0;
}
QTextEdit QScrollBar::add-line:vertical, QTextEdit QScrollBar::sub-line:vertical {
    border: none;
    background: none;
    height: 0px;
}
QTextEdit QScrollBar::add-page:vertical, QTextEdit QScrollBar::sub-page:vertical {
    background: none;
}
QTextEdit QScrollBar:horizontal {
    border: none;
    background: #f0f0f0;
    height: 8px;
    border-radius: 4px;
    margin: 0px;
}
QTextEdit QScrollBar::handle:horizontal {
    background: #c0c0c0;
    border-radius: 4px;
    min-width: 20px;
}
QTextEdit QScrollBar::handle:horizontal:hover {
    background: #a0a0a0;
}
QTextEdit QScrollBar::add-line:horizontal, QTextEdit QScrollBar::sub-line:horizontal {
    border: none;
    background: none;
    width: 0px;
}
QTextEdit QScrollBar::add-page:horizontal, QTextEdit QScrollBar::sub-page:horizontal {
    background: none;
}
"""


style_chat_list = """
QListWidget {
    border-radius: 15px;
    border: 1px solid #cccccc;
    background: #ffffff;
    outline: 0;
}
QListWidget::item {
    border-radius: 10px;
    padding: 10px;
    font-size: 14px;
    background: #ffffff;
    color: #000000;
    min-height: 30px;
}
QListWidget::item:selected {
    background: #e0e0e0;
    color: #000000;
}
QListWidget::item:hover {
    background: #f5f5f5;
    color: #000000;
}
"""

style_message_area1 = """
QTextBrowser {
    border-radius: 15px;
    border: 1px solid #cccccc;
    padding: 15px;
    font-size: 14px;
    background: #ffffff;
}
"""


style_hi_label = """
QLabel {
    font-size: 18px;
    color: #444444;
    font-weight: bold;
    padding: 10px;
    text-align: center;
}
"""

style_input_dialog = """
QInputDialog {
    background-color: #ffffff;
    border-radius: 10px;
}
QInputDialog QLabel {
    font-size: 15px;
    color: #333333;
    padding: 6px;
}
QInputDialog QLineEdit {
    border-radius: 8px;
    border: 2px solid #cccccc;
    padding: 8px 12px;
    font-size: 14px;
    background: #ffffff;
}
QInputDialog QLineEdit:focus {
    border: 2px solid #007acc;
}
QInputDialog QPushButton {
    border-radius: 8px;
    border: 2px solid #007acc;
    background: #007acc;
    padding: 8px 16px;
    font-size: 14px;
    color: #ffffff;
    min-width: 80px;
}
QInputDialog QPushButton:hover {
    background: #005a9e;
}
"""

angle_alf = "abcdefghijklmnopqrstuvwxyz"
numbers = "1234567890"
from pathlib import Path
script_dir = Path(__file__).parent
images_dir = script_dir / "images"
defult_ava = str(images_dir / "default_avatar.jpg")
