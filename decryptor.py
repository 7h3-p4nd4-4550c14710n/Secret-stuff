import sys

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (QApplication, QPushButton, QVBoxLayout, QWidget,
                               QFileDialog, QLabel)
from Crypto.Cipher import AES

from __feature__ import snake_case, true_property

key = b"poJmIrGFozbFFjS4"
aes = AES.new(key, AES.MODE_ECB)


def decrypt_file(path: str):
    with open(path, "rb") as f:
        ciphertext = f.read()
        cleartext = aes.decrypt(ciphertext)
        return cleartext


class Window(QWidget):

    def __init__(self):
        QWidget.__init__(self)

        self.file_name = ""

        self.status_label = QLabel("No file selected")
        self.plaintext_label = QLabel()
        self.choose_file_button = QPushButton("Select file for decryption")
        self.decrypt_button = QPushButton("Decrypt")

        self.layout = QVBoxLayout(self)
        self.layout.add_widget(self.choose_file_button)
        self.layout.add_widget(self.decrypt_button)
        self.layout.add_widget(self.status_label)
        self.layout.add_widget(self.plaintext_label)

        self.choose_file_button.clicked.connect(self.select_file)
        self.decrypt_button.clicked.connect(self.decrypt)

    @Slot()
    def select_file(self):
        print("selecting file...")
        file_name = QFileDialog.get_open_file_name(self, "Open File")
        if file_name:
            self.file_name = file_name[0]
            self.status_label.setText(self.file_name)

    @Slot()
    def decrypt(self):
        if self.file_name:
            plaintext = decrypt_file(self.file_name)
            try:
                self.plaintext_label.setText(plaintext.decode("utf-8"))
            except UnicodeDecodeError:
                self.plaintext_label.setText("")
            with open("decrypted", "wb") as f:
                f.write(plaintext)
        else:
            print("Select a file first!")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec())
