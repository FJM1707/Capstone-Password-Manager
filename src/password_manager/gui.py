"""PySide6 desktop GUI for the password manager."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .config import DEFAULT_VAULT_PATH
from .crypto import DecryptionError
from .generator import GeneratorOptions, generate_password
from .vault import Vault, VaultError

CLIPBOARD_CLEAR_SECONDS = 20
MASKED_PASSWORD_DISPLAY = "*" * 10


class GeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Password")
        self.result_password = ""

        layout = QVBoxLayout(self)

        form = QFormLayout()
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 128)
        self.length_spin.setValue(20)
        self.length_spin.valueChanged.connect(self._regenerate)
        form.addRow("Length:", self.length_spin)
        layout.addLayout(form)

        self.lower_check = QCheckBox("Lowercase (a-z)")
        self.lower_check.setChecked(True)
        self.upper_check = QCheckBox("Uppercase (A-Z)")
        self.upper_check.setChecked(True)
        self.digit_check = QCheckBox("Digits (0-9)")
        self.digit_check.setChecked(True)
        self.symbol_check = QCheckBox("Symbols (!@#$...)")
        self.symbol_check.setChecked(True)
        for cb in (self.lower_check, self.upper_check, self.digit_check, self.symbol_check):
            cb.toggled.connect(self._regenerate)
            layout.addWidget(cb)

        self.preview = QLineEdit()
        self.preview.setReadOnly(True)
        layout.addWidget(self.preview)

        regen_btn = QPushButton("Regenerate")
        regen_btn.clicked.connect(self._regenerate)
        layout.addWidget(regen_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._regenerate()

    def _options(self) -> GeneratorOptions:
        return GeneratorOptions(
            length=self.length_spin.value(),
            use_lowercase=self.lower_check.isChecked(),
            use_uppercase=self.upper_check.isChecked(),
            use_digits=self.digit_check.isChecked(),
            use_symbols=self.symbol_check.isChecked(),
        )

    def _regenerate(self):
        try:
            self.preview.setText(generate_password(self._options()))
        except ValueError as exc:
            self.preview.setText("")
            QMessageBox.warning(self, "Cannot generate", str(exc))

    def accept(self):
        self.result_password = self.preview.text()
        super().accept()


class EntryDialog(QDialog):
    def __init__(self, parent=None, service="", username="", password="", notes="", editing_service=False):
        super().__init__(parent)
        self.setWindowTitle("Edit Entry" if editing_service else "Add Entry")

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.service_edit = QLineEdit(service)
        self.service_edit.setReadOnly(editing_service)
        form.addRow("Service:", self.service_edit)

        self.username_edit = QLineEdit(username)
        form.addRow("Username:", self.username_edit)

        pw_row = QHBoxLayout()
        self.password_edit = QLineEdit(password)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pw_row.addWidget(self.password_edit)

        show_btn = QPushButton("Show")
        show_btn.setCheckable(True)
        show_btn.toggled.connect(
            lambda checked: self.password_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        pw_row.addWidget(show_btn)

        gen_btn = QPushButton("Generate")
        gen_btn.clicked.connect(self._generate)
        pw_row.addWidget(gen_btn)

        form.addRow("Password:", pw_row)

        self.notes_edit = QTextEdit(notes)
        self.notes_edit.setFixedHeight(80)
        form.addRow("Notes:", self.notes_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _generate(self):
        dialog = GeneratorDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.password_edit.setText(dialog.result_password)

    def values(self):
        return (
            self.service_edit.text().strip(),
            self.username_edit.text().strip(),
            self.password_edit.text(),
            self.notes_edit.toPlainText(),
        )


class VaultWindow(QMainWindow):
    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault
        self.setWindowTitle(f"Password Manager - {vault.path}")
        self.resize(700, 400)

        central = QWidget()
        layout = QVBoxLayout(central)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Service", "Username", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_entry)
        edit_btn = QPushButton("Edit")
        edit_btn.clicked.connect(self.edit_entry)
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_entry)
        copy_btn = QPushButton("Copy Password")
        copy_btn.clicked.connect(self.copy_password)
        self.reveal_btn = QPushButton("Show Passwords")
        self.reveal_btn.setCheckable(True)
        self.reveal_btn.toggled.connect(self.toggle_reveal)
        change_pw_btn = QPushButton("Change Master Password")
        change_pw_btn.clicked.connect(self.change_master_password)
        lock_btn = QPushButton("Lock")
        lock_btn.clicked.connect(self.lock)

        for b in (add_btn, edit_btn, delete_btn, copy_btn, self.reveal_btn, change_pw_btn, lock_btn):
            btn_row.addWidget(b)
        layout.addLayout(btn_row)

        self.setCentralWidget(central)

        self._revealed = False
        self._clipboard_timer = QTimer(self)
        self._clipboard_timer.setSingleShot(True)
        self._clipboard_timer.timeout.connect(self._clear_clipboard)

        self.refresh_table()

    def refresh_table(self):
        services = self.vault.list_services()
        self.table.setRowCount(len(services))
        for row, service in enumerate(services):
            entry = self.vault.get_entry(service)
            self.table.setItem(row, 0, QTableWidgetItem(service))
            self.table.setItem(row, 1, QTableWidgetItem(entry.username))
            shown = entry.password if self._revealed else MASKED_PASSWORD_DISPLAY
            self.table.setItem(row, 2, QTableWidgetItem(shown))

    def toggle_reveal(self, checked):
        self._revealed = checked
        self.reveal_btn.setText("Hide Passwords" if checked else "Show Passwords")
        self.refresh_table()

    def _selected_service(self) -> str | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        return self.table.item(row, 0).text()

    def add_entry(self):
        dialog = EntryDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            service, username, password, notes = dialog.values()
            if not service:
                QMessageBox.warning(self, "Missing service", "Service name is required")
                return
            try:
                self.vault.add_entry(service, username, password, notes)
            except VaultError as exc:
                QMessageBox.warning(self, "Error", str(exc))
            self.refresh_table()

    def edit_entry(self):
        service = self._selected_service()
        if not service:
            return
        entry = self.vault.get_entry(service)
        dialog = EntryDialog(
            self,
            service=service,
            username=entry.username,
            password=entry.password,
            notes=entry.notes,
            editing_service=True,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            _, username, password, notes = dialog.values()
            self.vault.update_entry(service, username=username, password=password, notes=notes)
            self.refresh_table()

    def delete_entry(self):
        service = self._selected_service()
        if not service:
            return
        confirm = QMessageBox.question(self, "Delete entry", f"Delete the entry for '{service}'?")
        if confirm == QMessageBox.StandardButton.Yes:
            self.vault.delete_entry(service)
            self.refresh_table()

    def copy_password(self):
        service = self._selected_service()
        if not service:
            return
        entry = self.vault.get_entry(service)
        QApplication.clipboard().setText(entry.password)
        self._clipboard_timer.start(CLIPBOARD_CLEAR_SECONDS * 1000)
        QMessageBox.information(
            self, "Copied", f"Password copied to clipboard - it will clear automatically in {CLIPBOARD_CLEAR_SECONDS}s"
        )

    def _clear_clipboard(self):
        QApplication.clipboard().clear()

    def change_master_password(self):
        new_pw, ok = QInputDialog.getText(
            self, "Change Master Password", "New master password:", QLineEdit.EchoMode.Password
        )
        if not ok or not new_pw:
            return
        confirm_pw, ok = QInputDialog.getText(
            self, "Change Master Password", "Confirm new master password:", QLineEdit.EchoMode.Password
        )
        if not ok or confirm_pw != new_pw:
            QMessageBox.warning(self, "Mismatch", "Passwords did not match")
            return
        self.vault.change_master_password(new_pw)
        QMessageBox.information(self, "Done", "Master password changed")

    def lock(self):
        launch_unlock_flow(self.vault.path)
        self.close()


class UnlockWindow(QWidget):
    def __init__(self, vault_path: Path):
        super().__init__()
        self.vault_path = vault_path
        self.creating = not Vault.exists(vault_path)
        self.setWindowTitle("Create Master Password" if self.creating else "Unlock Vault")
        self.resize(360, 160)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Master password:", self.password_edit)

        self.confirm_edit = None
        if self.creating:
            self.confirm_edit = QLineEdit()
            self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Confirm password:", self.confirm_edit)

        layout.addLayout(form)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: red")
        layout.addWidget(self.error_label)

        submit_btn = QPushButton("Create Vault" if self.creating else "Unlock")
        submit_btn.clicked.connect(self.submit)
        layout.addWidget(submit_btn)

        self.password_edit.returnPressed.connect(submit_btn.click)

    def submit(self):
        password = self.password_edit.text()
        if not password:
            self.error_label.setText("Password cannot be empty")
            return

        if self.creating:
            if password != self.confirm_edit.text():
                self.error_label.setText("Passwords do not match")
                return
            if len(password) < 8:
                self.error_label.setText("Use at least 8 characters for your master password")
                return
            vault = Vault.create(self.vault_path, password)
        else:
            try:
                vault = Vault.unlock(self.vault_path, password)
            except DecryptionError as exc:
                self.error_label.setText(str(exc))
                return

        self.vault_window = VaultWindow(vault)
        self.vault_window.show()
        self.close()


def launch_unlock_flow(vault_path: Path = DEFAULT_VAULT_PATH) -> UnlockWindow:
    window = UnlockWindow(vault_path)
    window.show()
    # Keep a strong reference on the QApplication instance so PySide6 doesn't
    # garbage-collect the window the moment this function returns.
    app = QApplication.instance()
    app._pm_unlock_window = window
    return window


def main():
    DEFAULT_VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    app = QApplication(sys.argv)
    launch_unlock_flow()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
