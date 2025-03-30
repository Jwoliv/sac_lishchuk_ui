import sys
import requests
from PyQt6.QtCore import QByteArray
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QMessageBox, \
    QComboBox, QGroupBox, QFormLayout, QHBoxLayout


API_URL = "http://localhost:8080/api/rule/files"


class FileRuleClient(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # User Credentials Section
        user_credentials_group = QGroupBox("User Credentials", self)
        user_credentials_layout = QFormLayout()
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Enter Username")
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter Password")
        user_credentials_layout.addRow("Username:", self.username_input)
        user_credentials_layout.addRow("Password:", self.password_input)
        user_credentials_group.setLayout(user_credentials_layout)
        layout.addWidget(user_credentials_group)

        # File Operations Section
        file_operations_group = QGroupBox("File Operations", self)
        file_operations_layout = QVBoxLayout()

        self.file_name_input = QLineEdit(self)
        self.file_name_input.setPlaceholderText("Enter File Name")
        file_operations_layout.addWidget(self.file_name_input)

        self.response_area = QTextEdit(self)
        self.response_area.setReadOnly(True)
        file_operations_layout.addWidget(self.response_area)

        self.register_button = QPushButton("Register File", self)
        self.register_button.clicked.connect(self.register_file)
        file_operations_layout.addWidget(self.register_button)

        self.read_button = QPushButton("Read File", self)
        self.read_button.clicked.connect(self.read_file)
        file_operations_layout.addWidget(self.read_button)

        self.prepare_write_button = QPushButton("Prepare Write", self)
        self.prepare_write_button.clicked.connect(self.prepare_write)
        file_operations_layout.addWidget(self.prepare_write_button)

        self.write_button = QPushButton("Write File", self)
        self.write_button.clicked.connect(self.write_file)
        self.write_button.setEnabled(False)
        file_operations_layout.addWidget(self.write_button)

        self.content_area = QTextEdit(self)
        self.content_area.setPlaceholderText("Enter content to write...")
        self.content_area.setVisible(False)
        file_operations_layout.addWidget(self.content_area)

        self.execute_button = QPushButton("Execute File", self)
        self.execute_button.clicked.connect(self.execute_file)
        file_operations_layout.addWidget(self.execute_button)

        file_operations_group.setLayout(file_operations_layout)
        layout.addWidget(file_operations_group)

        # Permission Management Section
        permission_management_group = QGroupBox("Permission Management", self)
        permission_management_layout = QVBoxLayout()

        self.prepare_change_permission_button = QPushButton("Prepare Change Permission", self)
        self.prepare_change_permission_button.clicked.connect(self.prepare_change_permission)
        permission_management_layout.addWidget(self.prepare_change_permission_button)

        self.change_permission_button = QPushButton("Change Permission", self)
        self.change_permission_button.clicked.connect(self.change_permission)
        self.change_permission_button.setEnabled(False)
        permission_management_layout.addWidget(self.change_permission_button)

        self.role_permission_select = QComboBox(self)
        self.role_permission_select.addItems(["ADMIN", "MODERATOR", "USER"])
        self.role_permission_select.setVisible(False)
        permission_management_layout.addWidget(self.role_permission_select)

        self.permission_select = QComboBox(self)
        self.permission_select.addItems(["R", "W", "E"])
        self.permission_select.setVisible(False)
        permission_management_layout.addWidget(self.permission_select)

        self.action_select = QComboBox(self)
        self.action_select.addItems(["ADD", "REMOVE"])
        self.action_select.setVisible(False)
        permission_management_layout.addWidget(self.action_select)

        permission_management_group.setLayout(permission_management_layout)
        layout.addWidget(permission_management_group)

        # User Management Section
        user_management_group = QGroupBox("User Management", self)
        user_management_layout = QVBoxLayout()

        self.prepare_add_user_button = QPushButton("Prepare Add User", self)
        self.prepare_add_user_button.clicked.connect(self.prepare_add_user)
        user_management_layout.addWidget(self.prepare_add_user_button)

        self.add_user_button = QPushButton("Add User", self)
        self.add_user_button.clicked.connect(self.add_user)
        self.add_user_button.setEnabled(False)
        user_management_layout.addWidget(self.add_user_button)

        # New User Fields
        self.first_name_input = QLineEdit(self)
        self.first_name_input.setPlaceholderText("Enter First Name")
        self.first_name_input.setVisible(False)
        user_management_layout.addWidget(self.first_name_input)

        self.last_name_input = QLineEdit(self)
        self.last_name_input.setPlaceholderText("Enter Last Name")
        self.last_name_input.setVisible(False)
        user_management_layout.addWidget(self.last_name_input)

        self.middle_name_input = QLineEdit(self)
        self.middle_name_input.setPlaceholderText("Enter Middle Name")
        self.middle_name_input.setVisible(False)
        user_management_layout.addWidget(self.middle_name_input)

        self.new_user_email_input = QLineEdit(self)
        self.new_user_email_input.setPlaceholderText("Enter Email")
        self.new_user_email_input.setVisible(False)
        user_management_layout.addWidget(self.new_user_email_input)

        self.new_user_password_input = QLineEdit(self)
        self.new_user_password_input.setPlaceholderText("Enter Password")
        self.new_user_password_input.setVisible(False)
        user_management_layout.addWidget(self.new_user_password_input)

        # Role and Mandatory Level Select Fields
        self.role_select = QComboBox(self)
        self.role_select.addItems(["USER","MODERATOR","ADMIN"])
        self.role_select.setVisible(False)
        user_management_layout.addWidget(self.role_select)

        self.mandatory_level_select = QComboBox(self)
        self.mandatory_level_select.addItems([
            "TOP_SECRET",
            "SECRET",
            "HIGHLY_CONFIDENTIAL",
            "CONFIDENTIAL",
            "RESTRICTED",
            "INTERNAL_USE_ONLY",
            "UNCLASSIFIED",
            "PUBLIC"
        ])
        self.mandatory_level_select.setVisible(False)
        user_management_layout.addWidget(self.mandatory_level_select)

        # Admin Config Fields (new fields for adminConfig)
        self.admin_email_input = QLineEdit(self)
        self.admin_email_input.setPlaceholderText("Enter Admin Email")
        self.admin_email_input.setVisible(True)
        user_management_layout.addWidget(self.admin_email_input)

        self.admin_password_input = QLineEdit(self)
        self.admin_password_input.setPlaceholderText("Enter Admin Password")
        self.admin_password_input.setVisible(True)
        user_management_layout.addWidget(self.admin_password_input)

        user_management_group.setLayout(user_management_layout)
        layout.addWidget(user_management_group)

        self.clear_button = QPushButton("Clear All Forms", self)
        self.clear_button.clicked.connect(self.clear_all_forms)
        layout.addWidget(self.clear_button)

        self.setLayout(layout)
        self.setWindowTitle("File Rule Client")

    def send_request(self, data, endpoint = "", api_url = API_URL):
        try:
            if endpoint is not None:
                response = requests.post(f"{api_url}/{endpoint}", json=data, timeout=10)
            else:
                response = requests.post(f"{api_url}", json=data, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                QMessageBox.critical(self, "Error", f"Request failed: {response.status_code}\n{response.text}")
                return None
        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"Network error: {e}")
            return None

    def register_file(self):
        data = {
            "fileName": self.file_name_input.text(),
            "permissions": {"ADMIN": ["R", "W", "X"]},
            "adminConfig": {"email": self.username_input.text(), "password": self.password_input.text()},
            "role": self.role_select.currentText() if self.role_select.isVisible() else None,
            "mandatoryLevel": self.mandatory_level_select.currentText() if self.mandatory_level_select.isVisible() else None,
        }
        response = self.send_request(data, "register")
        if response:
            self.response_area.setText(str(response))

    def read_file(self):
        data = {
            "fileName": self.file_name_input.text(),
            "userConfig": {
                "email": self.username_input.text(),
                "password": self.password_input.text()
            }
        }

        # Send the request, checking the endpoint based on the file extension
        if data["fileName"].lower().endswith(".jpg") or data["fileName"].lower().endswith(".png"):
            response = requests.post(f"{API_URL}/image/read", json=data, timeout=10)
        else:
            response = requests.post(f"{API_URL}/read", json=data, timeout=10)

        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")

            # Handle JSON responses
            if "application/json" in content_type:
                try:
                    response_json = response.json()
                    if "content" in response_json:
                        self.response_area.setText(response_json["content"])
                    else:
                        self.response_area.setText(response_json["clientText"])
                except ValueError:
                    self.response_area.setText("Invalid JSON response")

            # Handle Image Responses
            elif "image" in content_type:
                image_data = QByteArray(response.content)
                pixmap = QPixmap()
                if pixmap.loadFromData(image_data):
                    self.image_label = QLabel(self)  # Ensure the QLabel exists
                    self.image_label.setPixmap(pixmap)
                    self.image_label.setScaledContents(True)
                    self.image_label.setMinimumWidth(500)
                    self.image_label.setMinimumHeight(500)
                    self.image_label.show()
                else:
                    self.response_area.setText("Failed to load image data.")

            else:
                self.response_area.setText("Unknown response type")
        else:
            self.response_area.setText(f"Error {response.status_code}: {response.text}")

    def prepare_write(self):
        self.content_area.setVisible(True)
        self.write_button.setEnabled(True)

    def write_file(self):
        data = {
            "fileName": self.file_name_input.text(),
            "userConfig": {"email": self.username_input.text(), "password": self.password_input.text()},
            "newContent": self.content_area.toPlainText(),
            "action": "OVERWRITE"
        }
        response = self.send_request(data, "write")
        if "content" in response:
            self.response_area.setText(response["content"])
        else:
            self.response_area.setText(response["clientText"])

    def execute_file(self):
        data = {
            "fileName": self.file_name_input.text(),
            "userConfig": {"email": self.username_input.text(), "password": self.password_input.text()}
        }
        response = self.send_request(data, "execute")
        response_json = response.json()
        if "content" in response_json:
            self.response_area.setText(response_json["content"])
        else:
            self.response_area.setText(response_json["clientText"])

    def prepare_change_permission(self):
        self.role_permission_select.setVisible(True)
        self.permission_select.setVisible(True)
        self.action_select.setVisible(True)
        self.change_permission_button.setEnabled(True)

    def change_permission(self):
        data = {
            "fileName": self.file_name_input.text(),
            "permissions": {self.role_permission_select.currentText(): [self.permission_select.currentText()]},
            "action": self.action_select.currentText(),
            "userConfig": {"email": self.username_input.text(), "password": self.password_input.text()}
        }
        response = self.send_request(data, "change-permission")
        if response:
            self.response_area.setText(str(response))

    def prepare_add_user(self):
        self.first_name_input.setVisible(True)
        self.last_name_input.setVisible(True)
        self.middle_name_input.setVisible(True)
        self.new_user_email_input.setVisible(True)
        self.new_user_password_input.setVisible(True)
        self.role_select.setVisible(True)
        self.mandatory_level_select.setVisible(True)
        self.admin_email_input.setVisible(True)
        self.admin_password_input.setVisible(True)
        self.add_user_button.setEnabled(True)

    def add_user(self):
        data = {
            "firstName": self.first_name_input.text(),
            "lastName": self.last_name_input.text(),
            "middleName": self.middle_name_input.text(),
            "email": self.new_user_email_input.text(),
            "password": self.new_user_password_input.text(),
            "role": self.role_select.currentText(),
            "mandatoryLevel": self.mandatory_level_select.currentText(),
            "adminConfig": {
                "email": self.admin_email_input.text(),
                "password": self.admin_password_input.text()
            }
        }
        response = self.send_request(data, None, "http://localhost:8080/api/users")
        if response:
            self.response_area.setText(str(response))


    # Define the function to clear all inputs
    def clear_all_forms(self):
        self.username_input.clear()
        self.password_input.clear()
        self.file_name_input.clear()
        self.response_area.clear()
        self.content_area.clear()
        self.first_name_input.clear()
        self.last_name_input.clear()
        self.middle_name_input.clear()
        self.new_user_email_input.clear()
        self.new_user_password_input.clear()
        self.admin_email_input.clear()

        # Hide optional fields
        self.content_area.setVisible(False)
        self.permission_select.setVisible(False)
        self.action_select.setVisible(False)
        self.first_name_input.setVisible(False)
        self.last_name_input.setVisible(False)
        self.middle_name_input.setVisible(False)
        self.new_user_email_input.setVisible(False)
        self.new_user_password_input.setVisible(False)
        self.role_select.setVisible(False)
        self.mandatory_level_select.setVisible(False)
        self.admin_email_input.setVisible(False)
        self.admin_password_input.setVisible(False)

        # Disable buttons that require input
        self.write_button.setEnabled(False)
        self.change_permission_button.setEnabled(False)
        self.add_user_button.setEnabled(False)
        self.image_label.setVisible(False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    client = FileRuleClient()
    client.show()
    sys.exit(app.exec())
