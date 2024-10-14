import hashlib
import os
import tarfile
import zipfile
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QFileDialog, QTextEdit, QMessageBox

class FileHashAnalyzer(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.result_area = QTextEdit(self)
        self.result_area.setReadOnly(True)
        layout.addWidget(self.result_area)

        self.hash_count_label = QLabel("Hashes found: 0")
        layout.addWidget(self.hash_count_label)

        # Button to select file
        self.select_file_btn = QPushButton('Select Archive File', self)
        self.select_file_btn.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_btn)

        # Button to copy all hashes
        self.copy_btn = QPushButton('Copy All Hashes', self)
        self.copy_btn.clicked.connect(self.copy_hashes_to_clipboard)
        layout.addWidget(self.copy_btn)

        self.setLayout(layout)
        self.setWindowTitle('File Hash Analyzer')

    def select_file(self):
        file_filter = 'Archives (*.tar.bz2 *.zip);;All Files (*)'
        file_name, _ = QFileDialog.getOpenFileName(self, 'Select File to Analyze', '', file_filter)
        
        if file_name:
            try:
                hashes = self.analyze_file(file_name)
                sorted_hashes = sorted(hashes)  # Sort lexicographically
                self.display_hashes(sorted_hashes)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to process file: {e}")

    def analyze_file(self, file_path):
        """Analyzes the archive file and returns a list of SHA256 hashes"""
        hashes = []

        # Extract and process .tar.bz2
        if file_path.endswith('.tar.bz2'):
            with tarfile.open(file_path, 'r:bz2') as archive:
                for member in archive.getmembers():
                    if member.isfile():  # Check for actual files only
                        file_content = archive.extractfile(member).read()
                        file_hash = hashlib.sha256(file_content).hexdigest()
                        hashes.append(file_hash.lower())  # Ensure lowercase
                        print(f"Hashed file: {member.name}")  # Log the file being hashed
                        
        # Extract and process .zip
        elif file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as archive:
                for file_info in archive.infolist():
                    if not file_info.is_dir():  # Skip directories
                        file_content = archive.read(file_info.filename)
                        file_hash = hashlib.sha256(file_content).hexdigest()
                        hashes.append(file_hash.lower())  # Ensure lowercase
                        print(f"Hashed file: {file_info.filename}")  # Log the file being hashed

        return hashes

    def display_hashes(self, hashes):
        """Displays the sorted hashes in the text area and updates the count"""
        self.result_area.clear()
        self.result_area.append("\n".join(hashes))
        self.hash_count_label.setText(f"Hashes found: {len(hashes)}")

    def copy_hashes_to_clipboard(self):
        """Copies the hashes from the text area to the clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.result_area.toPlainText())
        QMessageBox.information(self, "Copied", "Hashes copied to clipboard!")


if __name__ == '__main__':
    app = QApplication([])
    window = FileHashAnalyzer()
    window.show()
    app.exec_()
