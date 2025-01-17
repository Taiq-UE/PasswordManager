import os
import secrets
import string
import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from storage import Storage


class PasswordManager:
    """
    Klasa zarządzająca hasłami:
     - generuje i weryfikuje klucz na podstawie hasła głównego,
     - szyfruje / deszyfruje hasła,
     - zapisuje / odczytuje / usuwa pliki .json z hasłami.
    """

    def __init__(self, master_password, salt=None):
        if not salt:
            self.salt = os.urandom(16)
        else:
            self.salt = salt

        self.key = self._generate_key(master_password)
        self.backend = default_backend()

    def _generate_key(self, password, iterations=100000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit
            salt=self.salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def verify_master_password(self, stored_key):
        """
        Porównuje wygenerowany klucz z przechowywanym kluczem.
        """
        return self.key == stored_key

    def encrypt_password(self, plain_password):
        """
        Szyfruje tekst jawny AES (CFB) i zwraca zakodowany w base64.
        """
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(plain_password.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(iv + ct).decode()

    def decrypt_password(self, encrypted_password):
        """
        Deszyfruje base64 z (iv+zaszyfrowane dane).
        """
        encrypted_data = base64.urlsafe_b64decode(encrypted_password)
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        return decrypted.decode()

    def generate_password(self, length=16):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))

    def save_password(self, service, username, password):
        """
        Zapisuje zaszyfrowane hasło w pliku (service).json w folderze 'passwords'.
        """
        encrypted_password = self.encrypt_password(password)
        data = {
            "service": service,
            "username": username,
            "password": encrypted_password
        }
        Storage.save_service_password(service, data)

    def load_password(self, service):
        """
        Odczytuje plik (service).json i deszyfruje hasło.
        Zwraca krotkę (username, plain_password) lub None, jeśli plik nie istnieje.
        """
        data = Storage.load_service_password(service)
        if data is not None:
            plain_password = self.decrypt_password(data['password'])
            return data['username'], plain_password
        return None

    def delete_password(self, service):
        """
        Usuwa plik (service).json z folderu 'passwords'.
        """
        Storage.delete_service_password(service)
