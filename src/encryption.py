import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class Encryption:
    @staticmethod
    def generate_key(password, salt=None, iterations=100000):
        if not salt:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )

        # Zwracamy klucz w base64 i sól (gdybyśmy chcieli osobno zapisywać)
        derived_key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(derived_key), salt
