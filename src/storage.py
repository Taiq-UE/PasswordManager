import os
import json

class Storage:
    """
    Klasa odpowiedzialna za operacje na plikach JSON w folderze 'passwords'.
    Zapewnia funkcje zapisu, odczytu i usuwania plików haseł.
    """

    # Ustal bazowy folder obok folderu src
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PASSWORDS_DIR = os.path.join(BASE_DIR, '..', 'passwords')

    # Upewniamy się, że folder 'passwords' istnieje
    os.makedirs(PASSWORDS_DIR, exist_ok=True)

    @staticmethod
    def save_to_file(filename, data):
        """
        Zapisuje słownik `data` do pliku `filename` (JSON) w folderze 'passwords'.
        Np. 'master.json'.
        """
        path = os.path.join(Storage.PASSWORDS_DIR, filename)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    @staticmethod
    def load_from_file(filename):
        """
        Odczytuje dane z pliku JSON `filename` w folderze 'passwords'.
        Zwraca None, jeśli plik nie istnieje.
        """
        path = os.path.join(Storage.PASSWORDS_DIR, filename)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    @staticmethod
    def save_service_password(service_name, data):
        """
        Zapisuje dane usługi do pliku o nazwie service_name.json w folderze 'passwords'.
        data to słownik zawierający np. { "service": ..., "username": ..., "password": ... }
        """
        filename = f"{service_name}.json"
        Storage.save_to_file(filename, data)

    @staticmethod
    def load_service_password(service_name):
        """
        Odczytuje dane usługi z pliku service_name.json w folderze 'passwords'.
        Zwraca słownik z kluczami 'service', 'username', 'password'.
        Zwraca None, jeśli plik nie istnieje.
        """
        filename = f"{service_name}.json"
        return Storage.load_from_file(filename)

    @staticmethod
    def delete_service_password(service_name):
        """
        Usuwa plik service_name.json z folderu 'passwords', jeśli istnieje.
        """
        filename = f"{service_name}.json"
        path = os.path.join(Storage.PASSWORDS_DIR, filename)
        if os.path.exists(path):
            os.remove(path)

    @staticmethod
    def load_all_services():
        """
        Zwraca słownik wszystkich usług i powiązanych danych z folderu 'passwords'
        w formacie:
        {
            "nazwa_uslugi": {
                "service": "nazwa_uslugi",
                "username": "...",
                "password": "zaszyfrowane_haslo"
            },
            ...
        }

        Pomija plik master.json.
        """
        services_data = {}
        for filename in os.listdir(Storage.PASSWORDS_DIR):
            if filename.endswith('.json') and filename != 'master.json':
                path = os.path.join(Storage.PASSWORDS_DIR, filename)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        service_name = data.get("service")
                        if service_name:
                            services_data[service_name] = data
                except (FileNotFoundError, json.JSONDecodeError):
                    pass
        return services_data
