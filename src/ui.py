import os
import base64
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import pyperclip

from password_manager import PasswordManager
from storage import Storage


MASTER_FILE = 'master.json'


class UI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("800x600")
        self.manager = None  # Obiekt PasswordManager po poprawnym logowaniu

        self._check_master_status()

    def _check_master_status(self):
        """
        Sprawdza, czy istnieje już master.json z zapisanym master password.
        Jeśli tak – wyświetla formularz logowania,
        jeśli nie – formularz do ustawienia nowego hasła głównego.
        """
        master_data = Storage.load_from_file(MASTER_FILE)
        if master_data is None:
            # Brak pliku master.json => rejestracja
            self._create_register_window()
        else:
            # Plik istnieje => logowanie
            self._create_login_window()

    def _create_login_window(self):
        frame = tk.Frame(self.root)
        frame.pack(expand=True, fill=tk.BOTH)

        tk.Label(frame, text="Wprowadź Master Password:", font=("Arial", 12)).pack(pady=10)
        self.master_password_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.master_password_var, show="*", width=30).pack()

        tk.Button(frame, text="Zaloguj", command=self._login).pack(pady=10)

    def _create_register_window(self):
        frame = tk.Frame(self.root)
        frame.pack(expand=True, fill=tk.BOTH)

        tk.Label(frame, text="Ustaw nowe Master Password:", font=("Arial", 12)).pack(pady=10)
        self.new_master_password_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.new_master_password_var, show="*", width=30).pack()

        tk.Button(frame, text="Utwórz", command=self._register_master_password).pack(pady=10)

    def _login(self):
        """
        Walidacja hasła głównego, jeśli plik master.json już istnieje.
        """
        master_password = self.master_password_var.get()
        if not master_password:
            messagebox.showerror("Błąd", "Pole Master Password jest puste!")
            return

        master_data = Storage.load_from_file(MASTER_FILE)
        # Wyciągamy salt i klucz
        salt = base64.b64decode(master_data['salt'])
        stored_key = base64.b64decode(master_data['key'])

        temp_manager = PasswordManager(master_password, salt=salt)
        if not temp_manager.verify_master_password(stored_key):
            messagebox.showerror("Błąd", "Niepoprawne hasło główne!")
            return

        # Logowanie pomyślne
        self.manager = temp_manager
        self._clear_window()
        self._create_main_window()

    def _register_master_password(self):
        """
        Pierwsze uruchomienie: tworzenie nowego Master Password i zapisywanie salt + derived key w master.json.
        """
        master_password = self.new_master_password_var.get()
        if not master_password:
            messagebox.showerror("Błąd", "Pole Master Password jest puste!")
            return

        # Tworzymy managera
        self.manager = PasswordManager(master_password)
        # Zapisujemy salt i klucz w base64
        master_data = {
            'salt': base64.b64encode(self.manager.salt).decode(),
            'key': base64.b64encode(self.manager.key).decode()
        }
        Storage.save_to_file(MASTER_FILE, master_data)

        messagebox.showinfo("Sukces", "Hasło główne zostało ustawione!")
        self._clear_window()
        self._create_main_window()

    def _clear_window(self):
        """
        Czyści wszystkie widgety z okna.
        """
        for widget in self.root.winfo_children():
            widget.destroy()

    def _create_main_window(self):
        """
        Okno główne: dodawanie/usuwanie/wyświetlanie haseł.
        """
        self.root.geometry("800x600")

        main_frame = tk.Frame(self.root)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # --- Sekcja dodawania nowego hasła ---
        add_frame = tk.LabelFrame(main_frame, text="Dodaj nowe hasło")
        add_frame.pack(fill=tk.X, pady=5)

        tk.Label(add_frame, text="Nazwa usługi:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        tk.Label(add_frame, text="Login:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        tk.Label(add_frame, text="Hasło (opcjonalnie):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)

        self.service_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        tk.Entry(add_frame, textvariable=self.service_var, width=30).grid(row=0, column=1, padx=5, pady=5)
        tk.Entry(add_frame, textvariable=self.username_var, width=30).grid(row=1, column=1, padx=5, pady=5)
        tk.Entry(add_frame, textvariable=self.password_var, width=30).grid(row=2, column=1, padx=5, pady=5)

        tk.Button(add_frame, text="Dodaj/Generuj", command=self._add_password).grid(row=3, column=0, columnspan=2, pady=5)

        # --- Sekcja wyświetlania i operowania na hasłach ---
        list_frame = tk.LabelFrame(main_frame, text="Zapisane hasła")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = ("service", "username")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        self.tree.heading("service", text="Usługa")
        self.tree.heading("username", text="Login")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscroll=scrollbar.set)

        # --- Przyciski akcji ---
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(anchor=tk.E, pady=5, fill=tk.X)

        tk.Button(btn_frame, text="Odśwież listę", command=self._refresh_list).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Pokaż hasło", command=self._show_password).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Usuń hasło", command=self._delete_password).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Wyjdź", command=self.root.quit).pack(side=tk.RIGHT, padx=5)

        # Na start wypełnij listę
        self._refresh_list()

    def _add_password(self):
        """
        Dodaje nowe hasło (lub generuje) i zapisuje w pliku.
        """
        if not self.manager:
            messagebox.showerror("Błąd", "Brak obiektu managera. Zaloguj się lub ustaw Master Password.")
            return

        service = self.service_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not service:
            messagebox.showerror("Błąd", "Nazwa usługi nie może być pusta!")
            return

        if not username:
            username = "brak"

        # Jeśli nie podano hasła, generujemy je
        if not password:
            password = self.manager.generate_password()

        # Zapis do pliku
        self.manager.save_password(service, username, password)
        messagebox.showinfo("Sukces", f"Hasło dla {service} zostało zapisane.")

        # Czyścimy pola
        self.service_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        self._refresh_list()

    def _refresh_list(self):
        """
        Wczytuje listę usług z folderu 'passwords' i wyświetla w Treeview.
        """
        # Czyścimy Treeview
        for row in self.tree.get_children():
            self.tree.delete(row)

        # Ładujemy wszystkie usługi (bez master.json)
        data = Storage.load_all_services()
        if not data:
            return

        # Wstawiamy do drzewa
        for service_name, info in data.items():
            username = info.get('username', 'brak')
            self.tree.insert("", tk.END, values=(service_name, username))

    def _show_password(self):
        """
        Odszyfrowuje i wyświetla hasło dla zaznaczonej usługi.
        """
        if not self.manager:
            messagebox.showerror("Błąd", "Brak obiektu managera. Zaloguj się lub ustaw Master Password.")
            return

        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Uwaga", "Nie wybrano żadnej usługi.")
            return

        item = self.tree.item(selected_item)
        service_name = item["values"][0]

        result = self.manager.load_password(service_name)
        if result:
            username, plain_password = result
            response = messagebox.askquestion("Hasło", f"Usługa: {service_name}\nLogin: {username}\nHasło: {plain_password}\n\nCzy chcesz skopiować hasło do schowka?")
            if response == 'yes':
                pyperclip.copy(plain_password)
                messagebox.showinfo("Skopiowano", "Hasło zostało skopiowane do schowka.")
        else:
            messagebox.showwarning("Brak", f"Brak danych dla usługi {service_name}.")

    def _delete_password(self):
        """
        Usuwa plik z hasłem dla zaznaczonej usługi.
        """
        if not self.manager:
            messagebox.showerror("Błąd", "Brak obiektu managera. Zaloguj się lub ustaw Master Password.")
            return

        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Uwaga", "Nie wybrano żadnej usługi.")
            return

        item = self.tree.item(selected_item)
        service_name = item["values"][0]

        # Potwierdzenie akcji
        confirm = messagebox.askyesno("Potwierdzenie", f"Czy na pewno chcesz usunąć hasło dla usługi '{service_name}'?")
        if not confirm:
            return

        self.manager.delete_password(service_name)
        messagebox.showinfo("Usunięto", f"Hasło dla usługi {service_name} zostało usunięte.")

        # Odśwież widok
        self._refresh_list()


def run_gui():
    """
    Uruchamia aplikację z interfejsem graficznym.
    """
    root = tk.Tk()
    UI(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
