#    Smart Password Manager - Skrip Python yang memungkinkan lo buat nyimpen, liat, dan hapus password buat layanan beda.
#    Copyright (C) 2023-2024 TheRebo
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

# ——— Import Modul ———
import os
import time
import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import pickle
import secrets
import string
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, BarColumn, TextColumn
import sys
import json

# ——— Deklarasi Konstanta ———
PASSWORDS_FILE = "passwords.dat"
MASTER_PASSWORD_FILE = "master_password.dat"
KEY_FILE = "key.dat"
SALT_FILE = "salt.dat"

# Inisialisasi konsol rich
console = Console()

# ——— Definisi Fungsi ———
def hash_password(password, salt):
    """Hash password pake SHA-512 dengan salt."""
    password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    hashed_password = base64.urlsafe_b64encode(kdf.derive(password))
    return hashed_password

def generate_salt():
    """Generate salt random 32-byte."""
    return secrets.token_bytes(32)

def save_salt(salt):
    """Simpan salt ke file."""
    with open(SALT_FILE, "wb") as file:
        file.write(salt)

def load_salt():
    """Load salt dari file."""
    with open(SALT_FILE, "rb") as file:
        salt = file.read()
    return salt

def generate_key(master_password, salt):
    """Generate kunci AES 256-bit dari master password pake PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def load_key(master_password):
    """Load kunci enkripsi dari file, generate kalau perlu."""
    if not os.path.exists(KEY_FILE):
        if not os.path.exists(SALT_FILE):
            salt = generate_salt()
            save_salt(salt)
        else:
            salt = load_salt()
        key = generate_key(master_password, salt)
        with open(KEY_FILE, "wb") as file:
            file.write(key)
    else:
        with open(KEY_FILE, "rb") as file:
            key = file.read()
    return key

def encrypt_data(data, key):
    """Enkripsi data pake Fernet."""
    f = Fernet(key)
    if not isinstance(data, bytes):
        data = data.encode()
    encrypted_data = f.encrypt(data)
    return encrypted_data

def decrypt_data(encrypted_data, key):
    """Dekripsi data pake Fernet dengan error handling."""
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data
    except InvalidToken:
        console.print(Panel(
            "[bold red]Error: Token data nggak valid. Dekripsi gagal. :worried:[/]",
            title="[bold red]Dekripsi Error",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()
        return None

def generate_password(length):
    """Generate password random pake secrets."""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(characters) for _ in range(length))
    return password

def save_passwords(passwords, key):
    """Simpan dictionary passwords ke file setelah enkripsi."""
    with open(PASSWORDS_FILE, "wb") as file:
        pickled_data = pickle.dumps(passwords)
        encrypted_data = encrypt_data(pickled_data, key)
        file.write(encrypted_data)

def load_passwords(key):
    """Load dictionary passwords dari file setelah dekripsi."""
    with open(PASSWORDS_FILE, "rb") as file:
        encrypted_data = file.read()
        decrypted_data = decrypt_data(encrypted_data, key)
        if decrypted_data is not None:
            passwords = pickle.loads(decrypted_data)
            return passwords
        else:
            return {}

def pause_and_space():
    """Tambah jeda dan spasi buat readability lebih baik."""
    time.sleep(1)
    print()

def create_master_password():
    """Buat dan simpan hash master password."""
    os.system('clear')
    time.sleep(1)

    console.print(Panel(
        "[bold green]Selamat datang di Smart Password Manager! :smiley:[/]\n\n"
        "Skrip ini memungkinkan lo buat nyimpen, liat, dan manage password lo buat layanan berbeda secara aman. "
        "Buat mulai, lo perlu buat Master Password yang kuat.\n\n"
        "[bold red]Inget, Master Password lo adalah kunci buat semua password yang lo simpan. "
        "Nggak ada cara buat recover kalau lo lupa! :fearful:[/]",
        title="[bold blue]Selamat Datang!",
        title_align="center",
        padding=(1, 2),
        border_style="bright_blue"
    ), justify="center")
    time.sleep(1)

    salt = generate_salt()
    while True:
        master_password = Prompt.ask("\n[bold yellow]Masukkan Master Password[/]", password=True)
        pause_and_space()

        if len(master_password) < 8:
            console.print(Panel(
                "[bold red]Master Password terlalu lemah. Harus minimal 8 karakter. :pensive:[/]",
                title="[bold red]Password Lemah",
                title_align="center",
                padding=(1, 2),
                border_style="red"
            ), justify="center")
            pause_and_space()
        else:
            confirm_password = Prompt.ask("[bold yellow]Konfirmasi Master Password[/]", password=True)
            pause_and_space()
            if master_password == confirm_password:
                console.print(Panel(
                    "[bold green]Master Password berhasil dibuat! :tada:[/]",
                    title="[bold green]Sukses!",
                    title_align="center",
                    padding=(1, 2),
                    border_style="green"
                ), justify="center")
                pause_and_space()
                hashed_password = hash_password(master_password, salt)
                with open(MASTER_PASSWORD_FILE, "wb") as file:
                    file.write(hashed_password)
                save_salt(salt)
                break
            else:
                console.print(Panel(
                    "[bold red]Password nggak sama. Coba lagi. :disappointed:[/]",
                    title="[bold red]Nggak Sama",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red"
                ), justify="center")
                pause_and_space()

def verify_master_password():
    """Verifikasi master password dengan hash tersimpan."""
    with open(MASTER_PASSWORD_FILE, "rb") as file:
        hashed_password = file.read()
    master_password = Prompt.ask("[bold yellow]Masukkan Master Password[/]", password=True)
    pause_and_space()
    salt = load_salt()
    if hash_password(master_password, salt) == hashed_password:
        console.print(Panel(
            "[bold green]Master Password benar. :thumbsup:[/]",
            title="[bold green]Akses Diberikan!",
            title_align="center",
            padding=(1, 2),
            border_style="green"
        ), justify="center")
        pause_and_space()
        return master_password
    else:
        console.print(Panel(
            "[bold red]Master Password salah. :worried:[/]",
            title="[bold red]Password Salah",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()
        return False

def add_password(key):
    """Tambah password baru ke penyimpanan terenkripsi."""
    passwords = load_passwords(key)

    try:
        service = Prompt.ask("[bold yellow]Masukkan nama layanan[/]")
        pause_and_space()
        if not service.strip():
            raise ValueError("Nama layanan nggak boleh kosong.")

        if service in passwords:
            console.print(Panel(
                f"[bold red]Lo udah punya password buat [bold underline red]{service}[/]. :open_mouth:[/]\n\n"
                f"[bold red]Password lo buat [bold underline red]{service}[/] adalah [bold underline red]{decrypt_data(passwords[service], key).split('|')[0]}[/] :key:[/]\n\n"
                "[bold red]Hapus dulu kalau lo mau ganti. :pray:[/]",
                title="[bold red]Entri Duplikat",
                title_align="center",
                padding=(1, 2),
                border_style="red"
            ), justify="center")
            pause_and_space()
        else:
            create_random = Confirm.ask("[bold yellow]Buat password random?[/]")
            pause_and_space()
            if create_random:
                length = Prompt.ask("[bold yellow]Masukkan panjang password (8-32)[/]", console=console)
                pause_and_space()
                try:
                    length = int(length)
                    if 8 <= length <= 32:
                        password = generate_password(length)
                        console.print(Panel(
                            f"[bold green]Password random lo buat [bold underline green]{service}[/] adalah [bold underline green]{password}[/] :game_die:[/]",
                            title="[bold green]Password Dihasilkan!",
                            title_align="center",
                            padding=(1, 2),
                            border_style="green"
                        ), justify="center")
                        pause_and_space()
                        timestamp_str = time.strftime("%H:%M:%S %Y-%m-%d")
                        combined_data = json.dumps({"password": password, "timestamp": timestamp_str})
                        encrypted_data = encrypt_data(combined_data, key)

                        passwords[service] = encrypted_data
                        save_passwords(passwords, key)
                    else:
                        console.print(Panel(
                            "[bold red]Panjang password harus antara 8 dan 32. :pensive:[/]",
                            title="[bold red]Panjang Nggak Valid",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red"
                        ), justify="center")
                        pause_and_space()
                        return
                except ValueError:
                    console.print(Panel(
                        "[bold red]Input panjang password nggak valid. Masukkan angka antara 8 dan 32. :pensive:[/]",
                        title="[bold red]Input Nggak Valid",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red"
                    ), justify="center")
                    pause_and_space()
                    return
            else:
                try:
                    password = Prompt.ask("[bold yellow]Masukkan password lo buat layanan ini[/]", password=True)
                    pause_and_space()
                    if not password.strip():
                        raise ValueError("Password nggak boleh kosong.")

                    timestamp_str = time.strftime("%H:%M:%S %Y-%m-%d")
                    combined_data = json.dumps({"password": password, "timestamp": timestamp_str})
                    encrypted_data = encrypt_data(combined_data, key)

                    passwords[service] = encrypted_data
                    save_passwords(passwords, key)
                    console.print(Panel(
                        f"[bold green]Password buat [bold underline green]{service}[/] berhasil disimpan! :raised_hands:[/]",
                        title="[bold green]Password Tersimpan!",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green"
                    ), justify="center")
                    pause_and_space()
                except ValueError as e:
                    console.print(Panel(
                        f"[bold red]{e}[/]",
                        title="[bold red]Input Nggak Valid",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red"
                    ), justify="center")
                    pause_and_space()
    except ValueError as e:
        console.print(Panel(
            f"[bold red]{e}[/]",
            title="[bold red]Input Nggak Valid",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()

def view_passwords(key):
    """Liat password tersimpan dalam tabel terformat."""
    passwords = load_passwords(key)
    if passwords:
        table = Table(title="Password Tersimpan Lo :memo:", title_style="bold magenta")
        table.add_column("No.", style="cyan", justify="center")
        table.add_column("Layanan", style="cyan", justify="center")
        table.add_column("Password", style="magenta", justify="center")
        table.add_column("Ditambahkan Pada", style="green", justify="center")
        for i, (service, encrypted_data) in enumerate(passwords.items(), 1):
            decrypted_data = decrypt_data(encrypted_data, key)
            if decrypted_data:
                decrypted_string = decrypted_data.decode('utf-8')
                data = json.loads(decrypted_string)
                password = data.get("password")
                timestamp = data.get("timestamp")
                table.add_row(str(i), service, password, timestamp)
        console.print(table, justify="center")
        pause_and_space()
    else:
        console.print(Panel(
            "[bold red]Lo nggak punya password tersimpan. :crying_face:[/]",
            title="[bold red]Nggak Ada Password",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()

def delete_passwords(key):
    """Hapus password terpilih dari penyimpanan terenkripsi."""
    passwords = load_passwords(key)
    if passwords:
        table = Table(title="Password Tersimpan Lo :memo:", title_style="bold magenta")
        table.add_column("No.", style="cyan", justify="center")
        table.add_column("Layanan", style="cyan", justify="center")
        table.add_column("Password", style="magenta", justify="center")
        table.add_column("Ditambahkan Pada", style="green", justify="center")
        for i, (service, encrypted_data) in enumerate(passwords.items(), 1):
            decrypted_data = decrypt_data(encrypted_data, key)
            if decrypted_data:
                decrypted_string = decrypted_data.decode('utf-8')
                data = json.loads(decrypted_string)
                password = data.get("password")
                timestamp = data.get("timestamp")
                table.add_row(str(i), service, password, timestamp)
        console.print(table, justify="center")
        pause_and_space()

        choice = Prompt.ask("[bold yellow]Masukkan nomor password untuk dihapus (pisahkan dengan koma)[/]")
        pause_and_space()
        numbers = choice.split(",")
        services = []
        for number in numbers:
            try:
                number = int(number)
                service = list(passwords.keys())[number - 1]
                services.append(service)
            except:
                console.print(Panel(
                    f"[bold underline red]{number}[/] [bold red]bukan nomor yang valid.[/] :pensive:",
                    title="[bold red]Input Nggak Valid",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red"
                ), justify="center")
                pause_and_space()
                return

        confirm = Confirm.ask(
            f"[bold yellow]Hapus password buat [bold yellow]{', '.join([f'[bold underline yellow]{service}[/]' for service in services])}[/]?[/]")
        pause_and_space()
        if confirm:
            for service in services:
                passwords.pop(service)
            save_passwords(passwords, key)
            console.print(Panel(
                f"[bold green]Password buat [bold green]{', '.join([f'[bold underline green]{service}[/]' for service in services])}[/] berhasil dihapus! :wastebasket:[/]",
                title="[bold green]Password Dihapus",
                title_align="center",
                padding=(1, 2),
                border_style="green"
            ), justify="center")
            pause_and_space()
        else:
            console.print(Panel(
                "[bold green]Penghapusan dibatalkan. :relieved:[/]",
                title="[bold green]Penghapusan Dibatalkan",
                title_align="center",
                padding=(1, 2),
                border_style="green"
            ), justify="center")
            pause_and_space()
    else:
        console.print(Panel(
            "[bold red]Lo nggak punya password tersimpan. :crying_face:[/]",
            title="[bold red]Nggak Ada Password",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()

def reset_data(key):
    """Reset data berdasarkan pilihan user."""
    while True:
        console.print(Panel(
            "[bold red]PERINGATAN: Aksi ini akan menghapus data secara permanen! :warning:[/]\n\n"
            "[bold]Pilih opsi reset:[/]",
            title="[bold red]Reset Data",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()

        console.print("[1] Reset SEMUA Password")
        console.print("[2] Reset SEMUA Data (Password, Master Password, Kunci)")
        console.print("[3] Batalkan Reset")
        pause_and_space()

        choice = Prompt.ask("\n[bold red]Masukkan pilihan (1-3)[/]", choices=["1", "2", "3"])
        pause_and_space()

        if choice == "1" or choice == "2":
            console.print(Panel(
                "[bold red]BAHAYA! Aksi ini nggak bisa dibalik. Data yang dihapus nggak bisa dipulihkan! :skull:[/]\n\n"
                "[bold red]Lo yakin banget mau lanjut?[/]",
                title="[bold red]Peringatan Terakhir",
                title_align="center",
                padding=(1, 2),
                border_style="red"
            ), justify="center")
            pause_and_space()

            if Confirm.ask("[bold red]Konfirmasi Reset Data?[/]"):
                pause_and_space()
                master_password = Prompt.ask("[bold red]Masukkan Master Password untuk konfirmasi[/]", password=True)
                pause_and_space()
                salt = load_salt()

                with open(MASTER_PASSWORD_FILE, "rb") as file:
                    stored_hashed_password = file.read() 

                if hash_password(master_password, salt) == stored_hashed_password:
                    if choice == "1":
                        passwords = {}
                        save_passwords(passwords, key)
                        console.print(Panel(
                            "[bold red]Semua password telah direset. :fire:[/]",
                            title="[bold red]Password Direset",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red"
                        ), justify="center")
                        pause_and_space()
                        break
                    elif choice == "2":
                        for filename in [PASSWORDS_FILE, MASTER_PASSWORD_FILE, KEY_FILE, SALT_FILE]:
                            if os.path.exists(filename):
                                os.remove(filename)
                        console.print(Panel(
                            "[bold red]Semua data telah direset. Program seperti baru saja diinstal. :fire:[/]",
                            title="[bold red]Data Direset",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red"
                        ), justify="center")
                        pause_and_space()
                        sys.exit(0)
                else:
                    console.print(Panel(
                        "[bold red]Master Password salah. Operasi reset dibatalkan. :no_entry_sign:[/]",
                        title="[bold red]Password Salah",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red"
                    ), justify="center")
                    pause_and_space()
            else:
                pause_and_space()
                console.print(Panel(
                    "[bold green]Operasi reset dibatalkan. :relieved:[/]",
                    title="[bold green]Reset Dibatalkan",
                    title_align="center",
                    padding=(1, 2),
                    border_style="green"
                ), justify="center")
                pause_and_space()
                break
        elif choice == "3":
            console.print(Panel(
                "[bold green]Operasi reset dibatalkan. :relieved:[/]",
                title="[bold green]Reset Dibatalkan",
                title_align="center",
                padding=(1, 2),
                border_style="green"
            ), justify="center")
            pause_and_space()
            break

def change_master_password(key):
    """Ganti master password."""
    console.print(Panel(
        "[bold yellow]Mengganti Master Password lo...[/]\n\n"
        "[bold red]Inget, ini operasi krusial. Pastikan lo ingat Master Password baru lo![/]",
        title="[bold yellow]Ganti Master Password",
        title_align="center",
        padding=(1, 2),
        border_style="yellow"
    ), justify="center")
    pause_and_space()

    while True:
        old_master_password = Prompt.ask("[bold yellow]Masukkan Master Password lama[/]", password=True)
        pause_and_space()
        salt = load_salt()

        with open(MASTER_PASSWORD_FILE, "rb") as file:
            stored_hashed_password = file.read() 

        if hash_password(old_master_password, salt) == stored_hashed_password: 
            new_master_password = Prompt.ask("\n[bold yellow]Masukkan Master Password baru[/]", password=True)
            pause_and_space()

            if len(new_master_password) < 8:
                console.print(Panel(
                    "[bold red]Master Password baru terlalu lemah. Harus minimal 8 karakter. :pensive:[/]",
                    title="[bold red]Password Lemah",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red"
                ), justify="center")
                pause_and_space()
            else:
                confirm_password = Prompt.ask("[bold yellow]Konfirmasi Master Password baru[/]", password=True)
                pause_and_space()
                if new_master_password == confirm_password:
                    console.print(Panel(
                        "[bold green]Master Password berhasil diganti! :tada:[/]",
                        title="[bold green]Sukses!",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green"
                    ), justify="center")
                    pause_and_space()
                    new_hashed_password = hash_password(new_master_password, salt)
                    with open(MASTER_PASSWORD_FILE, "wb") as file:
                        file.write(new_hashed_password)
                    new_key = generate_key(new_master_password, salt)
                    with open(KEY_FILE, "wb") as file:
                        file.write(new_key)
                    passwords = load_passwords(key)
                    save_passwords(passwords, new_key)
                    break
                else:
                    console.print(Panel(
                        "[bold red]Password nggak sama. Coba lagi. :disappointed:[/]",
                        title="[bold red]Nggak Sama",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red"
                    ), justify="center")
                    pause_and_space()
        else:
            console.print(Panel(
                "[bold red]Master Password lama salah. Operasi ganti dibatalkan. :no_entry_sign:[/]",
                title="[bold red]Password Salah",
                title_align="center",
                padding=(1, 2),
                border_style="red"
            ), justify="center")
            pause_and_space()
            break

# ——— Fungsi Utama ———
def main():
    """Fungsi utama buat Password Manager."""
    os.system('clear')
    time.sleep(1)

    # Setup Master Password
    if not os.path.exists(MASTER_PASSWORD_FILE):
        create_master_password()

    # Verifikasi Master Password tiap dijalankan
    master_password = verify_master_password()
    if not master_password:
        return
    key = load_key(master_password)

    # Penyimpanan Password awal
    if not os.path.exists(PASSWORDS_FILE):
        passwords = {}
        save_passwords(passwords, key)

    while True:
        console.print(Panel(
            "[bold green]Selamat datang di Smart Password Manager! :smiley:[/]\n\n"
            "[bold]Mau ngapain?[/]",
            title="[bold blue]Menu Utama",
            title_align="center",
            padding=(1, 2),
            border_style="bright_blue"
        ), justify="center")
        pause_and_space()

        console.print("[1] Tambah password baru")
        console.print("[2] Liat password tersimpan")
        console.print("[3] Hapus password")
        console.print("[4] Ganti Master Password")
        console.print("[5] Reset Data")
        console.print("[6] Keluar")
        pause_and_space()

        choice = Prompt.ask("\n[bold yellow]Masukkan pilihan (1-6)[/]", choices=["1", "2", "3", "4", "5", "6"])
        pause_and_space()

        if choice == "1":
            add_password(key)
        elif choice == "2":
            view_passwords(key)
        elif choice == "3":
            delete_passwords(key)
        elif choice == "4":
            change_master_password(key)
        elif choice == "5":
            reset_data(key)
        elif choice == "6":
            console.print(Panel(
                "[bold]Makasih udah pake Smart Password Manager! :smiley:[/]\n\n"
                "[bold]Semoga harimu menyenangkan! :wave:[/]",
                title="[bold magenta]Sampai Jumpa!",
                title_align="center",
                padding=(1, 2),
                border_style="magenta"
            ), justify="center")
            pause_and_space()
            break

        console.input("[bold blue]Tekan Enter untuk lanjut...[/]")
        os.system('clear')
        pause_and_space()

# Jalankan fungsi utama
if __name__ == "__main__":
    main()
