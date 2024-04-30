#    Smart Password Manager - A Python script that lets you store, view, and delete passwords for different services.
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

# Ambil peralatan yang kita butuhin
import os, time, hashlib, cryptography
from cryptography.fernet import Fernet, InvalidToken
import pickle, random, string
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, BarColumn, TextColumn
import sys

# Tempat nyimpen barang-barangmu
PASSWORDS_FILE = "passwords.dat"
MASTER_PASSWORD_FILE = "master_password.dat"
KEY_FILE = "key.dat"

# Biar konsolnya kece
console = Console()

# Acak-acak password biar aman
def hash_password(password):
    password = password.encode()
    hashed_password = hashlib.sha256(password).hexdigest()
    return hashed_password

# Bikin kunci rahasia
def generate_key():
    return Fernet.generate_key()

# Ambil kuncinya
def load_key():
    with open(KEY_FILE, "rb") as file:
        key = file.read()
    return key

# Kunci rapat-rapat
def encrypt_data(data):
    key = load_key()
    f = Fernet(key)
    data = data.encode()
    encrypted_data = f.encrypt(data)
    return encrypted_data

# Buka kuncinya
def decrypt_data(encrypted_data): 
    key = load_key()
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode()
    except InvalidToken:
        console.print(Panel(
            "[bold red]Waduh, datanya kayaknya error. Kagak bisa dibuka. :worried:[/]", 
            title="[bold red]Gagal Dekripsi", 
            title_align="center",
            padding=(1, 2),
            border_style="red" 
        ), justify="center") 
        pause_and_space()
        return None  

# Bikin password acak, yang random abis
def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(characters) for _ in range(length))
    return password

# Simpan password buat nanti
def save_passwords(passwords):
    with open(PASSWORDS_FILE, "wb") as file:
        pickle.dump(passwords, file)

# Buka password yang udah disimpen
def load_passwords():
    with open(PASSWORDS_FILE, "rb") as file:
        passwords = pickle.load(file)
    return passwords

# Istirahat bentar
def pause_and_space():
    time.sleep(1) 
    print() 

# Bikin master key, bro
def create_master_password():
    os.system('clear')
    time.sleep(1)

    console.print(Panel(
        "[bold green]Selamat datang di Smart Password Manager! :smiley:[/]\n\n" 
        "Aplikasi ini bantuin kamu nyimpen password buat macem-macem akun dengan aman. " 
        "Pertama-tama, kita bikin Master Password yang kuat dulu.\n\n"
        "[bold red]Inget, Master Password ini kunci semua password kamu. " 
        "Kalo lupa, ya wassalam! :fearful:[/]",
        title="[bold blue]Selamat Datang!", 
        title_align="center", 
        padding=(1, 2),
        border_style="bright_blue" 
    ), justify="center") 
    time.sleep(1)

    while True:
        master_password = Prompt.ask("\n[bold yellow]Masukkan Master Password kamu[/]", password=True) 
        pause_and_space()

        if len(master_password) < 8:
            console.print(Panel(
                "[bold red]Passwordnya letoy banget. Minimal 8 karakter dong. :pensive:[/]", 
                title="[bold red]Password Lemah", 
                title_align="center", 
                padding=(1, 2),
                border_style="red" 
            ), justify="center") 
            pause_and_space()
        else:
            confirm_password = Prompt.ask("[bold yellow]Masukkan lagi Master Password-nya, buat mastiin[/]", password=True)
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
                hashed_password = hash_password(master_password)
                with open(MASTER_PASSWORD_FILE, "w") as file:
                    file.write(hashed_password)
                break 
            else:
                console.print(Panel(
                    "[bold red]Password-nya gak cocok. Coba lagi ya. :disappointed:[/]", 
                    title="[bold red]Gak Cocok", 
                    title_align="center", 
                    padding=(1, 2),
                    border_style="red" 
                ), justify="center")
                pause_and_space()

# Cek apakah kuncinya bener
def verify_master_password():
    with open(MASTER_PASSWORD_FILE, "r") as file:
        hashed_password = file.read()
    master_password = Prompt.ask("[bold yellow]Masukkan Master Password kamu[/]", password=True) 
    pause_and_space()
    if hash_password(master_password) == hashed_password:
        console.print(Panel(
            "[bold green]Master Password bener. :thumbsup:[/]", 
            title="[bold green]Akses Diberikan!", 
            title_align="center",
            padding=(1, 2),
            border_style="green"
        ), justify="center") 
        pause_and_space()
        return True 
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

# Tambahin password baru ke brankas
def add_password():
    passwords = load_passwords()

    try:
        service = Prompt.ask("[bold yellow]Password ini buat situs apa?[/]") 
        pause_and_space() 
        if not service.strip():
            raise ValueError("Nama situs gak boleh kosong.") 

        if service in passwords:
            console.print(Panel(
                f"[bold red]Kamu udah punya password buat [bold underline red]{service}[/]. :open_mouth:[/]\n\n" 
                f"[bold red]Password kamu buat [bold underline red]{service}[/] adalah [bold underline red]{decrypt_data(passwords[service]).split('|')[0]}[/] :key:[/]\n\n"
                "[bold red]Hapus dulu kalo mau ganti. :pray:[/]", 
                title="[bold red]Situs Udah Ada", 
                title_align="center", 
                padding=(1, 2),
                border_style="red" 
            ), justify="center") 
            pause_and_space() 
        else:
            create_random = Confirm.ask("[bold yellow]Mau dibuatin password acak?[/]")
            pause_and_space()  
            if create_random:
                length = Prompt.ask("[bold yellow]Mau berapa karakter? (8-32 karakter)[/]", console=console) 
                pause_and_space() 
                try:  
                    length = int(length)
                    if 8 <= length <= 32: 
                        password = generate_password(length)
                        console.print(Panel(
                            f"[bold green]Password acak kamu buat [bold underline green]{service}[/] adalah [bold underline green]{password}[/] :game_die:[/]", 
                            title="[bold green]Password Dibuat!", 
                            title_align="center", 
                            padding=(1, 2),
                            border_style="green" 
                        ), justify="center")  
                        pause_and_space() 
                        # Enkripsi timestamp bareng password
                        timestamp_str = time.strftime("%H:%M:%S %Y-%m-%d") 
                        combined_data = password + "|" + timestamp_str  
                        encrypted_data = encrypt_data(combined_data)  

                        passwords[service] = encrypted_data
                        save_passwords(passwords)
                    else:
                        console.print(Panel(
                            "[bold red]Password harus antara 8 dan 32 karakter. :pensive:[/]", 
                            title="[bold red]Panjang Gak Valid", 
                            title_align="center", 
                            padding=(1, 2),
                            border_style="red"
                        ), justify="center") 
                        pause_and_space() 
                        return 
                except ValueError:
                    console.print(Panel(
                        "[bold red]Input-nya gak bener. Masukin angka antara 8 dan 32. :pensive:[/]", 
                        title="[bold red]Input Gak Valid", 
                        title_align="center", 
                        padding=(1, 2),
                        border_style="red" 
                    ), justify="center") 
                    pause_and_space() 
                    return 
            else: 
                try:  
                    password = Prompt.ask("[bold yellow]Masukkan password kamu buat situs ini[/]", password=True) 
                    pause_and_space()  
                    if not password.strip():
                        raise ValueError("Password gak boleh kosong.") 

                    # Gabungin password sama timestamp sebelum dienkripsi
                    timestamp_str = time.strftime("%H:%M:%S %Y-%m-%d") 
                    combined_data = password + "|" + timestamp_str 
                    encrypted_data = encrypt_data(combined_data) 

                    passwords[service] = encrypted_data  
                    save_passwords(passwords)
                    console.print(Panel(
                        f"[bold green]Password buat [bold underline green]{service}[/] berhasil disimpan! :raised_hands:[/]", 
                        title="[bold green]Password Disimpan!", 
                        title_align="center", 
                        padding=(1, 2),
                        border_style="green" 
                    ), justify="center") 
                    pause_and_space() 
                except ValueError as e:
                    console.print(Panel(
                        f"[bold red]{e}[/]", 
                        title="[bold red]Input Gak Valid", 
                        title_align="center",
                        padding=(1, 2),
                        border_style="red"
                    ), justify="center") 
                    pause_and_space() 
    except ValueError as e:
        console.print(Panel(
            f"[bold red]{e}[/]", 
            title="[bold red]Input Gak Valid", 
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center") 
        pause_and_space() 

# Intip password yang udah disimpen
def view_passwords(): 
    passwords = load_passwords()
    if passwords:
        table = Table(title="Password yang Udah Disimpen :memo:", title_style="bold magenta") 
        table.add_column("No.", style="cyan", justify="center") 
        table.add_column("Situs", style="cyan", justify="center") 
        table.add_column("Password", style="magenta", justify="center") 
        table.add_column("Ditambah Pada", style="green", justify="center")  
        for i, (service, encrypted_data) in enumerate(passwords.items(), 1):
            decrypted_data = decrypt_data(encrypted_data) 
            if decrypted_data:
                password, timestamp = decrypted_data.split("|")  
                table.add_row(str(i), service, password, timestamp) 
        console.print(table, justify="center") 
        pause_and_space() 
    else:
        console.print(Panel(
            "[bold red]Kayaknya kamu belum nyimpen password. :crying_face:[/]", 
            title="[bold red]Gak Ada Password", 
            title_align="center", 
            padding=(1, 2),
            border_style="red" 
        ), justify="center") 
        pause_and_space() 

# Saatnya buang beberapa password
def delete_passwords(): 
    passwords = load_passwords()
    if passwords:
        table = Table(title="Password yang Udah Disimpen :memo:", title_style="bold magenta") 
        table.add_column("No.", style="cyan", justify="center") 
        table.add_column("Situs", style="cyan", justify="center") 
        table.add_column("Password", style="magenta", justify="center") 
        table.add_column("Ditambah Pada", style="green", justify="center")  
        for i, (service, encrypted_data) in enumerate(passwords.items(), 1):
            decrypted_data = decrypt_data(encrypted_data) 
            if decrypted_data:
                password, timestamp = decrypted_data.split("|") 
                table.add_row(str(i), service, password, timestamp) 
        console.print(table, justify="center") 
        pause_and_space() 

        choice = Prompt.ask("[bold yellow]Masukin nomor password yang mau dibuang (pisahin pake koma)[/]") 
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
                    title="[bold red]Input Gak Valid", 
                    title_align="center", 
                    padding=(1, 2),
                    border_style="red" 
                ), justify="center") 
                pause_and_space() 
                return  

        confirm = Confirm.ask(f"[bold yellow]Yakin mau buang password buat [bold yellow]{', '.join([f'[bold underline yellow]{service}[/]' for service in services])}[/]?[/]")
        pause_and_space() 
        if confirm:
            for service in services:
                passwords.pop(service) 
            save_passwords(passwords)
            console.print(Panel(
                f"[bold green]Password buat [bold green]{', '.join([f'[bold underline green]{service}[/]' for service in services])}[/] berhasil dibuang! :wastebasket:[/]", 
                title="[bold green]Password Dihapus", 
                title_align="center", 
                padding=(1, 2),
                border_style="green" 
            ), justify="center") 
            pause_and_space() 
        else:
            console.print(Panel(
                "[bold green]Santay, pembuangan dibatalin. :relieved:[/]", 
                title="[bold green]Pembatalan Sukses", 
                title_align="center", 
                padding=(1, 2),
                border_style="green" 
            ), justify="center") 
            pause_and_space() 
    else:
        console.print(Panel(
            "[bold red]Kayaknya kamu belum nyimpen password. :crying_face:[/]", 
            title="[bold red]Gak Ada Password", 
            title_align="center", 
            padding=(1, 2),
            border_style="red" 
        ), justify="center") 
        pause_and_space() 

def main():
    # Gaskeun!
    os.system('clear')
    time.sleep(1)
    if not os.path.exists(MASTER_PASSWORD_FILE):
        # Baru pertama kali? Bikin master password dulu!
        create_master_password() 
        key = generate_key() 
        with open(KEY_FILE, "wb") as file:
            file.write(key) 
        passwords = {} 
        save_passwords(passwords) 

    while True:
        console.print(Panel(
            "[bold green]Selamat datang di Smart Password Manager! :smiley:[/]\n\n" 
            "[bold]Mau ngapain nih?[/]", 
            title="[bold blue]Menu Utama", 
            title_align="center", 
            padding=(1, 2),
            border_style="bright_blue" 
        ), justify="center") 
        pause_and_space() 

        console.print("[1] Simpan password baru") 
        console.print("[2] Lihat password yang udah disimpen") 
        console.print("[3] Buang password") 
        console.print("[4] Cabut")
        pause_and_space() 

        choice = Prompt.ask("\n[bold yellow]Pilih nomornya[/]", choices=["1", "2", "3", "4"])
        pause_and_space() 
        if choice == "1":
            if verify_master_password():
                add_password() 
        elif choice == "2":
            if verify_master_password():
                view_passwords() 
        elif choice == "3":
            if verify_master_password():
                delete_passwords() 
        elif choice == "4":
            console.print(Panel(
                "[bold]Oke, makasih udah pake Smart Password Manager! :smiley:[/]\n\n" 
                "[bold]Semoga harimu menyenangkan! :wave:[/]", 
                title="[bold magenta]Sampai Jumpa!", 
                title_align="center", 
                padding=(1, 2),
                border_style="magenta" 
            ), justify="center") 
            pause_and_space()
            break  
        console.input("[bold blue]Tekan Enter buat lanjut...[/]") 
        os.system('clear')  
        pause_and_space() 

# Jalankan fungsi utama
if __name__ == "__main__":
    main()
