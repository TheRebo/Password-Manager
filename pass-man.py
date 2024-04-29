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

# Import the modules we need
import os
import time
import hashlib
import cryptography
from cryptography.fernet import Fernet, InvalidToken
import pickle
import random
import string
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, BarColumn, TextColumn
import sys

# Define some constants
PASSWORDS_FILE = "passwords.dat"
MASTER_PASSWORD_FILE = "master_password.dat"
KEY_FILE = "key.dat"

# Initialize rich console
console = Console()

# Define some functions
def hash_password(password):
    # Hash password using SHA-256
    password = password.encode()
    hashed_password = hashlib.sha256(password).hexdigest()
    return hashed_password

def generate_key():
    # Generate a random encryption key
    return Fernet.generate_key()

def load_key():
    # Load the encryption key from file
    with open(KEY_FILE, "rb") as file:
        key = file.read()
    return key

def encrypt_data(data):  # Function now encrypts combined data
    key = load_key()
    f = Fernet(key)
    data = data.encode()
    encrypted_data = f.encrypt(data)
    return encrypted_data

def decrypt_data(encrypted_data): 
    # Decrypt data using Fernet with error handling
    key = load_key()
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data.decode()
    except InvalidToken:
        console.print(Panel(
            "[bold red]Error: Invalid data token. Decryption failed. :worried:[/]",
            title="[bold red]Decryption Error",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()
        return None  # or raise an exception for further handling

def generate_password(length):
    # Generate a random password
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(random.choice(characters) for _ in range(length))
    return password

def save_passwords(passwords):
    # Save passwords dictionary to file
    with open(PASSWORDS_FILE, "wb") as file:
        pickle.dump(passwords, file)

def load_passwords():
    # Load passwords dictionary from file
    with open(PASSWORDS_FILE, "rb") as file:
        passwords = pickle.load(file)
    return passwords

# Define a function to add pauses and spacing
def pause_and_space():
    time.sleep(1)  # Introduce a one-second pause
    print()  # Add a blank line for spacing

def create_master_password():
    # Create and save master password
    os.system('clear')
    time.sleep(1)

    console.print(Panel(
        "[bold green]Welcome to the Smart Password Manager! :smiley:[/]\n\n"
        "This script lets you securely store, view, and manage your passwords for different services. "
        "To get started, you'll need to create a strong Master Password.\n\n"
        "[bold red]Remember, your Master Password is the key to all your stored passwords. "
        "There's no way to recover it if you forget it! :fearful:[/]",
        title="[bold blue]Welcome!",
        title_align="center",
        padding=(1, 2),
        border_style="bright_blue"
    ), justify="center")
    time.sleep(1)

    while True:
        master_password = Prompt.ask("\n[bold yellow]Enter your Master Password[/]", password=True)
        pause_and_space()

        if len(master_password) < 8:
            console.print(Panel(
                "[bold red]Master Password is too weak. It should be at least 8 characters long. :pensive:[/]",
                title="[bold red]Weak Password",
                title_align="center",
                padding=(1, 2),
                border_style="red"
            ), justify="center")
            pause_and_space()
        else:
            confirm_password = Prompt.ask("[bold yellow]Confirm your Master Password[/]", password=True)
            pause_and_space()
            if master_password == confirm_password:
                console.print(Panel(
                    "[bold green]Master Password created successfully! :tada:[/]",
                    title="[bold green]Success!",
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
                    "[bold red]Passwords don't match. Please try again. :disappointed:[/]",
                    title="[bold red]Mismatch",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red"
                ), justify="center")
                pause_and_space()

def verify_master_password():
    # Verify master password
    with open(MASTER_PASSWORD_FILE, "r") as file:
        hashed_password = file.read()
    master_password = Prompt.ask("[bold yellow]Enter your Master Password[/]", password=True)
    pause_and_space()
    if hash_password(master_password) == hashed_password:
        console.print(Panel(
            "[bold green]Master Password is correct. :thumbsup:[/]",
            title="[bold green]Access Granted!",
            title_align="center",
            padding=(1, 2),
            border_style="green"
        ), justify="center")
        pause_and_space()
        return True
    else:
        console.print(Panel(
            "[bold red]Master Password is wrong. :worried:[/]",
            title="[bold red]Incorrect Password",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()
        return False

def add_password():
    # Add a new password 
    passwords = load_passwords()

    try:
        service = Prompt.ask("[bold yellow]Enter the name of the service[/]")
        pause_and_space()
        if not service.strip():
            raise ValueError("Service name cannot be blank.")

        if service in passwords:
            console.print(Panel(
                f"[bold red]You already have a password for [bold underline red]{service}[/]. :open_mouth:[/]\n\n" 
                f"[bold red]Your password for [bold underline red]{service}[/] is [bold underline red]{decrypt_data(passwords[service]).split('|')[0]}[/] :key:[/]\n\n"
                "[bold red]Delete it first if you want to change it. :pray:[/]",
                title="[bold red]Duplicate Entry",
                title_align="center", 
                padding=(1, 2),
                border_style="red" 
            ), justify="center") 
            pause_and_space()
        else:
            create_random = Confirm.ask("[bold yellow]Create a random password?[/]")
            pause_and_space()  
            if create_random:
                length = Prompt.ask("[bold yellow]Enter the length of the password (8-32)[/]", console=console)
                pause_and_space() 
                try:  
                    length = int(length)
                    if 8 <= length <= 32: 
                        password = generate_password(length)
                        console.print(Panel(
                            f"[bold green]Your random password for [bold underline green]{service}[/] is [bold underline green]{password}[/] :game_die:[/]", 
                            title="[bold green]Password Generated!",
                            title_align="center", 
                            padding=(1, 2),
                            border_style="green" 
                        ), justify="center")  
                        pause_and_space()
                        # Encrypt the timestamp along with the password
                        timestamp_str = time.strftime("%H:%M:%S %Y-%m-%d")
                        combined_data = password + "|" + timestamp_str  
                        encrypted_data = encrypt_data(combined_data)  

                        passwords[service] = encrypted_data
                        save_passwords(passwords)
                    else:
                        console.print(Panel(
                            "[bold red]Password length should be between 8 and 32. :pensive:[/]",
                            title="[bold red]Invalid Length", 
                            title_align="center", 
                            padding=(1, 2),
                            border_style="red"
                        ), justify="center") 
                        pause_and_space()
                        return 
                except ValueError:
                    console.print(Panel(
                        "[bold red]Invalid input for password length. Please enter a number between 8 and 32. :pensive:[/]", 
                        title="[bold red]Invalid Input", 
                        title_align="center", 
                        padding=(1, 2),
                        border_style="red"
                    ), justify="center")
                    pause_and_space()
                    return 
            else: 
                try:  
                    password = Prompt.ask("[bold yellow]Enter your password for this service[/]", password=True)
                    pause_and_space()  
                    if not password.strip():
                        raise ValueError("Password cannot be blank.")

                    # Combine password and timestamp before encryption
                    timestamp_str = time.strftime("%H:%M:%S %Y-%m-%d")
                    combined_data = password + "|" + timestamp_str 
                    encrypted_data = encrypt_data(combined_data)

                    passwords[service] = encrypted_data  # Store combined data
                    save_passwords(passwords)
                    console.print(Panel(
                        f"[bold green]Password for [bold underline green]{service}[/] saved successfully! :raised_hands:[/]",
                        title="[bold green]Password Saved!",
                        title_align="center", 
                        padding=(1, 2),
                        border_style="green" 
                    ), justify="center") 
                    pause_and_space() 
                except ValueError as e:
                    console.print(Panel(
                        f"[bold red]{e}[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red"
                    ), justify="center")
                    pause_and_space()
    except ValueError as e:
        console.print(Panel(
            f"[bold red]{e}[/]",
            title="[bold red]Invalid Input",
            title_align="center",
            padding=(1, 2),
            border_style="red"
        ), justify="center")
        pause_and_space()

def view_passwords(): 
    # View stored passwords 
    passwords = load_passwords()
    if passwords:
        table = Table(title="Your Stored Passwords :memo:", title_style="bold magenta")
        table.add_column("No.", style="cyan", justify="center") 
        table.add_column("Service", style="cyan", justify="center") 
        table.add_column("Password", style="magenta", justify="center") 
        table.add_column("Added On", style="green", justify="center")  
        for i, (service, encrypted_data) in enumerate(passwords.items(), 1):
            decrypted_data = decrypt_data(encrypted_data)
            if decrypted_data:
                password, timestamp = decrypted_data.split("|")  # Split data
                table.add_row(str(i), service, password, timestamp)
        console.print(table, justify="center") 
        pause_and_space()
    else:
        console.print(Panel(
            "[bold red]You have no stored passwords. :crying_face:[/]",
            title="[bold red]No Passwords Found",
            title_align="center", # Center title
            padding=(1, 2),
            border_style="red" 
        ), justify="center") 
        pause_and_space()

def delete_passwords(): 
    # Delete passwords 
    passwords = load_passwords()
    if passwords:
        table = Table(title="Your Stored Passwords :memo:", title_style="bold magenta")
        table.add_column("No.", style="cyan", justify="center") 
        table.add_column("Service", style="cyan", justify="center") 
        table.add_column("Password", style="magenta", justify="center") 
        table.add_column("Added On", style="green", justify="center")  # Add timestamp column
        for i, (service, encrypted_data) in enumerate(passwords.items(), 1):
            decrypted_data = decrypt_data(encrypted_data) 
            if decrypted_data:
                password, timestamp = decrypted_data.split("|") 
                table.add_row(str(i), service, password, timestamp)
        console.print(table, justify="center") 
        pause_and_space()

        choice = Prompt.ask("[bold yellow]Enter the number(s) of the password(s) to delete (comma-separated)[/]")
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
                    f"[bold underline red]{number}[/] [bold red]is not a valid number.[/] :pensive:",  # Change to red
                    title="[bold red]Invalid Input",  # Change to red
                    title_align="center", 
                    padding=(1, 2),
                    border_style="red" 
                ), justify="center") 
                pause_and_space()
                return 

        confirm = Confirm.ask(f"[bold yellow]Delete password(s) for [bold yellow]{', '.join([f'[bold underline yellow]{service}[/]' for service in services])}[/]?[/]")
        pause_and_space() 
        if confirm:
            for service in services:
                passwords.pop(service) 
            save_passwords(passwords)
            console.print(Panel(
                f"[bold green]Password(s) for [bold green]{', '.join([f'[bold underline green]{service}[/]' for service in services])}[/] deleted successfully! :wastebasket:[/]",
                title="[bold green]Passwords Deleted",
                title_align="center", 
                padding=(1, 2),
                border_style="green" 
            ), justify="center") 
            pause_and_space()
        else:
            console.print(Panel(
                "[bold green]Deletion canceled. :relieved:[/]",
                title="[bold green]Deletion Canceled", 
                title_align="center", 
                padding=(1, 2),
                border_style="green" 
            ), justify="center") 
            pause_and_space()
    else:
        console.print(Panel(
            "[bold red]You have no stored passwords. :crying_face:[/]",
            title="[bold red]No Passwords Found",
            title_align="center", 
            padding=(1, 2),
            border_style="red" 
        ), justify="center") 
        pause_and_space() 

def main():
    # Main function
    os.system('clear')
    time.sleep(1)
    if not os.path.exists(MASTER_PASSWORD_FILE):
        create_master_password()
        key = generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
        passwords = {}
        save_passwords(passwords)

    while True:
        console.print(Panel(
            "[bold green]Welcome to the Smart Password Manager! :smiley:[/]\n\n" 
            "[bold]What do you want to do?[/]", 
            title="[bold blue]Main Menu",
            title_align="center", 
            padding=(1, 2),
            border_style="bright_blue"
        ), justify="center") 
        pause_and_space()

        console.print("[1] Add a new password") 
        console.print("[2] View your stored passwords") 
        console.print("[3] Delete a password") 
        console.print("[4] Exit") 
        pause_and_space()

        choice = Prompt.ask("\n[bold yellow]Enter your choice (1-4)[/]", choices=["1", "2", "3", "4"]) 
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
                "[bold]Thank you for using the Smart Password Manager! :smiley:[/]\n\n" 
                "[bold]Have a nice day! :wave:[/]", 
                title="[bold magenta]Goodbye!", 
                title_align="center", 
                padding=(1, 2),
                border_style="magenta"
            ), justify="center") 
            pause_and_space() 
            break 
        console.input("[bold blue]Press Enter to continue...[/]")  
        os.system('clear')  
        pause_and_space()

# Run the main function 
if __name__ == "__main__":
    main()

