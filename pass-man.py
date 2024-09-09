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

# ——— Import Module ———
import os, time, sys, string, difflib
import cryptography, argon2, base64
import pickle, secrets, json
import rich

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

from difflib import get_close_matches

# ——— Constant Declaration ———
PASSWORDS_FILE = "passwords.dat"
MASTER_PASSWORD_FILE = "master_password.dat"
KEY_FILE = "key.dat"
SALT_FILE = "salt.dat"

console = Console()


# ——— Function Definition ———
def hash_password(password, salt):
    """Hash password using Argon2id with maximum security parameters."""
    password = password.encode()
    hasher = argon2.PasswordHasher(
        time_cost=16,
        memory_cost=2**18,
        parallelism=2,
        hash_len=32,
        salt_len=32,
        type=argon2.Type.ID,
    )
    hashed_password = hasher.hash(password)
    return hashed_password


def generate_salt():
    """Generate a random 32-byte salt."""
    return secrets.token_bytes(32)


def save_salt(salt):
    """Save the salt to a file."""
    with open(SALT_FILE, "wb") as file:
        file.write(salt)


def load_salt():
    """Load the salt from a file."""
    with open(SALT_FILE, "rb") as file:
        salt = file.read()
    return salt


def generate_key(master_password, salt):
    """Generate a 32-byte AES key from the master password using Argon2id."""
    password = master_password.encode()
    argon2_hasher = argon2.PasswordHasher(
        time_cost=16,
        memory_cost=2**18,
        parallelism=2,
        hash_len=32,
        salt_len=32,
        type=argon2.Type.ID,
    )
    hash = argon2_hasher.hash(password)
    key = base64.urlsafe_b64encode(hash.encode()[:32])
    return key


def load_key(master_password):
    """Load the encryption key from file, generating it using Argon2id if needed."""
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
    """Encrypt data using AES-GCM."""
    aesgcm = AESGCM(base64.urlsafe_b64decode(key))
    nonce = secrets.token_bytes(12)
    if not isinstance(data, bytes):
        data = data.encode()
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    return base64.urlsafe_b64encode(nonce + encrypted_data)


def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-GCM with error handling."""
    aesgcm = AESGCM(base64.urlsafe_b64decode(key))
    try:
        decoded_data = base64.urlsafe_b64decode(encrypted_data)
        nonce = decoded_data[:12]
        ciphertext = decoded_data[12:]
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except Exception:
        console.print(
            Panel(
                "[bold red]Error: Invalid data or key. Decryption failed. :worried:[/]",
                title="[bold red]Decryption Error",
                title_align="center",
                padding=(1, 2),
                border_style="red",
            ),
            justify="center",
        )
        pause_and_space()
        return None


def generate_password(length, options):
    """Generate a random password using secrets and with customizable options."""

    characters = ""

    if "L" in options:
        characters += string.ascii_lowercase
    if "U" in options:
        characters += string.ascii_uppercase
    if "D" in options:
        characters += string.digits
    if "S" in options:
        characters += string.punctuation

    if not characters:
        raise ValueError("No valid options selected to generate password.")

    password = "".join(secrets.choice(characters) for _ in range(length))
    return password


def save_passwords(passwords, key):
    """Save passwords dictionary to file after encryption."""
    with open(PASSWORDS_FILE, "wb") as file:
        pickled_data = pickle.dumps(passwords)
        encrypted_data = encrypt_data(pickled_data, key)
        file.write(encrypted_data)


def load_passwords(key):
    """Load passwords dictionary from file after decryption."""
    with open(PASSWORDS_FILE, "rb") as file:
        encrypted_data = file.read()
        decrypted_data = decrypt_data(encrypted_data, key)
        if decrypted_data is not None:
            passwords = pickle.loads(decrypted_data)
            return passwords
        else:
            return {}


def secure_delete_file(filename):
    """Securely delete a file by overwriting it 3 times before deletion."""
    if not os.path.exists(filename):
        return

    file_size = os.path.getsize(filename)

    with open(filename, "rb+") as f:
        for _ in range(3):
            f.seek(0)
            f.write(secrets.token_bytes(file_size))
            f.flush()
            os.fsync(f.fileno())

    os.remove(filename)


def normalize_string(s):
    return "".join(c.lower() for c in s if not c.isspace())


def search_passwords(passwords, key, search_term):
    """Search for passwords containing the search term with improved matching."""
    results = {}
    normalized_search = normalize_string(search_term)

    # Exact and partial matches
    for service, encrypted_data in passwords.items():
        if normalized_search in normalize_string(service):
            decrypted_data = decrypt_data(encrypted_data, key)
            if decrypted_data:
                results[service] = json.loads(decrypted_data.decode("utf-8"))

    # If no results, try to find close matches
    if not results:
        normalized_services = {normalize_string(s): s for s in passwords.keys()}
        close_matches = get_close_matches(
            normalized_search, normalized_services.keys(), n=3, cutoff=0.6
        )
        for match in close_matches:
            service = normalized_services[match]
            decrypted_data = decrypt_data(passwords[service], key)
            if decrypted_data:
                results[service] = json.loads(decrypted_data.decode("utf-8"))

    return results


def pause_and_space():
    """Add pauses and spacing for better readability."""
    time.sleep(1)
    print()


def create_master_password():
    """Create and save master password hash."""
    os.system("clear")
    time.sleep(1)

    console.print(
        Panel(
            "[bold green]Welcome to the Smart Password Manager! :smiley:[/]\n\n"
            "[bold]This script lets you securely store, view, and manage your passwords for different services.\n\n[/]"
            "[bold]To get started, you'll need to create a strong Master Password.\n\n[/]"
            "[bold red]Remember, your Master Password is the key to all your stored passwords. "
            "There's no way to recover it if you forget it! :fearful:[/]\n\n"
            "[bold yellow]Note: The password creation process might take a few seconds for enhanced security.[/]",
            title="[bold blue]Welcome!",
            title_align="center",
            padding=(1, 2),
            border_style="bright_blue",
        ),
        justify="center",
    )
    time.sleep(1)

    salt = generate_salt()
    while True:
        master_password = Prompt.ask(
            "\n[bold yellow]Enter your Master Password[/]", password=True
        )
        pause_and_space()

        if len(master_password) < 8:
            console.print(
                Panel(
                    "[bold red]Master Password is too weak. It should be at least 8 characters long. :pensive:[/]",
                    title="[bold red]Weak Password",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            pause_and_space()
        else:
            confirm_password = Prompt.ask(
                "[bold yellow]Confirm your Master Password[/]", password=True
            )
            pause_and_space()
            if master_password == confirm_password:
                console.print(
                    Panel(
                        "[bold green]Master Password created successfully! :tada:[/]",
                        title="[bold green]Success!",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                pause_and_space()
                hashed_password = hash_password(master_password, salt)
                with open(MASTER_PASSWORD_FILE, "w") as file:
                    file.write(hashed_password)
                save_salt(salt)
                break
            else:
                console.print(
                    Panel(
                        "[bold red]Passwords don't match. Please try again. :disappointed:[/]",
                        title="[bold red]Mismatch",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                pause_and_space()


def verify_master_password():
    """Verify master password against stored hash."""
    with open(MASTER_PASSWORD_FILE, "r") as file:
        hashed_password = file.read()

    console.print(
        Panel(
            "[bold yellow]Note: Verification might take a few seconds due to strong security measures.[/]\n\n"
            "[bold yellow]Enter Your Master Password to continue...[/]",
            title="[bold yellow]Enter Master Password[/]",
            title_align="center",
            padding=(1, 2),
            border_style="yellow",
        ),
        justify="center",
    )

    master_password = Prompt.ask(
        "\n[bold yellow]Enter your Master Password[/]", password=True
    )
    pause_and_space()

    salt = load_salt()
    hasher = argon2.PasswordHasher(type=argon2.Type.ID)

    try:
        hasher.verify(hashed_password, master_password.encode())
        console.print(
            Panel(
                "[bold green]Master Password is correct. :thumbsup:[/]",
                title="[bold green]Access Granted!",
                title_align="center",
                padding=(1, 2),
                border_style="green",
            ),
            justify="center",
        )
        pause_and_space()
        return master_password

    except argon2.exceptions.VerifyMismatchError:
        console.print(
            Panel(
                "[bold red]Master Password is wrong. :worried:[/]",
                title="[bold red]Incorrect Password",
                title_align="center",
                padding=(1, 2),
                border_style="red",
            ),
            justify="center",
        )
        pause_and_space()
        return False


def add_password(key):
    """Add a new password or update an existing one in the encrypted store."""
    passwords = load_passwords(key)

    try:
        service = Prompt.ask("[bold yellow]Enter the name of the service[/]")
        pause_and_space()
        if not service.strip():
            raise ValueError("Service name cannot be blank.")

        existing_password = None
        normalized_service = normalize_string(service)
        matching_service = next(
            (s for s in passwords if normalize_string(s) == normalized_service), None
        )

        if matching_service:
            decrypted_data = decrypt_data(passwords[matching_service], key)
            if decrypted_data:
                data = json.loads(decrypted_data.decode("utf-8"))
                existing_password = data.get("password")

        if existing_password:
            console.print(
                Panel(
                    f"[bold yellow]A password for [bold underline yellow]{matching_service}[/] already exists. :open_mouth:[/]\n\n"
                    f"[bold yellow]Your current password for [bold underline yellow]{matching_service}[/] is [bold underline yellow]{existing_password}[/] :key:[/]\n\n"
                    "[bold yellow]Do you want to update this password?[/]",
                    title="[bold yellow]Existing Entry",
                    title_align="center",
                    padding=(1, 2),
                    border_style="yellow",
                ),
                justify="center",
            )
            pause_and_space()

            update = Confirm.ask("[bold yellow]Update this password?[/]")
            pause_and_space()

            if not update:
                console.print(
                    Panel(
                        "[bold green]Password update canceled. :relieved:[/]",
                        title="[bold green]Update Canceled",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                pause_and_space()
                return

        create_random = Confirm.ask("[bold yellow]Create a random password?[/]")
        pause_and_space()

        if create_random:
            length = Prompt.ask(
                "[bold yellow]Enter the length of the password (8-32)[/]",
                console=console,
            )
            pause_and_space()

            try:
                length = int(length)
                if 8 <= length <= 32:
                    console.print(
                        Panel(
                            "[bold yellow]Enter options for password generation:[/]\n"
                            "[bold yellow]L = lowercase, U = uppercase, D = digits, S = symbols[/]\n"
                            "[bold yellow](e.g., 'LUD' for a password with lowercase, uppercase, and digits)[/]",
                            title="[bold yellow]Password Options[/]",
                            title_align="center",
                            padding=(1, 2),
                            border_style="yellow",
                        ),
                        justify="center",
                    )

                    options = Prompt.ask(
                        "[bold yellow]Enter your selection (L, U, D, S)[/]"
                    )
                    pause_and_space()

                    options = options.upper()
                    valid_options = set("LUDS")
                    selected_options = set(options)

                    if (
                        not selected_options.issubset(valid_options)
                        or len(selected_options) == 0
                    ):
                        console.print(
                            Panel(
                                "[bold red]Invalid options entered. Use only 'L', 'U', 'D', 'S'.[/]\n"
                                "[bold yellow]L = lowercase, U = uppercase, D = digits, S = symbols[/]",
                                title="[bold red]Invalid Input[/]",
                                title_align="center",
                                padding=(1, 2),
                                border_style="red",
                            ),
                            justify="center",
                        )
                        pause_and_space()
                        return

                    password = generate_password(length, options)

                    console.print(
                        Panel(
                            f"[bold green]Your random password for [bold underline green]{service}[/] is [bold underline green]{password}[/] :game_die:[/]",
                            title="[bold green]Password Generated!",
                            title_align="center",
                            padding=(1, 2),
                            border_style="green",
                        ),
                        justify="center",
                    )
                    pause_and_space()
                else:
                    console.print(
                        Panel(
                            "[bold red]Password length should be between 8 and 32. :pensive:[/]",
                            title="[bold red]Invalid Length[/]",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red",
                        ),
                        justify="center",
                    )
                    pause_and_space()
                    return
            except ValueError:
                console.print(
                    Panel(
                        "[bold red]Invalid input for password length. Please enter a number between 8 and 32. :pensive:[/]",
                        title="[bold red]Invalid Input[/]",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                pause_and_space()
                return
        else:
            password = Prompt.ask(
                "[bold yellow]Enter your password for this service[/]",
                password=True,
            )
            pause_and_space()
            if not password.strip():
                raise ValueError("Password cannot be blank.")

        timestamp_str = time.strftime("%H:%M:%S %Y-%m-%d")
        combined_data = json.dumps({"password": password, "timestamp": timestamp_str})
        encrypted_data = encrypt_data(combined_data, key)

        passwords[service] = encrypted_data
        save_passwords(passwords, key)
        action = "updated" if existing_password else "saved"
        console.print(
            Panel(
                f"[bold green]Password for [bold underline green]{service}[/] {action} successfully! :raised_hands:[/]",
                title=f"[bold green]Password {action.capitalize()}!",
                title_align="center",
                padding=(1, 2),
                border_style="green",
            ),
            justify="center",
        )
        pause_and_space()
    except ValueError as e:
        console.print(
            Panel(
                f"[bold red]{e}[/]",
                title="[bold red]Invalid Input",
                title_align="center",
                padding=(1, 2),
                border_style="red",
            ),
            justify="center",
        )
        pause_and_space()


def view_passwords(key):
    """View stored passwords in a formatted table."""
    passwords = load_passwords(key)
    if passwords:
        search_term = Prompt.ask(
            "[bold yellow]Enter a search term (or press Enter to view all)[/]"
        )
        pause_and_space()

        if search_term:
            results = search_passwords(passwords, key, search_term)
        else:
            results = {
                service: json.loads(decrypt_data(encrypted_data, key).decode("utf-8"))
                for service, encrypted_data in passwords.items()
            }

        if results:
            table = Table(
                title="Your Stored Passwords :memo:",
                title_style="bold magenta",
                box=box.HEAVY,
                show_lines=True,
                expand=True,
                highlight=True,
            )
            table.add_column("No.", style="cyan", justify="center")
            table.add_column("Service", style="cyan", justify="center")
            table.add_column("Password", style="magenta", justify="center")
            table.add_column("Added On", style="green", justify="center")
            for i, (service, data) in enumerate(results.items(), 1):
                table.add_row(str(i), service, data["password"], data["timestamp"])
            console.print(table, justify="center")
        else:
            console.print(
                Panel(
                    f"[bold red]No passwords found matching '{search_term}'. :mag:[/]",
                    title="[bold red]No Results",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
        pause_and_space()
    else:
        console.print(
            Panel(
                "[bold red]You have no stored passwords. :crying_face:[/]",
                title="[bold red]No Passwords Found",
                title_align="center",
                padding=(1, 2),
                border_style="red",
            ),
            justify="center",
        )
        pause_and_space()


def delete_passwords(key):
    """Delete selected passwords from the encrypted store."""
    passwords = load_passwords(key)
    if passwords:
        search_term = Prompt.ask(
            "[bold yellow]Enter a search term (or press Enter to view all)[/]"
        )
        pause_and_space()

        if search_term:
            results = search_passwords(passwords, key, search_term)
        else:
            results = {
                service: json.loads(decrypt_data(encrypted_data, key).decode("utf-8"))
                for service, encrypted_data in passwords.items()
            }

        if results:
            table = Table(
                title="Your Stored Passwords :memo:",
                title_style="bold magenta",
                box=box.HEAVY,
                show_lines=True,
                expand=True,
                highlight=True,
            )
            table.add_column("No.", style="cyan", justify="center")
            table.add_column("Service", style="cyan", justify="center")
            table.add_column("Password", style="magenta", justify="center")
            table.add_column("Added On", style="green", justify="center")
            for i, (service, data) in enumerate(results.items(), 1):
                table.add_row(str(i), service, data["password"], data["timestamp"])
            console.print(table, justify="center")
            pause_and_space()

            choice = Prompt.ask(
                "[bold yellow]Enter the number(s) of the password(s) to delete (comma-separated)[/]"
            )
            pause_and_space()
            numbers = choice.split(",")
            services = []
            for number in numbers:
                try:
                    number = int(number)
                    service = list(results.keys())[number - 1]
                    services.append(service)
                except:
                    console.print(
                        Panel(
                            f"[bold underline red]{number}[/] [bold red]is not a valid number.[/] :pensive:",
                            title="[bold red]Invalid Input",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red",
                        ),
                        justify="center",
                    )
                    pause_and_space()
                    return

            confirm = Confirm.ask(
                f"[bold yellow]Delete password(s) for [bold yellow]{', '.join([f'[bold underline yellow]{service}[/]' for service in services])}[/]?[/]"
            )
            pause_and_space()
            if confirm:
                for service in services:
                    passwords.pop(service)
                save_passwords(passwords, key)
                console.print(
                    Panel(
                        f"[bold green]Password(s) for [bold green]{', '.join([f'[bold underline green]{service}[/]' for service in services])}[/] deleted successfully! :wastebasket:[/]",
                        title="[bold green]Passwords Deleted",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                pause_and_space()
            else:
                console.print(
                    Panel(
                        "[bold green]Deletion canceled. :relieved:[/]",
                        title="[bold green]Deletion Canceled",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                pause_and_space()
        else:
            console.print(
                Panel(
                    f"[bold red]No passwords found matching '{search_term}'. :mag:[/]",
                    title="[bold red]No Results",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            pause_and_space()
    else:
        console.print(
            Panel(
                "[bold red]You have no stored passwords. :crying_face:[/]",
                title="[bold red]No Passwords Found",
                title_align="center",
                padding=(1, 2),
                border_style="red",
            ),
            justify="center",
        )
        pause_and_space()


def reset_data(key):
    """Resets data based on user choice."""
    while True:
        console.print(
            Panel(
                "[bold red]WARNING: This action will permanently delete data! :warning:[/]\n\n"
                "[bold]Choose a reset option:[/]",
                title="[bold red]Data Reset",
                title_align="center",
                padding=(1, 2),
                border_style="red",
            ),
            justify="center",
        )
        pause_and_space()

        console.print("[1] Reset ALL Passwords")
        console.print("[2] Reset ALL Data (Passwords, Master Password, Keys, Salt)")
        console.print("[3] Cancel Reset")
        pause_and_space()

        choice = Prompt.ask(
            "\n[bold red]Enter your choice (1-3)[/]", choices=["1", "2", "3"]
        )
        pause_and_space()

        if choice == "1" or choice == "2":
            console.print(
                Panel(
                    "[bold red]DANGER! This action is irreversible. Deleted data cannot be recovered! :skull:[/]\n\n"
                    "[bold red]Are you absolutely sure you want to continue?[/]",
                    title="[bold red]Final Warning",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            pause_and_space()

            if Confirm.ask("[bold red]Confirm Data Reset?[/]"):
                pause_and_space()
                console.print(
                    Panel(
                        "[bold yellow]Note: This process might take a few seconds for enhanced security.[/]\n\n"
                        "[bold red]Enter your Master Password for confirmation.[/]",
                        title="[bold red]Enter Master Password[/]",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                master_password = Prompt.ask(
                    "\n[bold red]Enter Master Password[/]", password=True
                )
                pause_and_space()
                salt = load_salt()

                with open(MASTER_PASSWORD_FILE, "r") as file:
                    stored_hashed_password = file.read()

                hasher = argon2.PasswordHasher(type=argon2.Type.ID)

                try:
                    hasher.verify(stored_hashed_password, master_password.encode())
                    if choice == "1":
                        secure_delete_file(PASSWORDS_FILE)
                        passwords = {}
                        save_passwords(passwords, key)
                        console.print(
                            Panel(
                                "[bold red]All passwords have been reset. :fire:[/]",
                                title="[bold red]Passwords Reset",
                                title_align="center",
                                padding=(1, 2),
                                border_style="red",
                            ),
                            justify="center",
                        )
                        pause_and_space()
                        break
                    elif choice == "2":
                        for filename in [
                            PASSWORDS_FILE,
                            MASTER_PASSWORD_FILE,
                            KEY_FILE,
                            SALT_FILE,
                        ]:
                            if os.path.exists(filename):
                                secure_delete_file(filename)
                        console.print(
                            Panel(
                                "[bold red]All data has been reset. The program is now like new. :fire:[/]",
                                title="[bold red]Data Reset",
                                title_align="center",
                                padding=(1, 2),
                                border_style="red",
                            ),
                            justify="center",
                        )
                        pause_and_space()
                        sys.exit(0)

                except argon2.exceptions.VerifyMismatchError:
                    console.print(
                        Panel(
                            "[bold red]Incorrect Master Password. Reset operation canceled. :no_entry_sign:[/]",
                            title="[bold red]Incorrect Password",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red",
                        ),
                        justify="center",
                    )
                    pause_and_space()
            else:
                pause_and_space()
                console.print(
                    Panel(
                        "[bold green]Reset operation canceled. :relieved:[/]",
                        title="[bold green]Reset Canceled",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                pause_and_space()
                break
        elif choice == "3":
            console.print(
                Panel(
                    "[bold green]Reset operation canceled. :relieved:[/]",
                    title="[bold green]Reset Canceled",
                    title_align="center",
                    padding=(1, 2),
                    border_style="green",
                ),
                justify="center",
            )
            pause_and_space()
            break


def change_master_password(key):
    """Change the master password."""
    console.print(
        Panel(
            "[bold yellow]Changing your Master Password...[/]\n\n"
            "[bold red]Remember, this is a critical operation. Ensure you remember your new Master Password![/]\n\n"
            "[bold yellow]Note: This process might take a few seconds for enhanced security.[/]",
            title="[bold yellow]Change Master Password",
            title_align="center",
            padding=(1, 2),
            border_style="yellow",
        ),
        justify="center",
    )
    pause_and_space()

    while True:
        old_master_password = Prompt.ask(
            "[bold yellow]Enter your current Master Password[/]", password=True
        )
        pause_and_space()
        salt = load_salt()

        with open(MASTER_PASSWORD_FILE, "r") as file:
            stored_hashed_password = file.read()

        hasher = argon2.PasswordHasher(type=argon2.Type.ID)

        try:
            hasher.verify(stored_hashed_password, old_master_password.encode())
            new_master_password = Prompt.ask(
                "\n[bold yellow]Enter your new Master Password[/]", password=True
            )
            pause_and_space()

            if len(new_master_password) < 8:
                console.print(
                    Panel(
                        "[bold red]New Master Password is too weak. It should be at least 8 characters long. :pensive:[/]",
                        title="[bold red]Weak Password",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                pause_and_space()
            else:
                confirm_password = Prompt.ask(
                    "[bold yellow]Confirm your new Master Password[/]", password=True
                )
                pause_and_space()
                if new_master_password == confirm_password:
                    console.print(
                        Panel(
                            "[bold green]Master Password changed successfully! :tada:[/]",
                            title="[bold green]Success!",
                            title_align="center",
                            padding=(1, 2),
                            border_style="green",
                        ),
                        justify="center",
                    )
                    pause_and_space()
                    new_hashed_password = hash_password(new_master_password, salt)
                    with open(MASTER_PASSWORD_FILE, "w") as file:
                        file.write(new_hashed_password)
                    new_key = generate_key(new_master_password, salt)
                    with open(KEY_FILE, "wb") as file:
                        file.write(new_key)
                    passwords = load_passwords(key)
                    save_passwords(passwords, new_key)
                    break
                else:
                    console.print(
                        Panel(
                            "[bold red]Passwords don't match. Please try again. :disappointed:[/]",
                            title="[bold red]Mismatch",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red",
                        ),
                        justify="center",
                    )
                    pause_and_space()
        except argon2.exceptions.VerifyMismatchError:
            console.print(
                Panel(
                    "[bold red]Incorrect current Master Password. Change operation canceled. :no_entry_sign:[/]",
                    title="[bold red]Incorrect Password",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            pause_and_space()
            break


# ——— Main Function ———
def main():
    """Main function for the Password Manager."""
    os.system("clear")
    time.sleep(1)

    if not os.path.exists(MASTER_PASSWORD_FILE):
        create_master_password()

    master_password = verify_master_password()

    if not master_password:
        return
    key = load_key(master_password)

    if not os.path.exists(PASSWORDS_FILE):
        passwords = {}
        save_passwords(passwords, key)

    while True:
        console.print(
            Panel(
                "[bold green]Welcome to the Smart Password Manager! :smiley:[/]\n\n"
                "[bold]What do you want to do?[/]",
                title="[bold blue]Main Menu",
                title_align="center",
                padding=(1, 2),
                border_style="bright_blue",
            ),
            justify="center",
        )
        pause_and_space()

        console.print("[1] Add a new password")
        console.print("[2] View your stored passwords")
        console.print("[3] Delete a password")
        console.print("[4] Change Master Password")
        console.print("[5] Reset Data")
        console.print("[6] Exit")
        pause_and_space()

        choice = Prompt.ask(
            "\n[bold yellow]Enter your choice (1-6)[/]",
            choices=["1", "2", "3", "4", "5", "6"],
        )
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
            console.print(
                Panel(
                    "[bold]Thank you for using the Smart Password Manager! :smiley:[/]\n\n"
                    "[bold]Have a nice day! :wave:[/]",
                    title="[bold magenta]Goodbye!",
                    title_align="center",
                    padding=(1, 2),
                    border_style="magenta",
                ),
                justify="center",
            )
            pause_and_space()
            break

        console.input("[bold blue]Press Enter to continue...[/]")
        os.system("clear")
        pause_and_space()


if __name__ == "__main__":
    main()
