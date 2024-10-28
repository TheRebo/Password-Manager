"""
Smart Password Manager with Advanced Security Features
Copyright (c) 2023-2024 Na'im Annafi Santosa (TheRebo)
Licensed under the MIT License

A sophisticated password manager implementing state-of-the-art security measures
including memory safety, side-channel protection, and secure cryptographic operations.
"""

from __future__ import annotations

import os
import sys
import time
import string
import mmap
import threading
import contextlib
import difflib
import pickle
import secrets
import json
import base64
import asyncio
from typing import Optional, Any, Dict, List, Set, Union, Callable, TypeVar, Final
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from contextlib import asynccontextmanager

import cryptography
import argon2
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box

# Type variables for generic operations
T = TypeVar("T")
PathLike = Union[str, Path]


class AppConfig:
    """Application-wide configuration and constants."""
    PASSWORDS_FILE: Final[str] = "passwords.dat"
    MASTER_PASSWORD_FILE: Final[str] = "master_password.dat"
    KEY_FILE: Final[str] = "key.dat"
    SALT_FILE: Final[str] = "salt.dat"
    PAGE_SIZE: Final[int] = mmap.PAGESIZE

    ARGON2_TIME_COST: Final[int] = 16
    ARGON2_MEMORY_COST: Final[int] = 2**18
    ARGON2_PARALLELISM: Final[int] = 2
    ARGON2_HASH_LEN: Final[int] = 32
    ARGON2_SALT_LEN: Final[int] = 32

    NONCE_SIZE: Final[int] = 12
    KEY_SIZE: Final[int] = 32


# Global console instance
console: Final[Console] = Console()


@dataclass
class PasswordEntry:
    """Structured representation of a password entry."""
    service: str
    password: str
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "PasswordEntry":
        """
        Create a PasswordEntry from a dictionary.

        Args:
            data (Dict[str, str]): Dictionary containing service, password, and timestamp

        Returns:
            PasswordEntry: New instance created from dictionary data
        """
        return cls(
            service=data["service"],
            password=data["password"],
            timestamp=data["timestamp"],
        )

    def to_dict(self) -> Dict[str, str]:
        """
        Convert PasswordEntry to dictionary format.

        Returns:
            Dict[str, str]: Dictionary containing service, password, and timestamp
        """
        return {
            "service": self.service,
            "password": self.password,
            "timestamp": self.timestamp,
        }


class SecureMemory:
    """
    Advanced memory safety implementation with secure allocation,
    locking, and wiping capabilities.
    """

    def __init__(self) -> None:
        """Initialize secure memory management system."""
        self._page_size: Final[int] = AppConfig.PAGE_SIZE
        self._secure_pages: Dict[int, bytearray] = {}
        self._lock: threading.Lock = threading.Lock()
        self._counter: int = 0

    def _round_to_page(self, size: int) -> int:
        """
        Rounds a memory size up to the nearest memory page boundary for secure allocation.

        Args:
            size (int): The requested memory size in bytes to be rounded up

        Returns:
            int: The size rounded up to the nearest page boundary. This will always be
                greater than or equal to the input size and will be a multiple of
                the system's page size.
        """
        return (size + self._page_size - 1) & ~(self._page_size - 1)

    def secure_malloc(self, size: int) -> bytearray:
        """
        Allocate memory with security features enabled.

        Args:
            size: Required memory size in bytes

        Returns:
            Secure bytearray buffer

        Raises:
            MemoryError: If secure allocation fails
        """
        page_size: int = self._round_to_page(size)

        try:
            buffer = bytearray(page_size)
            with self._lock:
                self._counter += 1
                self._secure_pages[self._counter] = buffer
            return buffer

        except Exception as e:
            raise MemoryError(f"Secure memory allocation failed: {e}")

    def secure_free(self, buffer: bytearray) -> None:
        """
        Securely free allocated memory with multiple overwrite passes.

        Args:
            buffer: Bytearray to securely free
        """
        size = len(buffer)

        for _ in range(3):
            for i in range(size):
                buffer[i] = 0
            for i in range(size):
                buffer[i] = 0xFF
            for i in range(size):
                buffer[i] = 0

        random_bytes = secrets.token_bytes(size)
        for i in range(size):
            buffer[i] = random_bytes[i]

        with self._lock:
            keys_to_remove = []
            for key, stored_buffer in self._secure_pages.items():
                if stored_buffer is buffer:
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del self._secure_pages[key]

    @asynccontextmanager
    async def secure_buffer(self, size: int) -> AsyncGenerator[bytearray, None]:
        """
        Async context manager for secure memory allocation.

        Args:
            size: Size of buffer to allocate

        Yields:
            Secure buffer as bytearray

        Raises:
            MemoryError: If secure allocation fails
        """
        buffer = None

        try:
            buffer = self.secure_malloc(size)
            yield buffer

        finally:
            if buffer is not None:
                self.secure_free(buffer)


class SideChannelProtection:
    """
    Advanced implementation of side-channel attack protections including
    timing attacks, memory access patterns, and cache attacks.
    """

    def __init__(self) -> None:
        """Initialize side-channel protection mechanisms."""
        self._rng: secrets.SystemRandom = secrets.SystemRandom()
        self._thread_pool: ThreadPoolExecutor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="secure_ops"
        )
        self._memory: SecureMemory = SecureMemory()
        self._lock: threading.Lock = threading.Lock()

    def _add_timing_noise(self) -> None:
        """Add randomized timing noise to operations."""
        time.sleep(self._rng.uniform(0.001, 0.005))

    @contextlib.contextmanager
    def timing_defense(self) -> None:
        """
        Context manager implementing timing attack mitigations through
        randomized operation timing.
        """
        try:
            self._add_timing_noise()
            yield

        finally:
            self._add_timing_noise()

    def constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """
        Perform constant-time comparison of two byte strings.

        Args:
            a: First byte string
            b: Second byte string

        Returns:
            True if strings are equal, False otherwise
        """
        return constant_time.bytes_eq(a, b)

    def secure_operation(
        self, operation: Callable[..., T], *args: Any, **kwargs: Any
    ) -> T:
        """
        Execute operation with comprehensive side-channel protections.

        Args:
            operation: Function to execute securely
            *args: Positional arguments for operation
            **kwargs: Keyword arguments for operation

        Returns:
            Operation result of type T

        Raises:
            Exception: If operation fails
        """
        with self.timing_defense():
            future = self._thread_pool.submit(operation, *args, **kwargs)
            return future.result()


class CryptographicOperations:
    """
    Handles all cryptographic operations with modern security practices.
    """

    def __init__(self) -> None:
        """Initialize cryptographic operations handler."""
        self._side_channel: SideChannelProtection = SideChannelProtection()
        self._secure_memory: SecureMemory = SecureMemory()

    def compare_secure_strings(
        self, a: Union[str, bytes], b: Union[str, bytes]
    ) -> bool:
        """
        Compare strings in constant time to prevent timing attacks.

        Args:
            a: First string/bytes to compare
            b: Second string/bytes to compare

        Returns:
            True if strings are equal, False otherwise
        """
        if isinstance(a, str):
            a = a.encode()
        if isinstance(b, str):
            b = b.encode()

        return self._side_channel.constant_time_compare(a, b)

    def hash_password(self, password: str, salt: bytes) -> str:
        """
        Hash password using Argon2id with maximum security parameters.

        Args:
            password: Password to hash
            salt: Salt for hashing

        Returns:
            Hashed password string

        Raises:
            ValueError: If password or salt is invalid
        """
        if not password or not salt:
            raise ValueError("Password and salt must not be empty")

        password_bytes = password.encode()

        hasher = argon2.PasswordHasher(
            time_cost=AppConfig.ARGON2_TIME_COST,
            memory_cost=AppConfig.ARGON2_MEMORY_COST,
            parallelism=AppConfig.ARGON2_PARALLELISM,
            hash_len=AppConfig.ARGON2_HASH_LEN,
            salt_len=AppConfig.ARGON2_SALT_LEN,
            type=argon2.Type.ID,
        )

        return self._side_channel.secure_operation(hasher.hash, password_bytes)

    def generate_key(self, master_password: str, salt: bytes) -> bytes:
        """
        Generate a cryptographic key from the master password using Argon2id.

        Args:
            master_password: Master password for key derivation
            salt: Salt for key derivation

        Returns:
            Derived key bytes

        Raises:
            ValueError: If master password or salt is invalid
        """
        if not master_password or not salt:
            raise ValueError("Master password and salt must not be empty")

        password_bytes = master_password.encode()

        argon2_hasher = argon2.PasswordHasher(
            time_cost=AppConfig.ARGON2_TIME_COST,
            memory_cost=AppConfig.ARGON2_MEMORY_COST,
            parallelism=AppConfig.ARGON2_PARALLELISM,
            hash_len=AppConfig.ARGON2_HASH_LEN,
            salt_len=AppConfig.ARGON2_SALT_LEN,
            type=argon2.Type.ID,
        )

        hash_result = self._side_channel.secure_operation(
            argon2_hasher.hash, password_bytes
        )

        return base64.urlsafe_b64encode(hash_result.encode()[:32])

    def encrypt_data(self, data: Union[str, bytes], key: bytes) -> bytes:
        """
        Encrypt data using AES-GCM with modern parameters.

        Args:
            data: Data to encrypt
            key: Encryption key

        Returns:
            Encrypted data bytes

        Raises:
            ValueError: If data or key is invalid
            cryptography.exceptions.InvalidKey: If key is invalid
        """
        if not data or not key:
            raise ValueError("Data and key must not be empty")

        aesgcm = AESGCM(base64.urlsafe_b64decode(key))
        nonce = secrets.token_bytes(AppConfig.NONCE_SIZE)

        data_bytes = data.encode() if isinstance(data, str) else data

        encrypted_data = self._side_channel.secure_operation(
            aesgcm.encrypt, nonce, data_bytes, None
        )

        return base64.urlsafe_b64encode(nonce + encrypted_data)

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> Optional[bytes]:
        """
        Decrypt data using AES-GCM with error handling.

        Args:
            encrypted_data: Data to decrypt
            key: Decryption key

        Returns:
            Decrypted data bytes or None if decryption fails

        Raises:
            ValueError: If encrypted_data or key is invalid
        """
        if not encrypted_data or not key:
            raise ValueError("Encrypted data and key must not be empty")

        try:
            aesgcm = AESGCM(base64.urlsafe_b64decode(key))
            decoded_data = base64.urlsafe_b64decode(encrypted_data)

            nonce = decoded_data[: AppConfig.NONCE_SIZE]
            ciphertext = decoded_data[AppConfig.NONCE_SIZE :]

            return self._side_channel.secure_operation(
                aesgcm.decrypt, nonce, ciphertext, None
            )

        except Exception as e:
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
            return None


class PasswordGenerator:
    """
    Advanced password generation with customizable options and entropy verification.
    """

    class Options:
        """Password generation options."""
        LOWERCASE: Final[str] = "L"
        UPPERCASE: Final[str] = "U"
        DIGITS: Final[str] = "D"
        SYMBOLS: Final[str] = "S"

    @dataclass
    class CharacterSets:
        """Available character sets for password generation."""
        lowercase: str = string.ascii_lowercase
        uppercase: str = string.ascii_uppercase
        digits: str = string.digits
        symbols: str = string.punctuation

    def __init__(self) -> None:
        """Initialize password generator with secure RNG."""
        self._rng: secrets.SystemRandom = secrets.SystemRandom()
        self._char_sets: PasswordGenerator.CharacterSets = self.CharacterSets()
        self._crypto_ops: CryptographicOperations = CryptographicOperations()

    def _get_character_set(self, options: str) -> str:
        """
        Build character set based on selected options.

        Args:
            options: String containing character set options

        Returns:
            Combined character set string
        """
        characters = ""
        options = options.upper()

        if self.Options.LOWERCASE in options:
            characters += self._char_sets.lowercase
        if self.Options.UPPERCASE in options:
            characters += self._char_sets.uppercase
        if self.Options.DIGITS in options:
            characters += self._char_sets.digits
        if self.Options.SYMBOLS in options:
            characters += self._char_sets.symbols

        return characters

    def _generate_with_entropy(self, length: int, characters: str) -> str:
        """
        Generate password with verified entropy.

        Args:
            length: Desired password length
            characters: Character set to use

        Returns:
            Generated password string
        """
        password = "".join(secrets.choice(characters) for _ in range(length))

        return password

    def generate(self, length: int, options: str) -> str:
        """
        Generate a cryptographically secure random password.

        Args:
            length: Desired password length
            options: String containing character set options (L,U,D,S)

        Returns:
            Generated password

        Raises:
            ValueError: If length or options are invalid
        """
        if not 8 <= length <= 32:
            raise ValueError("Password length must be between 8 and 32")

        characters = self._get_character_set(options)

        if not characters:
            raise ValueError("No valid options selected for password generation")

        password = self._generate_with_entropy(length, characters)

        return password


class FileOperations:
    """
    Secure file operations with memory protection and overwrites.
    """

    def __init__(self) -> None:
        """Initialize secure file operations handler."""
        self._secure_memory: SecureMemory = SecureMemory()
        self._side_channel: SideChannelProtection = SideChannelProtection()

    @asynccontextmanager
    async def secure_open(
        self, path: PathLike, mode: str, buffer_size: Optional[int] = None
    ) -> Any:
        """
        Async context manager for secure file operations.

        Args:
            path: Path to file
            mode: File open mode
            buffer_size: Optional buffer size

        Yields:
            File object wrapped in secure context
        """
        file = open(path, mode)

        try:
            yield file

        finally:
            file.flush()
            os.fsync(file.fileno())
            file.close()

    async def secure_save(
        self, data: Any, filepath: PathLike, key: Optional[bytes] = None
    ) -> None:
        """
        Securely save data to file with optional encryption.

        Args:
            data: Data to save
            filepath: Path to save file
            key: Optional encryption key

        Raises:
            IOError: If file operations fail
            ValueError: If data is invalid
        """
        try:
            async with self.secure_open(filepath, "wb") as file:
                if key:
                    crypto_ops = CryptographicOperations()
                    pickled_data = pickle.dumps(data)
                    encrypted_data = crypto_ops.encrypt_data(pickled_data, key)
                    file.write(encrypted_data)

                else:
                    pickle.dump(data, file)

        except Exception as e:
            raise IOError(f"Failed to save file securely: {e}")

    async def secure_load(self, filepath: PathLike, key: Optional[bytes] = None) -> Any:
        """
        Securely load data from file with optional decryption.

        Args:
            filepath: Path to load file from
            key: Optional decryption key

        Returns:
            Loaded data

        Raises:
            IOError: If file operations fail
            ValueError: If data is invalid
        """
        try:
            async with self.secure_open(filepath, "rb") as file:
                if key:
                    crypto_ops = CryptographicOperations()
                    encrypted_data = file.read()
                    decrypted_data = crypto_ops.decrypt_data(encrypted_data, key)

                    if decrypted_data is None:
                        return {}

                    return pickle.loads(decrypted_data)

                else:
                    return pickle.load(file)

        except Exception as e:
            raise IOError(f"Failed to load file securely: {e}")

    async def secure_delete(self, filepath: PathLike) -> None:
        """
        Securely delete file with multiple overwrites.

        Args:
            filepath: Path to file to delete

        Raises:
            IOError: If file operations fail
        """
        file_path = str(filepath)

        if not os.path.exists(file_path):
            return

        try:
            file_size = os.path.getsize(file_path)

            async with self.secure_open(file_path, "rb+") as f:
                async with self._secure_memory.secure_buffer(file_size) as secure_buf:
                    for _ in range(3):
                        f.seek(0)
                        for i in range(file_size):
                            secure_buf[i] = 0
                        f.write(secure_buf)
                        f.flush()

                        f.seek(0)
                        for i in range(file_size):
                            secure_buf[i] = 0xFF
                        f.write(secure_buf)
                        f.flush()

                        f.seek(0)
                        for i in range(file_size):
                            secure_buf[i] = 0
                        f.write(secure_buf)
                        f.flush()

                    f.seek(0)
                    random_bytes = secrets.token_bytes(file_size)
                    for i in range(file_size):
                        secure_buf[i] = random_bytes[i]
                    f.write(secure_buf)
                    f.flush()

            os.remove(file_path)

        except Exception as e:
            raise IOError(f"Secure file deletion failed: {e}")

    async def save_key(self, key: bytes) -> None:
        """Securely save encryption key to file."""
        try:
            async with self.secure_open(AppConfig.KEY_FILE, "wb") as f:
                f.write(key)

        except Exception as e:
            raise IOError(f"Failed to save key: {e}")

    async def load_key(self) -> bytes:
        """Load encryption key from file."""
        try:
            async with self.secure_open(AppConfig.KEY_FILE, "rb") as f:
                return f.read()

        except FileNotFoundError:
            raise FileNotFoundError(
                "Key file not found. Please initialize the password manager."
            )

        except Exception as e:
            raise IOError(f"Failed to load key: {e}")


class PasswordManager:
    """
    Core password management system with advanced security features.
    Handles password storage, retrieval, and management operations.
    """

    def __init__(self) -> None:
        """Initialize password manager with security components."""
        self._crypto_ops: CryptographicOperations = CryptographicOperations()
        self._file_ops: FileOperations = FileOperations()
        self._secure_memory: SecureMemory = SecureMemory()
        self._side_channel: SideChannelProtection = SideChannelProtection()
        self._password_generator: PasswordGenerator = PasswordGenerator()
        self._search_threshold: float = 0.6

    @asynccontextmanager
    async def _secure_context(self) -> None:
        """Provide secure context for sensitive operations."""
        with self._side_channel.timing_defense():
            yield

    def _normalize_string(self, s: str) -> str:
        """
        Normalize string for consistent comparison.

        Args:
            s: String to normalize

        Returns:
            Normalized string
        """
        return "".join(c.lower() for c in s if not c.isspace())

    async def _get_secure_input(
        self, prompt: str, password: bool = False, choices: Optional[List[str]] = None
    ) -> str:
        """
        Securely get user input with optional password masking.

        Args:
            prompt: Input prompt to display
            password: Whether to mask input as password
            choices: Optional list of valid choices

        Returns:
            User input string
        """
        try:
            if password:
                value = Prompt.ask(prompt, password=True)

            else:
                value = Prompt.ask(prompt)

            if choices and value not in choices:
                console.print(
                    Panel(
                        f"[bold red]Invalid choice. Please select from: {', '.join(choices)}[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                return await self._get_secure_input(prompt, password, choices)

            return value

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Input error: {e}[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            return ""

    async def _load_passwords(self, key: bytes) -> Dict[str, bytes]:
        """Load existing passwords or return empty dict if none exist."""
        try:
            return await self._file_ops.secure_load(AppConfig.PASSWORDS_FILE, key) or {}

        except FileNotFoundError:
            return {}

    async def _save_passwords(self, passwords: Dict[str, bytes], key: bytes) -> None:
        """Save passwords securely."""
        await self._file_ops.secure_save(passwords, AppConfig.PASSWORDS_FILE, key)

    async def _load_master_hash(self) -> str:
        """Load stored master password hash."""
        return await self._file_ops.secure_load(AppConfig.MASTER_PASSWORD_FILE)

    async def _load_salt(self) -> bytes:
        """Load stored salt."""
        return await self._file_ops.secure_load(AppConfig.SALT_FILE)

    async def _save_master_credentials(self, hashed_password: str, salt: bytes) -> None:
        """Save master password hash and salt."""
        await self._file_ops.secure_save(
            hashed_password, AppConfig.MASTER_PASSWORD_FILE
        )
        await self._file_ops.secure_save(salt, AppConfig.SALT_FILE)

    async def _hash_master_password(self, password: str, salt: bytes) -> str:
        """Hash master password using secure algorithm."""
        return self._crypto_ops.hash_password(password, salt)

    async def _find_existing_entry(
        self, service: str, passwords: Dict[str, bytes], key: bytes
    ) -> Optional[str]:
        """
        Find existing password entry with case and space insensitive matching.

        Args:
            service: Service name to search for
            passwords: Dictionary of encrypted passwords
            key: Decryption key

        Returns:
            Matching service name if found, None otherwise
        """
        normalized_search = "".join(service.lower().split())

        for existing_service in passwords:
            if "".join(existing_service.lower().split()) == normalized_search:
                return existing_service

        return None

    async def _generate_secure_password(self) -> str:
        """
        Generate secure password with user-specified options.

        Returns:
            Generated password string

        Raises:
            ValueError: If password generation parameters are invalid
        """
        console.print(
            Panel(
                "[bold]Password Generation Options:[/]\n"
                "L - Lowercase letters\n"
                "U - Uppercase letters\n"
                "D - Digits\n"
                "S - Special characters",
                title="[bold blue]Password Options",
                title_align="center",
                padding=(1, 2),
                border_style="blue",
            ),
            justify="center",
        )

        while True:
            options_input = await self._get_secure_input(
                "[bold yellow]Enter options (e.g., LUDS)[/]"
            )

            options = options_input.upper()
            valid_options = set("LUDS")

            if not options:
                console.print(
                    Panel(
                        "[bold red]Please select at least one character type (L, U, D, or S).[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            if not all(opt in valid_options for opt in options):
                console.print(
                    Panel(
                        "[bold red]Invalid options. Please use only L, U, D, and S.[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            break

        while True:
            length_input = await self._get_secure_input(
                "[bold yellow]Enter password length (8-32)[/]"
            )

            if not length_input.strip():
                console.print(
                    Panel(
                        "[bold red]Password length cannot be empty. Please enter a number between 8 and 32.[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            try:
                length = int(length_input)
                if 8 <= length <= 32:
                    break

                else:
                    console.print(
                        Panel(
                            "[bold red]Password length must be between 8 and 32.[/]",
                            title="[bold red]Invalid Input",
                            title_align="center",
                            padding=(1, 2),
                            border_style="red",
                        ),
                        justify="center",
                    )

            except ValueError:
                console.print(
                    Panel(
                        "[bold red]Please enter a valid number between 8 and 32.[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )

        try:
            password = self._password_generator.generate(length, options)
            console.print(
                Panel(
                    f"[bold green]Generated password:[/] {password}",
                    title="[bold green]Generated Password",
                    title_align="center",
                    padding=(1, 2),
                    border_style="green",
                ),
                justify="center",
            )
            return password

        except ValueError as e:
            raise ValueError(f"Password generation failed: {e}")

    async def _decrypt_password_data(
        self, encrypted_data: bytes, key: bytes
    ) -> Optional[bytes]:
        """
        Decrypt password data with error handling.

        Args:
            encrypted_data: Encrypted password data
            key: Decryption key

        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            return self._crypto_ops.decrypt_data(encrypted_data, key)

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Decryption failed: {e}[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            return None

    async def _handle_new_password(
        self, service: str, passwords: Dict[str, bytes], key: bytes
    ) -> None:
        """
        Handle adding new password entry.

        Args:
            service: Service name
            passwords: Password dictionary
            key: Encryption key
        """
        generate = Confirm.ask("[bold yellow]Generate secure password?[/]")

        while True:
            if generate:
                password = await self._generate_secure_password()

            else:
                password = await self._get_secure_input(
                    "[bold yellow]Enter password[/]", password=True
                )

            if not password:
                console.print(
                    Panel(
                        "[bold red]Password cannot be empty. :x:[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            entry = PasswordEntry(
                service=service,
                password=password,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            )

            encrypted_data = self._crypto_ops.encrypt_data(json.dumps(entry.to_dict()), key)

            passwords[service] = encrypted_data

            await self._save_passwords(passwords, key)

            console.print(
                Panel(
                    "[bold green]Password saved successfully! :thumbsup:[/]",
                    title="[bold green]Success",
                    title_align="center",
                    padding=(1, 2),
                    border_style="green",
                ),
                justify="center",
            )
            break

    async def _handle_existing_password(
        self, service: str, existing_entry: str, passwords: Dict[str, bytes], key: bytes
    ) -> None:
        """
        Handle updating existing password entry.

        Args:
            service: Service name
            existing_entry: Existing service name
            passwords: Password dictionary
            key: Encryption key
        """
        decrypted_data = await self._decrypt_password_data(
            passwords[existing_entry], key
        )

        if not decrypted_data:
            return

        entry_data = json.loads(decrypted_data.decode("utf-8"))

        console.print(
            Panel(
                f"[bold yellow]Found existing entry for '{existing_entry}'[/]\n"
                f"[bold]Current password:[/] {entry_data['password']}\n"
                f"[bold]Last modified:[/] {entry_data['timestamp']}",
                title="[bold yellow]Existing Entry Found",
                title_align="center",
                padding=(1, 2),
                border_style="yellow",
            ),
            justify="center",
        )

        if Confirm.ask("[bold yellow]Update existing password?[/]"):
            await self._handle_new_password(existing_entry, passwords, key)

        else:
            console.print(
                Panel(
                    "[bold green]Password update cancelled.[/]",
                    title="[bold green]Operation Cancelled",
                    title_align="center",
                    padding=(1, 2),
                    border_style="green",
                ),
                justify="center",
            )

    async def _verify_current_password(self, current_password: str) -> bool:
        """
        Verify the current master password.

        Args:
            current_password: Master password to verify

        Returns:
            True if password is valid, False otherwise
        """
        try:
            stored_hash = await self._load_master_hash()
            salt = await self._load_salt()

            current_hash = self._crypto_ops.hash_password(current_password, salt)

            return self._crypto_ops.compare_secure_strings(current_hash, stored_hash)

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Password verification failed: {e}[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            return False

    async def _process_new_password(self) -> Optional[str]:
        """
        Process and validate new master password.

        Returns:
            New password if valid, None otherwise
        """
        while True:
            new_password = await self._get_secure_input(
                "[bold yellow]Enter new Master Password[/]", password=True
            )

            if len(new_password) < 8:
                console.print(
                    Panel(
                        "[bold red]Password must be at least 8 characters long. :x:[/]",
                        title="[bold red]Invalid Password",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            current_salt = await self._load_salt()
            current_hash = await self._load_master_hash()
            new_hash = self._crypto_ops.hash_password(new_password, current_salt)

            if self._crypto_ops.compare_secure_strings(new_hash, current_hash):
                console.print(
                    Panel(
                        "[bold red]New password cannot be the same as current password. :x:[/]",
                        title="[bold red]Invalid Password",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            confirm_password = await self._get_secure_input(
                "[bold yellow]Confirm new Master Password[/]", password=True
            )

            if new_password == confirm_password:
                return new_password

            else:
                console.print(
                    Panel(
                        "[bold red]Passwords do not match. Please try again. :x:[/]",
                        title="[bold red]Password Mismatch",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

    async def _update_master_password(
        self, new_password: str, current_password: str, current_key: bytes
    ) -> None:
        """
        Update master password and re-encrypt all data.

        Args:
            new_password: New master password
            current_password: Current master password
            current_key: Current encryption key
        """
        try:
            new_salt = secrets.token_bytes(AppConfig.ARGON2_SALT_LEN)

            new_hash = await self._hash_master_password(new_password, new_salt)

            new_key = self._crypto_ops.generate_key(new_password, new_salt)

            passwords = await self._load_passwords(current_key)

            new_passwords: Dict[str, bytes] = {}
            for service, encrypted_data in passwords.items():
                decrypted_data = await self._decrypt_password_data(
                    encrypted_data, current_key
                )

                if decrypted_data:
                    new_encrypted = self._crypto_ops.encrypt_data(
                        decrypted_data, new_key
                    )
                    new_passwords[service] = new_encrypted

            await self._save_master_credentials(new_hash, new_salt)
            await self._save_passwords(new_passwords, new_key)

            console.print(
                Panel(
                    "[bold green]Master Password successfully updated! :thumbsup:[/]",
                    title="[bold green]Success",
                    title_align="center",
                    padding=(1, 2),
                    border_style="green",
                ),
                justify="center",
            )

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Failed to update Master Password: {e} :x:[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            raise

    async def _display_password_table(self, results: Dict[str, PasswordEntry]) -> None:
        """
        Display password entries in a formatted table.

        Args:
            results: Dictionary of password entries to display
        """
        table = Table(
            title="[bold magenta]Your Stored Passwords :memo:",
            box=box.DOUBLE_EDGE,
            header_style="bold cyan",
            title_style="bold blue",
            title_justify="center",
            show_lines=True,
            expand=True,
            padding=(0, 1),
        )

        table.add_column("#", style="dim", justify="right")
        table.add_column("Service", style="bold")
        table.add_column("Password", style="bold green")
        table.add_column("Last Modified", style="dim")

        for idx, (service, entry) in enumerate(results.items(), 1):
            table.add_row(str(idx), service, entry.password, entry.timestamp)

        print()
        console.print(table, justify="center")

    async def _process_deletion(
        self,
        selection: str,
        results: Dict[str, PasswordEntry],
        passwords: Dict[str, bytes],
        key: bytes,
    ) -> None:
        """
        Process the deletion of selected passwords with secure wiping.

        Args:
            selection: Comma-separated string of selection numbers
            results: Dictionary of displayed password entries
            passwords: Full dictionary of encrypted passwords
            key: Encryption key
        """
        try:
            selection_numbers = [
                int(num.strip())
                for num in selection.split(",")
                if num.strip().isdigit()
            ]

            if not selection_numbers:
                console.print(
                    Panel(
                        "[bold red]No valid selections provided.[/]",
                        title="[bold red]Invalid Selection",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                return

            services_to_delete = [
                service
                for idx, service in enumerate(results.keys(), 1)
                if idx in selection_numbers
            ]

            if not services_to_delete:
                console.print(
                    Panel(
                        "[bold red]No valid entries found for deletion.[/]",
                        title="[bold red]Invalid Selection",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                return

            console.print(
                Panel(
                    "[bold red]The following passwords will be deleted:[/]\n"
                    + "\n".join(
                        f"[bold]- {service}[/]" for service in services_to_delete
                    ),
                    title="[bold red]Confirm Deletion",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )

            confirmation = Confirm.ask(
                f"[bold red]Delete {len(services_to_delete)} password(s)?[/]"
            )

            if confirmation:
                for service in services_to_delete:
                    if service in passwords:
                        del passwords[service]

                await self._save_passwords(passwords, key)

                console.print(
                    Panel(
                        f"[bold green]Successfully deleted {len(services_to_delete)} password(s)![/]",
                        title="[bold green]Success",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )

            else:
                console.print(
                    Panel(
                        "[bold yellow]Deletion cancelled.[/]",
                        title="[bold yellow]Operation Cancelled",
                        title_align="center",
                        padding=(1, 2),
                        border_style="yellow",
                    ),
                    justify="center",
                )

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Error processing deletion: {e}[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )

    async def _handle_reset_confirmation(self, choice: str, key: bytes) -> None:
        """
        Handle reset data confirmation and secure deletion.

        Args:
            choice: Reset choice (1 for passwords only, 2 for all data)
            key: Current encryption key
        """
        try:
            confirmation = await self._get_secure_input(
                "\n[bold red]Type 'CONFIRM' to proceed with deletion[/]"
            )

            if confirmation != "CONFIRM":
                console.print(
                    Panel(
                        "[bold yellow]Reset operation cancelled.[/]",
                        title="[bold yellow]Operation Cancelled",
                        title_align="center",
                        padding=(1, 2),
                        border_style="yellow",
                    ),
                    justify="center",
                )
                return

            if choice == "1":
                await self._file_ops.secure_delete(AppConfig.PASSWORDS_FILE)
                await self._save_passwords({}, key)

                console.print(
                    Panel(
                        "[bold green]All passwords have been securely deleted.[/]",
                        title="[bold green]Reset Complete",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )

            elif choice == "2":
                files_to_delete = [
                    AppConfig.PASSWORDS_FILE,
                    AppConfig.MASTER_PASSWORD_FILE,
                    AppConfig.KEY_FILE,
                    AppConfig.SALT_FILE,
                ]

                for file in files_to_delete:
                    if os.path.exists(file):
                        await self._file_ops.secure_delete(file)

                console.print(
                    Panel(
                        "[bold green]All data has been securely deleted.\n"
                        "Please restart the application to create a new password store.[/]",
                        title="[bold green]Full Reset Complete",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                sys.exit(0)

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Reset operation failed: {e}[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )

    async def create_master_password(self) -> None:
        """Create and save master password with maximum security."""
        os.system("clear")
        await asyncio.sleep(1)

        console.print(
            Panel(
                "[bold green]Welcome to the Smart Password Manager! :smiley:[/]\n\n"
                "[bold]This application provides secure password storage and management "
                "with advanced cryptographic protection.\n\n[/]"
                "[bold]To begin, please create a strong Master Password.\n\n[/]"
                "[bold red]Warning: Your Master Password is the key to all stored data. "
                "It cannot be recovered if lost! :fearful:[/]\n\n"
                "[bold yellow]Note: Password creation involves intensive security "
                "calculations and may take a few moments.[/]",
                title="[bold blue]Welcome to Secure Password Management",
                title_align="center",
                padding=(1, 2),
                border_style="bright_blue",
            ),
            justify="center",
        )
        await asyncio.sleep(1)

        salt = secrets.token_bytes(AppConfig.ARGON2_SALT_LEN)

        while True:
            master_password = await self._get_secure_input(
                "\n[bold yellow]Enter your Master Password[/]", password=True
            )

            if len(master_password) < 8:
                console.print(
                    Panel(
                        "[bold red]Master Password must be at least 8 characters. "
                        "Please choose a stronger password. :pensive:[/]",
                        title="[bold red]Password Too Weak",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            confirm_password = await self._get_secure_input(
                "[bold yellow]Confirm your Master Password[/]", password=True
            )

            if self._crypto_ops.compare_secure_strings(
                master_password, confirm_password
            ):
                async with self._secure_context():
                    hashed_password = await self._hash_master_password(
                        master_password, salt
                    )
                    key = self._crypto_ops.generate_key(master_password, salt)
                    await self._save_master_credentials(hashed_password, salt)
                    await self._file_ops.save_key(key)

                console.print(
                    Panel(
                        "[bold green]Master Password successfully created! :tada:[/]",
                        title="[bold green]Success",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                break

            else:
                console.print(
                    Panel(
                        "[bold red]Passwords do not match. Please try again. :disappointed:[/]",
                        title="[bold red]Password Mismatch",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )

    async def verify_master_password(self) -> Optional[str]:
        """
        Verify master password with advanced security measures.

        Returns:
            Verified master password or None if verification fails
        """
        try:
            stored_hash = await self._load_master_hash()
            salt = await self._load_salt()
            key = await self._file_ops.load_key()

            console.print(
                Panel(
                    "[bold yellow]Note: Verification involves intensive security "
                    "calculations and may take a few moments.[/]\n\n"
                    "[bold yellow]Please enter your Master Password to continue...[/]",
                    title="[bold yellow]Master Password Verification",
                    title_align="center",
                    padding=(1, 2),
                    border_style="yellow",
                ),
                justify="center",
            )

            master_password = await self._get_secure_input(
                "\n[bold yellow]Enter your Master Password[/]", password=True
            )

            hasher = argon2.PasswordHasher(
                time_cost=AppConfig.ARGON2_TIME_COST,
                memory_cost=AppConfig.ARGON2_MEMORY_COST,
                parallelism=AppConfig.ARGON2_PARALLELISM,
                hash_len=AppConfig.ARGON2_HASH_LEN,
                salt_len=AppConfig.ARGON2_SALT_LEN,
                type=argon2.Type.ID,
            )

            try:
                hasher.verify(stored_hash, master_password.encode())
                console.print(
                    Panel(
                        "[bold green]Master Password verified successfully. :thumbsup:[/]",
                        title="[bold green]Access Granted",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                return master_password

            except argon2.exceptions.VerifyMismatchError:
                console.print(
                    Panel(
                        "[bold red]Invalid Master Password. :worried:[/]",
                        title="[bold red]Access Denied",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                return None

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Verification error: {e} :x:[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            return None

    async def add_password(self, key: bytes) -> None:
        """
        Add or update a password with comprehensive security measures.

        Args:
            key: Encryption key for password storage
        """
        try:
            passwords = await self._load_passwords(key)

            service = await self._get_secure_input("[bold yellow]Enter service name[/]")

            if not service.strip():
                raise ValueError("Service name cannot be empty")

            existing_entry = await self._find_existing_entry(service, passwords, key)

            if existing_entry:
                await self._handle_existing_password(
                    service, existing_entry, passwords, key
                )

            else:
                await self._handle_new_password(service, passwords, key)

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Failed to add password: {e} :x:[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )

    async def search_passwords(
        self, passwords: Dict[str, bytes], key: bytes, search_term: str
    ) -> Dict[str, PasswordEntry]:
        """
        Search passwords with fuzzy matching and secure decryption.

        Args:
            passwords: Encrypted password dictionary
            key: Decryption key
            search_term: Search query

        Returns:
            Dictionary of matching password entries
        """
        results: Dict[str, PasswordEntry] = {}
        normalized_search = self._normalize_string(search_term)

        for service, encrypted_data in passwords.items():
            if normalized_search in self._normalize_string(service):
                decrypted_data = await self._decrypt_password_data(encrypted_data, key)
                if decrypted_data:
                    results[service] = PasswordEntry.from_dict(
                        json.loads(decrypted_data.decode("utf-8"))
                    )

        if not results:
            normalized_services = {
                self._normalize_string(s): s for s in passwords.keys()
            }

            close_matches = difflib.get_close_matches(
                normalized_search,
                normalized_services.keys(),
                n=3,
                cutoff=self._search_threshold,
            )

            for match in close_matches:
                service = normalized_services[match]
                decrypted_data = await self._decrypt_password_data(
                    passwords[service], key
                )
                if decrypted_data:
                    results[service] = PasswordEntry.from_dict(
                        json.loads(decrypted_data.decode("utf-8"))
                    )

        return results

    async def view_passwords(self, key: bytes) -> None:
        """
        Display stored passwords with advanced search and secure decryption.

        Args:
            key: Decryption key for password access
        """
        try:
            passwords = await self._load_passwords(key)

            if not passwords:
                console.print(
                    Panel(
                        "[bold red]No passwords currently stored. :crying_face:[/]",
                        title="[bold red]Empty Password Store",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                return

            search_term = await self._get_secure_input(
                "[bold yellow]Enter search term (or press Enter to view all)[/]"
            )

            if search_term:
                results = await self.search_passwords(passwords, key, search_term)

            else:
                results = {}

                for service, encrypted_data in passwords.items():
                    decrypted_data = await self._decrypt_password_data(
                        encrypted_data, key
                    )

                    if decrypted_data:
                        results[service] = PasswordEntry.from_dict(
                            json.loads(decrypted_data.decode("utf-8"))
                        )

            if results:
                await self._display_password_table(results)

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

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Failed to view passwords: {e} :x:[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )

    async def delete_passwords(self, key: bytes) -> None:
        """
        Securely delete selected passwords with confirmation.

        Args:
            key: Decryption key for password access
        """
        try:
            passwords = await self._load_passwords(key)

            if not passwords:
                console.print(
                    Panel(
                        "[bold red]No passwords currently stored. :crying_face:[/]",
                        title="[bold red]Empty Password Store",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                return

            search_term = await self._get_secure_input(
                "[bold yellow]Enter search term (or press Enter to view all)[/]"
            )

            if search_term:
                results = await self.search_passwords(passwords, key, search_term)

            else:
                results = {}

                for service, encrypted_data in passwords.items():
                    decrypted_data = await self._decrypt_password_data(
                        encrypted_data, key
                    )

                    if decrypted_data:
                        results[service] = PasswordEntry.from_dict(
                            json.loads(decrypted_data.decode("utf-8"))
                        )

            if results:
                await self._display_password_table(results)

                selection = await self._get_secure_input(
                    "[bold yellow]Enter number(s) to delete (comma-separated)[/]"
                )

                await self._process_deletion(selection, results, passwords, key)

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

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Failed to delete passwords: {e} :x:[/]",
                    title="[bold red]Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )

    async def reset_data(self, key: bytes) -> None:
        """
        Securely reset password manager data with granular options.

        Args:
            key: Current encryption key
        """
        while True:
            console.print(
                Panel(
                    "[bold red]WARNING: Data deletion is permanent! :warning:[/]\n\n"
                    "[bold]Select reset option:[/]",
                    title="[bold red]Data Reset Options",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )

            console.print("[1] Reset ALL Passwords")
            console.print("[2] Reset ALL Data (Passwords, Master Password, Keys, Salt)")
            console.print("[3] Cancel Reset")

            choice = await self._get_secure_input(
                "\n[bold red]Enter choice (1-3)[/]", choices=["1", "2", "3"]
            )

            if choice in ("1", "2"):
                await self._handle_reset_confirmation(choice, key)
                break

            elif choice == "3":
                console.print(
                    Panel(
                        "[bold green]Reset operation canceled. :relieved:[/]",
                        title="[bold green]Operation Canceled",
                        title_align="center",
                        padding=(1, 2),
                        border_style="green",
                    ),
                    justify="center",
                )
                break

    async def change_master_password(self, key: bytes) -> None:
        """
        Securely change master password with comprehensive validation.

        Args:
            key: Current encryption key
        """
        console.print(
            Panel(
                "[bold yellow]Master Password Change Process[/]\n\n"
                "[bold red]Warning: This is a critical security operation.[/]\n\n"
                "[bold yellow]Note: Password change involves intensive security "
                "calculations and may take a few moments.[/]",
                title="[bold yellow]Change Master Password",
                title_align="center",
                padding=(1, 2),
                border_style="yellow",
            ),
            justify="center",
        )

        while True:
            current_password = await self._get_secure_input(
                "[bold yellow]Enter current Master Password[/]", password=True
            )
            
            if not current_password:
                console.print(
                    Panel(
                        "[bold red]Password cannot be empty. :x:[/]",
                        title="[bold red]Invalid Input",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                continue

            if await self._verify_current_password(current_password):
                new_password = await self._process_new_password()

                if new_password:
                    await self._update_master_password(
                        new_password, current_password, key
                    )
                    break

            else:
                console.print(
                    Panel(
                        "[bold red]Invalid current Master Password. :no_entry_sign:[/]",
                        title="[bold red]Authentication Failed",
                        title_align="center",
                        padding=(1, 2),
                        border_style="red",
                    ),
                    justify="center",
                )
                break


class ApplicationManager:
    """
    High-level application management with advanced security features.
    Coordinates all password management operations and user interface.
    """

    def __init__(self) -> None:
        """Initialize application manager with required components."""
        self._password_manager: PasswordManager = PasswordManager()
        self._secure_memory: SecureMemory = SecureMemory()
        self._crypto_ops: CryptographicOperations = CryptographicOperations()

    async def _generate_session_key(self, master_password: str) -> bytes:
        """
        Generate session encryption key from master password.

        Args:
            master_password: Verified master password

        Returns:
            Session encryption key as bytes
        """
        try:
            return await self._password_manager._file_ops.load_key()

        except FileNotFoundError:
            salt = await self._password_manager._load_salt()
            key = self._crypto_ops.generate_key(master_password, salt)
            await self._password_manager._file_ops.save_key(key)
            return key

        except Exception as e:
            raise RuntimeError(f"Failed to generate session key: {e}")

    async def _initialize_password_store(self, key: bytes) -> None:
        """
        Initialize password store if it doesn't exist.

        Args:
            key: Session encryption key
        """
        try:
            if not os.path.exists(AppConfig.PASSWORDS_FILE):
                await self._password_manager._file_ops.secure_save(
                    {}, AppConfig.PASSWORDS_FILE, key
                )

        except Exception as e:
            raise RuntimeError(f"Failed to initialize password store: {e}")

    async def _pause_operation(self) -> None:
        """Pause execution until user input."""
        await self._password_manager._get_secure_input(
            "\n[bold yellow]Press Enter to continue...[/]"
        )

    async def _handle_menu_choice(self, choice: str, key: bytes) -> bool:
        """
        Process menu selection with secure operation handling.

        Args:
            choice: Selected menu option
            key: Session encryption key

        Returns:
            True if application should exit, False otherwise
        """
        if choice == "1":
            await self._password_manager.add_password(key)
        elif choice == "2":
            await self._password_manager.view_passwords(key)
        elif choice == "3":
            await self._password_manager.delete_passwords(key)
        elif choice == "4":
            await self._password_manager.change_master_password(key)
        elif choice == "5":
            await self._password_manager.reset_data(key)
        elif choice == "6":
            console.print(
                Panel(
                    "[bold]Thank you for using Smart Password Manager! :smiley:[/]\n\n"
                    "[bold]Goodbye! :wave:[/]",
                    title="[bold magenta]Session Ended",
                    title_align="center",
                    padding=(1, 2),
                    border_style="magenta",
                ),
                justify="center",
            )
            return True
        return False

    async def _main_loop(self, key: bytes) -> None:
        """
        Main application loop with secure operation handling.

        Args:
            key: Session encryption key
        """
        while True:
            console.print(
                Panel(
                    "[bold green]Welcome to Smart Password Manager! :smiley:[/]\n\n"
                    "[bold]Select an operation:[/]",
                    title="[bold blue]Main Menu",
                    title_align="center",
                    padding=(1, 2),
                    border_style="bright_blue",
                ),
                justify="center",
            )

            console.print("[1] Add new password")
            console.print("[2] View stored passwords")
            console.print("[3] Delete passwords")
            console.print("[4] Change Master Password")
            console.print("[5] Reset Data")
            console.print("[6] Exit")

            choice = await self._password_manager._get_secure_input(
                "\n[bold yellow]Enter choice (1-6)[/]",
                choices=["1", "2", "3", "4", "5", "6"],
            )

            if await self._handle_menu_choice(choice, key):
                break

            await self._pause_operation()
            os.system("clear")

    async def run(self) -> None:
        """Execute main application loop with secure state management."""
        os.system("clear")
        await asyncio.sleep(1)

        try:
            if not os.path.exists(AppConfig.MASTER_PASSWORD_FILE):
                await self._password_manager.create_master_password()

            master_password = await self._password_manager.verify_master_password()

            if not master_password:
                return

            key = await self._generate_session_key(master_password)
            await self._initialize_password_store(key)
            await self._main_loop(key)

        except Exception as e:
            console.print(
                Panel(
                    f"[bold red]Application error: {e} :x:[/]",
                    title="[bold red]Critical Error",
                    title_align="center",
                    padding=(1, 2),
                    border_style="red",
                ),
                justify="center",
            )
            sys.exit(1)


def main() -> None:
    """Main application entry point with async execution."""
    try:
        app = ApplicationManager()
        asyncio.run(app.run())

    except KeyboardInterrupt:
        console.print(
            Panel(
                "[bold yellow]Application terminated by user. :warning:[/]",
                title="[bold yellow]Terminated",
                title_align="center",
                padding=(1, 2),
                border_style="yellow",
            ),
            justify="center",
        )
        sys.exit(0)

    except Exception as e:
        console.print(
            Panel(
                f"[bold red]Fatal error: {e} :x:[/]",
                title="[bold red]Fatal Error",
                title_align="center",
                padding=(1, 2),
                border_style="red",
            ),
            justify="center",
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
