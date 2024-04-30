# Smart Password Manager

[![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Smart Password Manager is a secure and user-friendly Python script that allows you to store, view, and manage your passwords for different services. With encryption and a master password, your data remains safe while being easily accessible.

> **Note:** For Indonesian users, please check the Branch, because there are Indonesian translations available.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Things to Know](#things-to-know)
- [Things Not to Do](#things-not-to-do)
- [Potential Bugs](#potential-bugs)
- [Changelog](#changelog)
- [Disclaimer](#disclaimer)
- [License](#license)

## Features

- **Secure Password Storage:** Passwords are encrypted using the industry-standard Fernet encryption algorithm from the `cryptography` library, ensuring maximum security.
- **Master Password Protection:** All your passwords are protected by a single, strong master password that you create during the initial setup.
- **Random Password Generation:** The program can generate strong, random passwords for you with a customizable length.
- **Password Viewing:** View all your stored passwords in a neat table format.
- **Password Deletion:** Delete passwords for services you no longer use.
- **Rich User Interface:** The program uses the `rich` library to provide a visually appealing and easy-to-use interface with colors, panels, and formatting.
- **Timestamp Tracking:** Each password entry is timestamped, so you know when it was added.

## Installation

1. Clone the repository or download the source code:

```
git clone https://github.com/TheRebo/Password-Manager.git
```

2. Install the required dependencies by running:

```
pip install -r requirements.txt
```

## Usage

1. Run the script with Python:

```
python pass-man.py
```

2. On the first run, you will be prompted to create a strong master password. This password is used to encrypt and decrypt your stored passwords, so make sure to remember it.

3. After creating the master password, you can choose from the following options:
   - Add a new password
   - View your stored passwords
   - Delete a password
   - Exit

4. Follow the on-screen instructions to perform the desired action.

## Things to Know

- Your master password is the key to all your stored passwords. **There is no way to recover it if you forget it.**
- Passwords are stored in an encrypted format in the `passwords.dat` file.
- The master password hash and encryption key are stored in `master_password.dat` and `key.dat` files, respectively.
- Each time you add a password, the password and the timestamp of addition are combined and encrypted before being stored.

## Things Not to Do

- **Do not** share your master password with anyone.
- **Do not** modify or delete the `passwords.dat`, `master_password.dat`, or `key.dat` files manually.
- **Do not** run the script with administrative privileges unless necessary.

## Potential Bugs

- If the encryption key (`key.dat`) is lost or corrupted, you will not be able to decrypt your stored passwords.
- If the `master_password.dat` file is corrupted, you may not be able to verify your master password.
- If the `passwords.dat` file is corrupted, your stored passwords may become inaccessible.

## Changelog

```markdown
## [Unreleased]
- Trying to strengthen its encryption method.
- Detect any changes in the program code (so that the Master Password function cannot be deleted).
- The database files can only be deleted through this program.

## [2.0.0] - 2024-04-30

- Now Fully Using the "Rich" Module.

## [1.1.0] - 2023-12-05

- Added Color (Colorama).

## [1.0.2] - 2023-11-30

- A Little Bugfix and Improvement.

## [1.0.1] - 2023-11-26

- A Little Bugfix.

## [1.0.0] - 2023-11-18

- Initial Released :)
```
## Disclaimer

This program was created with the assistance of an AI language model. The author takes full responsibility for its content and functionality.
**Use this program at your own risk**. The author is not responsible for any loss or damage caused by the use of this program.

## License

This program is licensed under the GNU Affero General Public License v3.0.
