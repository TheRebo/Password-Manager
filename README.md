# 🛡️ Smart Password Manager

## 🚀 Program Description

[![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Smart Password Manager** is a sophisticated Python script designed to securely store, view, and manage your passwords for various services. This tool ensures that your sensitive information is well-protected using advanced encryption methods.

> **Note:** For Indonesian users, please check the Branch, because there are Indonesian translations available. (**Translations for v3.0 will follow soon!**)

---

## ✨ Features

- 🔒 **Secure Storage**: Store your passwords with `256-bit AES` encryption.
- 🗂️ **Easy Management**: View and delete passwords effortlessly.
- 🔑 **Master Password Protection**: Secure your data with a strong master password.
- 🎲 **Random Password Generation**: Create strong passwords using the built-in generator.
- ⏰ **Timestamp Tracking:** Each password entry is timestamped, so you know when it was added.
- 💻 **Rich UI**: Interactive command-line interface using `rich`.

---

## 🌟 Highlighted Features

- 🔐 **Advanced Encryption**: Uses `Argon2id` for hashing and key derivation, and `AES-GCM` for encryption and decryption.
- 🖥️ **User-Friendly Interface**: Leverages `rich` for a visually appealing CLI experience.
- 🖥️ **Cross-Platform Compatibility**: Works seamlessly on Windows, macOS, and Linux.

---

## 🛠️ Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/TheRebo/Password-Manager.git
    cd Password-Manager
    ```
2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## 📖 Usage

1. Run the script:
    ```bash
    python pass-man.py
    ```
2. Follow the on-screen prompts to create a master password and manage your passwords.

---

## 📚 Things to Know

- 🔑 Your master password is the key to all your stored passwords. **There is no way to recover it if you forget it.**
- 🔒 Passwords are stored in an encrypted format in the `passwords.dat` file.
- 🔒 The master password hash and encryption key are stored in `master_password.dat` and `key.dat` files, respectively.
- 🧂 The salt are stored in `salt.dat`.

---

## 🚫 Don'ts

- 🚷 **Do Not Forget Your Master Password**: There's no way to recover it if you forget it!
- 🛡️ **Do Not Share Your Master Password**: Keep your master password confidential to ensure security.
- 🚫 **Do Not Delete or Edit the Files Mentioned Above Manually!**: If You don't want to corrupt Your data!.

---

## 📌 Changelog

```markdown
## [W.I.P] (Work In Progress)
Too many to list, just stay tuned!

## [v3.1.0] - 2024-08-27
In changelog file.

## [v3.0.0] - 2024-08-17
From now on the changelog will be included along with the program file.

## [v2.5.0] - 2024-05-20
- Strengthening the security and sophistication of its encryption and decryption mechanisms.
- Increasing the security of its "Master Password" mechanism.
- Added "Change Master Password" feature.
- Added "Data Reset" feature.
- And other minor changes.

## [v2.0.0] - 2024-04-30
- Now Fully Using the "Rich" Module.

## [v1.1.0] - 2023-12-05
- Added Color (Colorama).

## [v1.0.2] - 2023-11-30
- A Little Bugfix and Improvement.

## [v1.0.1] - 2023-11-26
- A Little Bugfix.

## [v1.0.0] - 2023-11-18
- Initial Released :)
```
---

## 📜 License

**Smart Password Manager** is licensed under the GNU Affero General Public License v3.0. You are free to use, modify, and distribute this software under the terms of the AGPL-3.0 license. For more details, see [LICENSE](https://www.gnu.org/licenses/agpl-3.0.html).

---

## ⚠️ Disclaimer

This project was aided by AI and human collaboration. While every effort has been made to ensure its security and functionality, use it at your own risk.

---

## ❤️ Made By

Developed by Na'im Annafi Santosa ([TheRebo](https://github.com/TheRebo)).

---

Thank you for using **Smart Password Manager**! Your feedback and contributions are welcome.
