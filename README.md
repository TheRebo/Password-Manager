# 🛡️ Smart Password Manager

![Smart Password Manager Logo](https://github.com/user-attachments/assets/5f130cc4-c6ab-4509-af84-2b74c7e75492)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<div align="center">
  <h1>
    A sophisticated, secure, and user-friendly command-line password manager built with Python.
    Ensuring your passwords remain private and protected with military-grade encryption.
  </h1>
</div>

<p align="center">
  <strong>
    <em>
      "Securing Your Digital Life with Precision, Guarding Your Privacy with Dedication"
    </em>
  </strong>
</p>

---
> **Note:** For Indonesian users, please check the Branch for Indonesian translations. (Translations for v3.0+ will follow soon after I finished a BIG update!)
---

## 📑 Table of Contents
- [🌟 Key Features](#-key-features)
- [🔒 Security Features](#-security-features)
- [🛠️ Installation](#️-installation)
- [📖 Usage Guide](#-usage-guide)
- [🔄 Program Flow](#-program-flow)
- [📁 File Structure](#-file-structure)
- [❓ FAQ](#-faq)
- [⚠️ Limitations & Warnings](#️-limitations--warnings)
- [🔍 Technical Details](#-technical-details)
- [📜 License](#-license)
- [👥 Contributing](#-contributing)
- [📞 Support](#-support)
- [⚠️ Disclaimer](#-disclaimer)
- [📝 Changelog](#-changelog)

## 🌟 Key Features
- **Advanced Encryption**: Military-grade AES-256-GCM encryption with Argon2id key derivation
- **Secure Memory Management**: *Protected memory allocation and secure wiping
- **Side-Channel Attack Protection**: *Timing attack defenses and constant-time operations
- **Smart Search**: Fuzzy matching for password lookup
- **Async Operations**: Modern asynchronous design for better performance
- **Comprehensive UI**: Rich terminal interface with intuitive controls
- **Secure Password Generation**: Customizable strong password creation
- **Data Protection**: Secure file operations with proper cleanup
- **Cross-Platform**: **Works on Windows, macOS, and Linux

*using temporary methods

**while you can install Python 3.7+ and its dependencies properly

## 🔒 Security Features
- **Zero Trust Architecture**: All data encrypted locally
- **Memory Protection**: *Secure allocation and wiping of sensitive data
- **Side-Channel Defense**: *Protection against timing and other side-channel attacks
- **Secure Key Derivation**: Argon2id with high memory and time cost parameters
- **Protected Storage**: *Encrypted file storage with secure deletion
- **Constant-Time Operations**: *Cryptographic operations resistant to timing analysis
- **Session Security**: Secure key handling during program runtime

*using temporary methods

### 🔐 Password Strength Simulation
The program encryption process:
1. **Master Password** → Argon2id hashing (memory-hard function)
2. **Generated Key** → 256-bit AES encryption
3. **Stored Passwords** → Encrypted with AES-GCM

Time to crack (estimated):
- Weak password (8 chars): Several years
- Strong password (12+ chars): Millions of years

## 🛠️ Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/TheRebo/Password-Manager.git
   cd Password-Manager
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 📖 Usage Guide
1. Run the program:
   ```bash
   python pass-man.py
   ```
2. Create a strong master password
3. Use the interactive menu to:
   - Add new passwords
   - View stored passwords
   - Delete passwords
   - Change master password
   - Reset data if needed

## 🔄 Program Flow
![flowchart-mermaid](https://github.com/user-attachments/assets/a94f5c48-e3e8-4fe4-adc8-a405cf0295b7)
*this flowchart only illustrates the main flow of the program.

**and sorry for the white background (⁠.⁠ ⁠❛⁠ ⁠ᴗ⁠ ⁠❛⁠.⁠)

## 📁 File Structure
- `passwords.dat`: Encrypted storage of your passwords
- `master_password.dat`: Hashed master password
- `key.dat`: Encrypted key file
- `salt.dat`: Cryptographic salt

All files use secure encryption and are only accessible with your master password.

## ❓ FAQ
1. **Q: What happens if I forget my master password?**  
   A: There is no recovery option. Your data is unrecoverable without the master password.

2. **Q: Is my data synced to the cloud?**  
   A: No, all data is stored locally for maximum security.

3. **Q: Can the developer access my passwords?**  
   A: No, your passwords are encrypted locally and never transmitted anywhere.

## ⚠️ Limitations & Warnings
- **No Password Recovery**: Your master password cannot be recovered if forgotten
- **Local Storage Only**: No cloud sync or backup features
- **CLI Interface**: No graphical user interface

## 🚫 What Not to Do
- **Don't** forget your master password
- **Don't** share your master password
- **Don't** manually edit the data files
- **Don't** attempt to decrypt files outside the program

## 🔍 Technical Details
- **Language**: Python 3.7+
- **Encryption**: AES-256-GCM
- **Key Derivation**: Argon2id (time-cost=16, memory-cost=2^18, parallelism=2)
- **UI Framework**: Rich (Terminal UI)

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support
If you encounter any issues or have questions, please open an issue on GitHub.

## ⚠️ Disclaimer
This password manager is provided for personal use only.
The creator is not responsible for any data loss or security breaches that may occur from using this software.
This project was aided by AI and human collaboration. While every effort has been made to ensure its security and functionality, use it at your own risk.

## 📝 Changelog
```markdown
## [W.I.P] (Work In Progress)
Too many to list, just stay tuned!

## [v4.0.0] - 2024-10-28
In changelog file.

## [v3.15.0] - 2024-09-08
In changelog file.

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

# Made with ❤️ by Na'im Annafi Santosa ([TheRebo](https://github.com/TheRebo))
