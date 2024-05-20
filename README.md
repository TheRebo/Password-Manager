# 🛡️ Smart Password Manager

## 🚀 Deskripsi Program

[![License](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Smart Password Manager** adalah skrip Python yang canggih yang dirancang untuk menyimpan, menampilkan, dan mengelola password kamu untuk berbagai layanan dengan aman. Alat ini memastikan informasi sensitif kamu terlindungi dengan metode enkripsi canggih.

---

## ✨ Fitur

- 🔒 **Penyimpanan Aman**: Simpan password kamu dengan enkripsi AES 256-bit.
- 🗂️ **Pengelolaan Mudah**: Lihat dan hapus password dengan gampang.
- 🔑 **Perlindungan Master Password**: Amankan data kamu dengan master password yang kuat.
- 🎲 **Pembuat Password Acak**: Buat password kuat menggunakan pembuat bawaan.
- ⏰ **Pelacakan Waktu Entri:** Setiap entri password ditandai waktunya, jadi kamu tahu kapan ditambahkan.
- 💻 **Antarmuka Kaya**: Antarmuka baris perintah interaktif menggunakan `rich`.

---

## 🌟 Fitur Unggulan

- 🔐 **Enkripsi Canggih**: Menggunakan SHA-512 dan PBKDF2HMAC untuk hashing dan derivasi kunci.
- 🖥️ **Antarmuka Ramah Pengguna**: Memanfaatkan `rich` untuk pengalaman CLI yang menarik secara visual.
- 🖥️ **Kompatibilitas Lintas Platform**: Berjalan lancar di Windows, macOS, dan Linux.

---

## 🛠️ Instalasi

1. Kloning repositori:
    ```bash
    git clone --branch Bahasa-Indonesia --single-branch https://github.com/TheRebo/Password-Manager.git
    cd Password-Manager
    ```
2. Instal dependensi yang dibutuhkan:
    ```bash
    pip install -r requirements.txt
    ```

---

## 📖 Penggunaan

1. Jalankan skrip:
    ```bash
    python pass-man-ind.py
    ```
2. Ikuti petunjuk di layar untuk membuat master password dan mengelola password kamu.

---

## 📚 Hal-hal yang Perlu Diketahui

- 🔑 Master password kamu adalah kunci untuk semua password yang disimpan. **Tidak ada cara untuk memulihkannya jika kamu lupa.**
- 🔒 Password disimpan dalam format terenkripsi di file `passwords.dat`.
- 🔒 Hash master password dan kunci enkripsi disimpan di file `master_password.dat` dan `key.dat`.
- 🧂 Salt disimpan di `salt.dat`.

---

## 🚫 Jangan Lakukan

- 🚷 **Jangan Lupa Master Password Kamu**: Tidak ada cara untuk memulihkannya jika kamu lupa!
- 🛡️ **Jangan Bagikan Master Password Kamu**: Jaga kerahasiaan master password kamu untuk memastikan keamanan.

---

## 📌 Changelog

```markdown
## [W.I.P] (Work In Progress)
- Deteksi perubahan kode program (agar fungsi Master Password tidak bisa dihapus).
- File database cuma bisa dihapus lewat program ini (hampir mustahil).
- Migrasi database dari file ".dat" ke database "SQLite".

## [2.5.0] - 2024-05-20

- Memperkuat keamanan dan kecanggihan mekanisme enkripsi dan dekripsinya.
- Meningkatkan keamanan mekanisme "Master Password".
- Menambahkan fitur "Ganti Master Password".
- Menambahkan fitur "Reset Data".
- Dan perubahan kecil lainnya.

## [2.0.0] - 2024-04-30

- Sekarang Menggunakan Modul "Rich" Sepenuhnya.

## [1.1.0] - 2023-12-05

- Menambahkan Warna (Colorama).

## [1.0.2] - 2023-11-30

- Sedikit Perbaikan Bug dan Peningkatan.

## [1.0.1] - 2023-11-26

- Sedikit Perbaikan Bug.

## [1.0.0] - 2023-11-18

- Rilis Perdana :)
```

---

## 📜 Lisensi

**Smart Password Manager** dilisensikan di bawah GNU Affero General Public License v3.0. Kamu bebas menggunakan, memodifikasi, dan mendistribusikan perangkat lunak ini di bawah ketentuan lisensi AGPL-3.0. Untuk detail lebih lanjut, lihat [LICENSE](https://www.gnu.org/licenses/agpl-3.0.html).

---

## ⚠️ Disclaimer

Proyek ini dibantu oleh AI dan kolaborasi manusia. Meski setiap upaya telah dilakukan untuk memastikan keamanan dan fungsionalitasnya, gunakan dengan risiko sendiri.

---

## ❤️ Dibuat Oleh

Dikembangkan oleh Na'im Annafi Santosa ([TheRebo](https://github.com/TheRebo)).

---

Terima kasih telah menggunakan **Smart Password Manager**! Masukan dan kontribusi kamu sangat diapresiasi.
