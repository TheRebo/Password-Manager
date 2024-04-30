# Smart Password Manager

[![Lisensi](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Smart Password Manager itu skrip Python yang amannya kebangetan buat nyimpen, ngeliat, sama ngatur password-passwordmu buat berbagai layanan. Pake enkripsi sama master password, datamu tetep aman tapi gampang diakses juga.

## Daftar Isi

- [Fitur](#fitur)
- [Instalasi](#instalasi)
- [Cara Pake](#cara-pake)
- [Yang Perlu Diingat](#yang-perlu-diingat)
- [Yang Jangan Diperbuat](#yang-jangan-diperbuat)
- [Kemungkinan Bug](#kemungkinan-bug)
- [Catatan Perubahan](#catatan-perubahan)
- [Disclaimer](#disclaimer)
- [Lisensi](#lisensi)

## Fitur

- **Penyimpanan Password Kebabekan:** Password dienkripsi pake algoritma enkripsi Fernet standar industri dari library `cryptography`, biar amannya maksimal gitu loh.
- **Perlindungan Master Password:** Semua passwordmu dilindungi satu master password kuat yang kamu bikin pas setup awal. Kece kan?
- **Pembuatan Password Acak:** Programnya bisa generate password acak yang kuat banget buat kamu dengan panjang yang bisa diatur sendiri.
- **Ngeliat Password:** Lihat semua password yang tersimpan dalam format tabel yang rapi, enak diliat gitu loh.
- **Penghapusan Password:** Hapus password buat layanan yang udah nggak kamu pake lagi, bersihin aja lah.
- **Antarmuka Pengguna Kece:** Programnya pake library `rich` buat ngasih antarmuka yang kece badai dan gampang digunakan dengan warna, panel, sama pemformatan yang keren.
- **Pelacakan Penanda Waktu:** Setiap entri password ditandai dengan waktu, jadi kamu tahu kapan itu ditambahkan. Guna banget kan?

## Instalasi

1. Clone repositorinya atau download kode sumbernya aja deh:

```
git clone --branch Bahasa-Indonesia --single-branch https://github.com/TheRebo/Password-Manager.git
```

2. Masuk ke direktori-nya:

```
cd Password-Manager
```

3. Instal dependensi yang dibutuhkan dengan menjalankan:

```
pip install -r requirements.txt
```

## Cara Pake

1. Jalankan skripnya pake Python:

```
python pass-man-ind.py
```

2. Pas dijalankan pertama kali, kamu bakal dimintain buat bikin master password yang kuat banget. Password ini digunakan buat ngenkripsi sama ndekripsi password yang tersimpan, jadi inget baik-baik ya passwordnya.

3. Setelah bikin master password, kamu bisa milih dari opsi-opsi keren berikut:
   - Tambahin password baru
   - Liat password yang udah tersimpan
   - Hapus password
   - Cabut dulu

4. Ikutin aja instruksi di layar buat ngelakuin aksi yang kamu mau.

## Yang Perlu Diingat

- Master passwordmu itu kunci buat semua password yang tersimpan. **Kalo kamu lupa, ya udah, nggak ada cara buat memulihkannya.**
- Password disimpan dalam format terenkripsi di file `passwords.dat`.
- Hash master password sama kunci enkripsinya disimpan di file `master_password.dat` sama `key.dat`.
- Setiap kali kamu nambahin password, password sama penanda waktu ditambahkan, digabungin, terus dienkripsi sebelum disimpan.

## Yang Jangan Diperbuat

- **Jangan** bagi-bagi master passwordmu ke siapa pun ya, bahaya!
- **Jangan** modifikasi atau hapus file `passwords.dat`, `master_password.dat`, atau `key.dat` secara manual, nanti rusak loh.
- **Jangan** jalankan skripnya dengan hak akses admin kecuali kalo emang lagi butuh.

## Kemungkinan Bug

- Kalo kunci enkripsi (`key.dat`) hilang atau rusak, kamu nggak bakal bisa ndekripsi password yang tersimpan, nyesel deh.
- Kalo file `master_password.dat` rusak, kamu mungkin nggak bisa verifikasi master passwordmu, repot kan?
- Kalo file `passwords.dat` rusak, password yang tersimpan bisa jadi nggak bisa diakses, sedihnya.

## Catatan Perubahan

```markdown
## [W.I.P] (Work In Progress)
- Mencoba memperkuat metode enkripsinya.
- Mendeteksi perubahan apa pun dalam kode program (sehingga fungsi Kata Sandi Utama tidak dapat dihapus).
- File data hanya akan dapat dihapus melalui program ini (untuk memperkecil kemungkinan data corrupt).

## [2.0.0] - 2024-04-30

- Sekarang Sepenuhnya Menggunakan Module "Rich".

## [1.1.0] - 2023-12-05

- Menambahkan Warna (Colorama).

## [1.0.2] - 2023-11-30

- Sedikit Perbaikan BUG dan Peningkatan.

## [1.0.1] - 2023-11-26

- Sedikit Perbaikan BUG.

## [1.0.0] - 2023-11-18

- Rilis Pertama :)
```

## Disclaimer

Program ini dibuat dengan bantuan model bahasa AI. Penulis bertanggung jawab sepenuhnya atas isi dan fungsionalitasnya.
**Gunakan program ini dengan risikomu sendiri** ya, jangan salahkan penulis kalo ada apa-apa.

## Lisensi

Program ini dilisensikan di bawah GNU Affero General Public License v3.0.
