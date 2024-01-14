# Password-Manager

Skrip ini berguna untuk menyimpan Kata Sandi Anda.

Fitur-fitur dari skrip ini adalah:

- Menyimpan Kata Sandi Anda dan kemudian mengenkripsinya dengan metode terkuat.
- Melihat Kata Sandi yang telah Anda simpan.
- Menghapus Password yang telah Anda simpan.
- Memiliki Master Password (yang nantinya harus Anda buat terlebih dahulu) untuk mengakses semua fitur ini.


Instalasi:

- Memerlukan Python (mungkin semua versi bisa digunakan, tetapi saya tidak tahu (saya menggunakan Python 3.11)).

1. git clone --branch Bahasa-Indonesia --single-branch https://github.com/TheRebo/Password-Manager.git
2. pip install -r requirements.txt / pip3 install -r requirements.txt


Kemungkinan bug yang diketahui(?):

- Terkadang setiap perangkat mungkin memiliki algoritma enkripsi dan dekripsi yang berbeda, sehingga terkadang kata sandi yang telah dienkripsi pada perangkat tertentu, ketika ditransfer ke perangkat lain akan terdeteksi atau tidak terdeteksi.
- Terkadang master password yang sudah kita buat setelah beberapa waktu, entah kenapa tidak bisa terdeteksi.

Bug di atas belum tentu benar, karena saya masih belum melakukan tes untuk mendalami hal tersebut, namun ada kemungkinan bug tersebut benar adanya. Jika bug tersebut benar adanya, mohon beritahu saya di bagian "Issues", dan saya mohon maaf atas ketidaknyamanannya =( .


Changelog:

- 1.1.0 = Penambahan Warna dan Sedikit Perbaikan Bug
- 1.0.2 = Sedikit Perbaikan Bug dan Sedikit Peningkatan
- 1.0.1 = Perbaikan Bug Kecil
- 1.0.0 = Rilis Awal


CATATAN!!! (Mohon dibaca agar tidak terjadi kesalahpahaman):

Skrip ini akan membuat 3 file setelah Anda membuat Kata Sandi Utama.
Daftar file yang dibuat oleh Skrip ini adalah:

- key.dat (Untuk menyimpan kunci yang akan digunakan saat mendekripsi kata sandi Anda nantinya)
- master_password.dat (Untuk menyimpan Kata Sandi Utama yang Anda buat)
- passwords.dat (Untuk menyimpan daftar kata sandi yang sudah Anda simpan, bersama dengan kata sandinya yang terenkripsi)

Jadi... JANGAN MENGHAPUS FILE-FILE TERSEBUT, JIKA ANDA TIDAK INGIN MENGHILANGKAN DATA KATA SANDI ANDA!!!.


DISCLAIMER!!! - SCRIPT INI DIBUAT DENGAN BANTUAN AI!!!
