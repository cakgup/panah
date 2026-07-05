# PANAH - Pentest Automation and Network Assessment Hub

<p align="center">
  <img src="logo.png" alt="Logo PANAH" width="220">
</p>

<p align="center">
  <strong>Console kerja untuk assessment teknis, simulasi eksekusi, live console, evidence, dan report dalam satu dashboard internal</strong><br>
  PANAH dipakai sebagai panel otomasi assessment untuk tim pentest atau lab internal yang ingin menjalankan modul teknis dari host server tanpa memindahkan workflow operator ke terminal sepanjang waktu.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688" alt="FastAPI">
  <img src="https://img.shields.io/badge/Frontend-HTML%20%2B%20CSS%20%2B%20JS-1E88E5" alt="Frontend">
  <img src="https://img.shields.io/badge/Environment-Kali%20Linux%20Server-3949AB" alt="Kali Linux Server">
  <img src="https://img.shields.io/badge/Runtime-Docker%20Compose-FB8C00" alt="Docker Compose">
  <img src="https://img.shields.io/badge/Scope-Authorized%20Lab-C62828" alt="Authorized Lab">
</p>

---

## Overview

Repository ini dibuat sebagai console kerja untuk tim pentest internal yang ingin menjalankan asesmen teknis dari server lab secara terpusat.

Tujuan utamanya:

- menyediakan antarmuka yang lebih rapi untuk menjalankan asesmen teknis;
- membatasi target ke range yang memang diizinkan;
- menampilkan hasil ke dalam live console, timeline, evidence, dan report;
- memudahkan operator membuka dashboard dari browser mesin lain di jaringan internal;
- menjaga assessment tetap berada dalam guardrail backend, bukan shell bebas dari browser.

PANAH berperan pada sisi assessment teknis. Jika temuan sudah perlu orkestrasi operasional atau ticketing formal, alurnya dapat dilanjutkan ke SATRIA dan PERISAI.

---

## Cocok Untuk Siapa

Console ini cocok untuk:

- operator lab internal yang menjalankan tool dari server Kali Linux;
- tim red team yang ingin satu panel untuk workflow asesmen;
- assessor yang ingin membuka dashboard dari laptop, tetapi tool dieksekusi di server;
- engineer lab yang butuh deployment yang mudah dipindahkan antar host.

---

## Posisi Dalam Ekosistem

Dalam ekosistem kerja SITP saat ini:

- `PANAH` berfokus pada assessment teknis dan otomasi simulasi.
- `SATRIA` berfokus pada registrasi aset, orkestrasi scan, gate decision, dan ticket publish.
- `PERISAI` atau IRIS berfokus pada case management, task, evidence, dan investigasi insiden.

Dengan pola ini, PANAH menjadi sumber awal assessment teknis sebelum hasilnya diolah lebih lanjut di layer operasional.

---

## Fitur Utama

- Guardrail target berbasis approved ranges atau subnet yang diizinkan.
- Module catalog berbasis fase kill chain atau kategori assessment.
- Full simulation chain sesuai execution profile.
- Live Console, Timeline, dan Evidence dalam panel terpisah.
- Severity summary yang mengikuti evidence yang benar-benar ditampilkan.
- Report view untuk membuka ringkasan hasil job aktif.
- Panel recent jobs untuk review job terakhir.
- Approved ranges editor dengan proteksi password.
- Tampilan login dummy dan header branding yang diselaraskan dengan ekosistem SITP.

---

## Menu dan Panel Operasional

- `Target`
  Operator mengisi target utama seperti IP, host, atau domain sesuai jenis assessment.

- `Target Kind`
  Menentukan kategori target, misalnya `ip` atau jenis lain sesuai modul yang aktif.

- `Module Profile`
  Menentukan kedalaman eksekusi seperti `fast`, `balanced`, atau `deep`.

- `Run Full Simulation Chain`
  Menjalankan alur asesmen berantai sesuai profile yang dipilih.

- `Advanced Settings`
  Menyediakan approved ranges dan guardrail tambahan untuk eksekusi harian.

- `Module Catalog`
  Menampilkan modul assessment, deskripsi singkat, dan command preview.

- `Recent Jobs`
  Menampilkan job terkini beserta tombol lihat hasil, hapus, atau review.

- `Console`
  Menampilkan output teknis real time dari job yang sedang dipilih.

- `Evidence`
  Menampilkan highlight hasil penting yang bisa dipakai untuk review cepat.

- `Report`
  Menampilkan hasil ringkas dalam format yang lebih nyaman dibaca operator atau reviewer.

---

## Konsep Kerja

Alur kerja PANAH dirancang sederhana:

1. source code di-clone ke server lab;
2. aplikasi dibangun dan dijalankan dengan Docker Compose;
3. backend FastAPI menjalankan workflow assessment yang sudah disetujui;
4. operator membuka dashboard dari browser;
5. job dieksekusi di host server;
6. output dikonversi menjadi console, timeline, evidence, severity, dan report.

Dengan pola ini, server lab dipakai sebagai execution environment, sedangkan browser operator dipakai untuk UI dan review hasil.

---

## Struktur Repository

```text
redteam-console-kali/
|-- backend/
|   |-- assets.py
|   |-- catalog.py
|   |-- lab_config.py
|   |-- main.py
|   |-- store.py
|   |-- workflow.py
|   |-- wahidin_check_headers.py
|   `-- data/
|-- .dockerignore
|-- .gitignore
|-- Dockerfile
|-- docker-compose.yml
|-- index.html
|-- script.js
|-- styles.css
|-- logo.png
|-- lab-ranges.json
|-- requirements.txt
`-- README.md
```

Ringkasnya:

- `backend/main.py` adalah entry point backend FastAPI.
- `backend/catalog.py` memuat definisi modul dan profile eksekusi.
- `backend/store.py` menangani penyimpanan job.
- `backend/lab_config.py` mengelola konfigurasi approved ranges.
- `index.html`, `script.js`, dan `styles.css` menangani UI dashboard.
- `Dockerfile` menyusun image beserta dependency yang dibutuhkan modul.
- `docker-compose.yml` menjadi jalur utama agar user lain cukup build dan start dari repo.

---

## Kebutuhan Lingkungan

Minimum yang disarankan di host tujuan:

- Kali Linux server
- Docker Engine
- Docker Compose plugin
- Git

Install dasar jika belum tersedia:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

Catatan:

- setelah `usermod -aG docker $USER`, login ulang biasanya membantu jika group belum terbaca;
- port default lokal repo ini adalah `4080`;
- pada deployment terpusat, port dapat dipetakan berbeda sesuai kebutuhan lingkungan.

---

## Quick Start

Di server tujuan:

```bash
git clone <URL-REPO-GITHUB-ANDA>
cd redteam-console-kali
docker compose up -d --build
docker compose ps
```

Lalu akses dari browser:

```text
http://IP_SERVER:4080
```

Contoh lokal:

```text
http://localhost:4080
```

---

## Menjalankan Console

Build dan start:

```bash
docker compose up -d --build
```

Lihat status:

```bash
docker compose ps
```

Lihat log:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

Start ulang tanpa rebuild:

```bash
docker compose up -d
```

---

## Workflow Penggunaan

Urutan pakai yang disarankan:

1. pastikan container sudah aktif;
2. buka dashboard dari browser ke IP server;
3. isi target yang berada dalam approved ranges;
4. pilih `Module Profile`:
   - `fast` untuk validasi cepat;
   - `balanced` untuk baseline umum;
   - `deep` untuk observasi lebih lengkap;
5. jalankan modul tunggal atau full chain;
6. pantau hasil di:
   - `Console`
   - `Timeline`
   - `Evidence`
   - `Report`
7. bila hasil perlu diteruskan secara operasional, gunakan SATRIA sebagai layer berikutnya.

---

## Data Persisten

Data runtime disimpan di:

- `backend/data/` untuk database dan hasil simpan lokal;
- `lab-ranges.json` untuk approved ranges dan profil lab.

`docker-compose.yml` sudah me-mount file dan folder tersebut, jadi data tetap bertahan walau container di-recreate.

---

## Approved Ranges

Target dibatasi agar operator hanya bekerja pada subnet yang diotorisasi.

File utama:

- [lab-ranges.json](C:\Users\gufroni\Documents\GitHub\redteam-console-kali\lab-ranges.json)

Contoh isi:

```json
{
  "allowed_subnets": [
    "10.10.10.0/24",
    "192.168.56.0/24"
  ]
}
```

Catatan:

- tombol `Simpan Ranges` dilindungi password;
- backend tetap punya fallback konfigurasi jika file range bermasalah;
- ini penting agar repo aman dipakai bersama dalam lab.

---

## Modul dan Tooling

Repo ini dirancang untuk memetakan output tool menjadi evidence yang lebih mudah dibaca operator. Area modul yang sudah disiapkan antara lain:

- service discovery;
- web fingerprinting;
- web security header audit;
- content discovery;
- TLS dan DNS baseline review;
- workflow evidence dan timeline.

Image Docker dapat meng-install tool penting seperti:

- `nmap`
- `ffuf`
- `gobuster`
- `amass`
- `nikto`
- `sqlmap`
- `whatweb`
- `hydra`
- `john`
- `hashcat`
- `impacket`
- `sslyze`
- `dnsx`
- `httpx`
- `nuclei`

---

## Verifikasi Yang Sudah Dicek

Skenario yang pernah diverifikasi untuk memastikan repo ini bisa dipindahkan ke host lain:

1. salin repo ke direktori bersih;
2. jalankan `docker compose build --no-cache`;
3. jalankan `docker compose up -d`;
4. cek health container;
5. cek endpoint `GET /api/jobs`.

Hasil verifikasi:

- build sukses dari source;
- container berhasil `healthy`;
- endpoint aplikasi merespons `200`;
- folder `backend/data/` otomatis terisi database saat aplikasi hidup.

---

## Troubleshooting Singkat

Jika dashboard tidak terbuka:

- cek `docker compose ps`;
- cek `docker compose logs -f`;
- pastikan port `4080` tidak dipakai service lain;
- pastikan firewall server mengizinkan akses ke port yang dipakai;
- cek apakah Anda membuka `http://IP_SERVER:4080`, bukan `localhost`, jika akses dilakukan dari mesin lain.

Jika build gagal:

- pastikan internet server aktif;
- pastikan Docker daemon hidup;
- coba ulang dengan `docker compose build --no-cache`.

Jika modul tidak menghasilkan data yang lengkap:

- cek apakah target berada di subnet yang diizinkan;
- cek apakah target memang merespons;
- cek tab `Console` untuk melihat command dan error yang muncul.

---

## Catatan Penggunaan

- Gunakan repo ini hanya untuk lab yang telah diotorisasi.
- Jangan memperluas target di luar approved ranges tanpa persetujuan yang jelas.
- Jangan menganggap UI ini sebagai pengganti analisis manual; ini adalah akselerator workflow.
- Bila hasil assessment perlu ditindaklanjuti secara formal, pindahkan orkestrasi dan ticketing ke SATRIA serta PERISAI.

---

<p align="center">
  developed with love by cakgup
</p>
