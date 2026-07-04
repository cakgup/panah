# Authorized Lab Emulation Console For Kali Linux Server

<p align="center">
  <img src="logo.png" alt="Authorized Lab Emulation Console For Kali Linux Server" width="220">
</p>

<p align="center">
  <strong>Console kerja untuk pentester yang ingin menjalankan dashboard dari server Kali Linux</strong><br>
  Menyatukan module catalog, live console, timeline, evidence, dan report dalam satu dashboard internal berbasis Docker.
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

Repository ini dibuat sebagai console kerja untuk tim pentest internal yang ingin menjalankan aplikasi langsung dari **server Kali Linux**, tanpa bergantung pada WSL.

Tujuan utamanya:

- memberi antarmuka yang lebih rapi untuk menjalankan asesmen lab yang terotorisasi;
- membatasi target ke subnet yang disetujui;
- merangkum hasil scan menjadi evidence, timeline, severity, dan report;
- memudahkan operator membuka dashboard dari browser mesin lain di jaringan internal.

Repo ini bukan shell bebas untuk menjalankan command arbitrer dari UI. Semua alur tetap berada dalam guardrail backend.

---

## Cocok Untuk Siapa

Console ini cocok untuk:

- operator lab internal yang menjalankan tool dari server Kali Linux;
- tim red team yang ingin satu panel untuk workflow asesmen;
- assessor yang ingin membuka dashboard dari laptop, tetapi tool dieksekusi di server;
- engineer lab yang butuh deployment yang mudah dipindahkan antar host.

---

## Konsep Kerja

Alur kerja repo ini sederhana:

1. source code di-clone ke server Kali Linux;
2. aplikasi dibangun dan dijalankan dengan Docker Compose;
3. container menjalankan backend FastAPI dan tool yang ada di image;
4. operator membuka dashboard dari browser ke IP server;
5. output modul diproses menjadi:
   - live console
   - module timeline
   - evidence highlights
   - severity summary
   - report

Dengan pola ini, server Kali dipakai sebagai execution environment, sedangkan browser operator dipakai untuk UI dan review hasil.

---

## Fitur Utama

- Guardrail target berdasarkan approved ranges atau subnet yang diizinkan.
- Module catalog berbasis fase kill chain.
- Full simulation chain sesuai execution profile.
- Live Console, Timeline, dan Evidence dalam panel terpisah.
- Severity summary yang mengikuti evidence yang benar-benar ditampilkan.
- View Report untuk membuka report dari job aktif.
- Perlindungan password untuk aksi `Simpan Ranges`.
- Build ulang cukup dari source repo dengan `docker compose up --build`.

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
- `Dockerfile` menyusun image Kali Linux beserta dependency yang dibutuhkan modul.
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
- port default aplikasi adalah `4080`;
- jika server memakai firewall, buka port `4080/tcp` bila dashboard perlu diakses dari mesin lain.

---

## Quick Start

Di server Kali Linux:

```bash
git clone <URL-REPO-GITHUB-ANDA>
cd redteam-console-kali
docker compose up -d --build
docker compose ps
```

Lalu akses dari browser:

```text
http://IP_SERVER_KALI:4080
```

Contoh:

```text
http://localhost:4080
```

---

## Menjalankan Console

Perintah utama yang paling sering dipakai:

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

Rebuild penuh lagi biasanya hanya diperlukan jika:

- `Dockerfile` berubah;
- dependency Python berubah;
- ada perubahan tool yang di-install di image.

Kalau hanya mengubah file UI atau source backend, Anda tetap bisa memakai `docker compose up -d --build` agar hasilnya konsisten untuk operator lain.

---

## Workflow Penggunaan

Urutan pakai yang disarankan:

1. pastikan container sudah aktif;
2. buka dashboard dari browser ke IP server;
3. isi target IP yang berada dalam approved ranges;
4. pilih `Module Profile`:
   - `fast` untuk validasi cepat;
   - `balanced` untuk baseline yang lebih umum;
   - `deep` untuk observasi lebih lengkap;
5. jalankan modul tunggal atau full chain;
6. pantau hasil di tab:
   - `Console`
   - `Timeline`
   - `Evidence`
7. buka report jika ingin melihat ringkasan hasil yang lebih rapi.

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

Repo ini dirancang untuk memetakan output tool menjadi evidence yang lebih mudah dibaca operator. Beberapa area modul yang sudah ada:

- service discovery
- web fingerprinting
- web security header audit
- content discovery
- TLS dan DNS baseline review
- workflow evidence dan timeline

Image Docker akan meng-install beberapa tool penting seperti:

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

Repo ini tetap bisa hidup walau sebagian target tidak merespons atau sebagian modul menghasilkan evidence yang ringan.

---

## Verifikasi Yang Sudah Dicek

Sebelum README ini dirapikan, repo ini sudah diuji dengan skenario setara user lain yang baru download source ke folder baru:

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

Artinya, secara praktis repo ini sudah siap dipakai user lain yang clone dari GitHub lalu menjalankan `docker compose up -d --build`.

---

## Troubleshooting Singkat

Jika dashboard tidak terbuka:

- cek `docker compose ps`;
- cek `docker compose logs -f`;
- pastikan port `4080` tidak dipakai service lain;
- pastikan firewall server mengizinkan akses ke port `4080`;
- cek apakah Anda membuka `http://IP_SERVER_KALI:4080`, bukan `localhost`, jika akses dilakukan dari laptop lain.

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
- Simpan pengembangan modul dengan pendekatan yang bertanggung jawab dan terukur.

---

<p align="center">
  developed with love by cakgup
</p>
