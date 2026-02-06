# Emilia - Cloudflare Proxy Scanner (Go Edition)

<p align="center">
<img src="https://github.com/user-attachments/assets/ced4b0da-e4cf-495b-a14c-b2385063313d" width="200">
</p>

## 📖 Deskripsi

**Emilia** adalah alat pemindai proxy (Proxy Scanner) berkinerja tinggi yang ditulis dalam bahasa **Go (Golang)**. Alat ini dirancang untuk memvalidasi dan memindai ribuan IP Cloudflare ("CSI") untuk menemukan IP yang aktif (*alive*) dan memiliki latensi rendah.

Script ini bekerja secara *concurrent* (paralel) untuk mempercepat proses pemindaian dan secara otomatis mengurutkan hasil berdasarkan prioritas negara yang sering digunakan untuk tunneling ASIA (Indonesia, Malaysia, Singapura, Hong Kong).

### 🚀 Fitur Utama Scanner
* **High Performance:** Ditulis menggunakan Go routine untuk pemindaian paralel yang sangat cepat dan ringan.
* **Smart Sorting:** Otomatis memprioritaskan IP dari negara **ID, MY, SG, dan HK**.
* **Dual Output:** Menyediakan hasil dalam dua format (Semua Alive & Prioritas Negara).

---

## 🛠️ Kompatibilitas (Supported Tunnels)

IP Proxy yang dihasilkan oleh Emilia dioptimalkan untuk digunakan pada proyek-proyek *Cloudflare Worker* dan *Pages* berikut ini:

### 1. [EDtunnel](https://github.com/6Kmfi6HP/EDtunnel)
*A proxy tool based on Cloudflare Workers and Pages.*
* ✅ Support for Cloudflare Workers and Pages deployment
* ✅ Multiple UUID configuration support & Custom proxy IP/port
* ✅ Protocols: **SOCKS5**, **HTTP**, **Trojan** (auto-detect), **VLESS** (full UDP)
* ✅ Multi-proxy rotation with automatic failover
* ✅ Path-based proxy parameters (`/socks5://`, `/http://`, `/vless://`)

### 2. [FoxCloud](https://github.com/code3-dev/foxcloud)
*High-performance VLESS proxy server built for Cloudflare Workers.*
FoxCloud dirancang untuk menyediakan akses internet yang aman dan cepat melalui jaringan global Cloudflare.
* ⚡ **Lightning Fast:** Didukung oleh jaringan global Cloudflare dengan 200+ pusat data.
* 🔒 **Secure:** Enkripsi tingkat perusahaan dengan dukungan TLS 1.3.
* 🌐 **Multi-Protocol:** Dukungan VLESS dengan transport WebSocket.
* 📋 **Subscription Management:** Pembuatan konfigurasi otomatis untuk klien.

### 3. [Nautica](https://github.com/FoolVPN-ID/Nautica)
*Sebuah repository serverless tunnel studi kasus Indonesia.*
* Dirancang khusus untuk kebutuhan tunneling dengan optimasi lokal untuk pengguna di Indonesia.

### 4. [Workers-VLESS](https://github.com/ymyuuu/workers-vless)
Implementasi VLESS ringan yang berjalan efisien di atas Cloudflare Workers. Cocok untuk penggunaan personal yang membutuhkan *setup* minimalis.

### 5. [BPB-Worker-Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel)
Panel manajemen worker yang memudahkan konfigurasi VLESS dan Trojan, memungkinkan pengguna mengelola banyak node dengan antarmuka yang lebih mudah.

---

## 📂 Link Download (Hasil Scan)

Berikut adalah daftar proxy yang telah dipindai dan siap digunakan. Silakan ambil sesuai kebutuhan:

### ✅ 1. Proxy Prioritas (Rekomendasi)
Daftar ini sudah diurutkan berdasarkan negara prioritas (**ID → MY → SG → HK**). Sangat disarankan untuk penggunaan tunnel di Asia.
> 🔗 **[Ambil Country-ALIVE.txt Disini](https://github.com/papapapapdelesia/Emilia/blob/main/Data/Country-ALIVE.txt)**

### ✅ 2. Semua Proxy Hidup (Alive)
Daftar lengkap seluruh proxy yang aktif (urut A-Z), tanpa filter prioritas negara.
> 🔗 **[Ambil alive.txt Disini](https://github.com/papapapapdelesia/Emilia/blob/main/Data/alive.txt)**

### 📦 Sumber Data
Daftar mentah IP yang digunakan sebagai input untuk scanning:
> 🔗 **[Lihat IPPROXY23K.txt](https://github.com/papapapapdelesia/Emilia/blob/main/Data/IPPROXY23K.txt)**

---

## ⚠️ Disclaimer
Project ini dibuat untuk tujuan edukasi dan penelitian jaringan (*Network Analysis*). Penggunaan IP untuk *bypass* atau akses ilegal adalah tanggung jawab pengguna masing-masing.

> *"Emilia strives to become the ruler of Lugnica, and this tool strives to find the best connection for you!"* 💜
<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&height=100&section=footer"/>
