<div align="center">

# 🐟 CUPANG

### **C**lient-side **U**nsanitized **P**ayload **A**uto-**N**esting **G**enerator

[![Version](https://img.shields.io/badge/version-2.8-blue.svg)](https://github.com/yourusername/cupang)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/yourusername/cupang)

**Scanner kerentanan XSS yang ringan, cepat, dan powerful dengan kemampuan deteksi intelligent**

[Fitur](#-fitur) • [Instalasi](#-instalasi) • [Penggunaan](#-penggunaan) • [Contoh](#-contoh-penggunaan) • [Kontribusi](#-kontribusi)

---

### 🌐 Language / Bahasa
[![en](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![id](https://img.shields.io/badge/lang-Bahasa%20Indonesia-red.svg)](README-id.md)

</div>

---

> CUPANG adalah scanner XSS ringan yang dirancang untuk mendeteksi kerentanan Cross-Site Scripting (XSS) secara otomatis dengan pendekatan modular dan efisien.

## ✨ Fitur

<table>
<tr>
<td width="50%">

🎯 **Deteksi Otomatis**
- Reflected XSS
- Stored XSS
- DOM-based XSS
- File Upload XSS

</td>
<td width="50%">

⚡ **Performa**
- Scanning multi-threaded
- Pemilihan payload cerdas
- Timeout dapat dikonfigurasi
- Testing concurrent

</td>
</tr>
<tr>
<td width="50%">

🔍 **Analisis Cerdas**
- Deteksi context-aware
- Pengurangan false positive
- Pelacakan payload unik
- Verifikasi intelligent

</td>
<td width="50%">

📊 **Pelaporan**
- Export JSON
- Laporan TXT
- Output console real-time
- Info kerentanan detail

</td>
</tr>
<tr>
<td width="50%">

🛠️ **Fleksibilitas**
- Dukungan custom headers
- Penanganan autentikasi
- Mode lightweight (cepat)
- Mode comprehensive (semua payload)

</td>
<td width="50%">

🎨 **Pengalaman Pengguna**
- Output dengan kode warna
- Indikator progress
- Mode verbose
- Interface bersih

</td>
</tr>
</table>

## 📋 Persyaratan

| Komponen | Versi |
|----------|-------|
| Python | 3.6+ |
| requests | Terbaru |
| beautifulsoup4 | Terbaru |
| colorama | Terbaru |

## 🚀 Instalasi

<details open>
<summary><b>Langkah Instalasi</b></summary>

1. **Clone repository:**
```bash
git clone <repository-url>
cd xss
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

Atau instalasi manual:
```bash
pip install requests beautifulsoup4 colorama
```

</details>

## 💻 Penggunaan

<details open>
<summary><b>Mulai Cepat</b></summary>

### Scan Dasar (Mode Cepat)
```bash
python cupang.py https://example.com
```

### Scan Komprehensif (Semua Payload)
```bash
python cupang.py https://example.com -a
```

</details>

<details>
<summary><b>Penggunaan Lanjutan</b></summary>

### Dengan Custom Headers
```bash
python cupang.py https://example.com -H "Cookie: session=abc123"
python cupang.py https://example.com -H "Authorization: Bearer token123" -H "X-Custom: value"
```

### Mode Verbose
```bash
python cupang.py https://example.com -v
```

### Konfigurasi Lengkap
```bash
python cupang.py https://example.com -a -v --threads 20 --timeout 15
```

</details>

## 🎮 Opsi

| Opsi | Deskripsi |
|------|-----------|
| `target_url` | Target URL untuk scan (wajib) |
| `-a, --all` | Test dengan SEMUA payload (komprehensif) |
| `-H, --header` | Tambahkan custom header (bisa multiple) |
| `--threads` | Jumlah threads (default: 10) |
| `--timeout` | Request timeout dalam detik (default: 10) |
| `-v, --verbose` | Enable output verbose |

## 🔍 Metode Deteksi

<details>
<summary><b>🔴 Reflected XSS</b></summary>

- ✅ Testing parameter URL
- ✅ Testing input form
- ✅ Verifikasi refleksi payload
- ✅ Deteksi context-aware

</details>

<details>
<summary><b>💾 Stored XSS</b></summary>

- ✅ Testing form submission
- ✅ Verifikasi persistensi payload
- ✅ Verifikasi multi-halaman

</details>

<details>
<summary><b>🌐 DOM-based XSS</b></summary>

- ✅ Deteksi JavaScript sink
- ✅ XSS berbasis location (hash, search)
- ✅ Testing properti DOM
- ✅ Testing event handler

</details>

<details>
<summary><b>📁 File Upload XSS</b></summary>

- ✅ Testing upload file SVG
- ✅ Testing upload file HTML
- ✅ Verifikasi content-type

</details>

## 📦 Struktur Payload

<details>
<summary><b>Klik untuk melihat organisasi payload</b></summary>

CUPANG menggunakan payload eksternal dari direktori `payloads/`:

```
payloads/
├── all_payloads.txt          # 🎯 File payload utama (500+ payload)
├── reflected.txt             # 🔴 Spesifik Reflected XSS
├── dom.txt                   # 🌐 Spesifik DOM-based XSS
├── javascript_protocol.txt   # ⚡ Payload protokol JavaScript
├── xss_payloads.json        # 📋 Payload JSON terstruktur
└── *.svg                     # 🖼️ Vector XSS berbasis SVG
```

| Mode | Payload Digunakan | Deskripsi |
|------|-------------------|-----------|
| **Fast** (default) | Top 50 | Scan cepat dengan payload paling efektif |
| **All** (flag `-a`) | Semua tersedia | Scan komprehensif dengan semua payload |

</details>

## 📊 Output

<details>
<summary><b>Format Output</b></summary>

### Output Console
- Progress real-time dengan hasil berkode warna
- Summary kerentanan
- Temuan detail dengan konteks

### File Export
- **JSON**: Data terstruktur detail dengan metadata lengkap
- **TXT**: Laporan yang mudah dibaca

File disimpan di folder `file/` dengan format:
- `xss_scan_results_[timestamp].json`
- `xss_scan_results_[timestamp].txt`

</details>

## 🛡️ Keamanan & Etika

<div align="center">

### ⚠️ **DISCLAIMER PENTING** ⚠️

</div>

<table>
<tr>
<td width="50%" bgcolor="#d4edda">

### ✅ **Penggunaan Sah**

- Testing pada sistem milik sendiri
- Penetration testing resmi
- Tujuan edukasi
- Riset keamanan dengan izin
- Program bug bounty

</td>
<td width="50%" bgcolor="#f8d7da">

### ❌ **Penggunaan Terlarang**

- Testing tanpa izin
- Aktivitas ilegal
- Merusak sistem orang lain
- Akses tidak sah
- Tujuan jahat

</td>
</tr>
</table>

> **Penulis tidak bertanggung jawab atas penyalahgunaan tool ini. Gunakan secara bertanggung jawab dan etis.**

## 🔧 Troubleshooting

<details>
<summary><b>Masalah Umum & Solusi</b></summary>

### Error Import
```bash
pip install --upgrade requests beautifulsoup4 colorama
```

### Error SSL Certificate
Tool menangani verifikasi SSL secara otomatis. Jika masih error, periksa koneksi internet Anda.

### Masalah Timeout
```bash
python cupang.py <url> --timeout 20
```

### Masalah Memory
```bash
python cupang.py <url> --threads 5
```

### Permission Denied
```bash
chmod +x cupang.py
```

</details>

## 📝 Contoh Penggunaan

<details>
<summary><b>💡 Klik untuk melihat contoh praktis</b></summary>

### Contoh 1: Test Cepat
```bash
python cupang.py https://testphp.vulnweb.com/
```

### Contoh 2: Scan dengan Autentikasi
```bash
python cupang.py https://example.com/dashboard \
  -H "Cookie: PHPSESSID=abc123; user=admin" \
  -a -v
```

### Contoh 3: Konfigurasi Custom
```bash
python cupang.py https://target.com \
  --threads 15 \
  --timeout 20 \
  -H "Authorization: Bearer mytoken" \
  -H "X-API-Key: key123" \
  -a
```

### Contoh 4: Multiple Headers
```bash
python cupang.py https://api.example.com \
  -H "Authorization: Bearer token" \
  -H "X-API-Key: key123" \
  -H "User-Agent: CustomAgent" \
  --verbose
```

</details>

## 🏗️ Arsitektur

```
┌─────────────────────────────────────────┐
│         UniversalXSSScanner             │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────┐   │
│  │  Payload Loader                 │   │
│  │  - File eksternal               │   │
│  │  - Payload fallback             │   │
│  │  - Injeksi ID unik              │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Modul Deteksi                  │   │
│  │  ├─ Reflected XSS               │   │
│  │  ├─ Stored XSS                  │   │
│  │  ├─ DOM-based XSS               │   │
│  │  └─ File Upload XSS             │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Engine Verifikasi              │   │
│  │  - Analisis konteks             │   │
│  │  - Verifikasi cerdas            │   │
│  │  - Pengurangan false positive   │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Handler Hasil                  │   │
│  │  - Export JSON                  │   │
│  │  - Laporan TXT                  │   │
│  │  - Output console               │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

## 🤝 Kontribusi

<details>
<summary><b>Cara Berkontribusi</b></summary>

Kami menerima kontribusi! Silakan ikuti langkah berikut:

1. 🍴 Fork repository
2. 🌿 Buat feature branch (`git checkout -b feature/FiturAmazing`)
3. 💾 Commit perubahan (`git commit -m 'Tambah FiturAmazing'`)
4. 📤 Push ke branch (`git push origin feature/FiturAmazing`)
5. 🎉 Buka Pull Request

</details>

## 📄 Lisensi

Proyek ini dilisensikan di bawah **MIT License** - lihat file [LICENSE](LICENSE) untuk detail.

## 🔗 Sumber Daya

<details>
<summary><b>Dokumentasi Eksternal & Referensi</b></summary>

| Sumber | Deskripsi |
|--------|-----------|
| [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/) | Dokumentasi XSS komprehensif |
| [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) | Referensi payload XSS |
| [HackTricks XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting) | Teknik XSS lanjutan |
| [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security) | Fundamental keamanan web |

</details>

## 📞 Dukungan

<div align="center">

**Butuh bantuan atau menemukan bug?**

[![Issues](https://img.shields.io/badge/Laporkan-Issue-red?style=for-the-badge)](https://github.com/yourusername/cupang/issues)
[![Email](https://img.shields.io/badge/Email-Kontak-blue?style=for-the-badge)](mailto:your-email@example.com)
[![Discord](https://img.shields.io/badge/Discord-Gabung-7289DA?style=for-the-badge&logo=discord)](https://discord.gg/yourserver)

</div>

---

<div align="center">

### 🐟 **CUPANG**
**Cepat • Ringan • Powerful**

Dibuat dengan ❤️ untuk Komunitas Keamanan

[⬆ Kembali ke Atas](#-cupang)

</div>
