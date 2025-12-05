<div align="center">

# 🐟 CUPANG

### **C**lient-side **U**nsanitized **P**ayload **A**uto-**N**esting **G**enerator

[![Version](https://img.shields.io/badge/version-2.8-blue.svg)](https://github.com/yourusername/cupang)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](https://github.com/yourusername/cupang)

**A lightweight, fast, and powerful XSS vulnerability scanner with intelligent detection capabilities**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [Contributing](#-contributing)

---

### 🌐 Language / Bahasa
[![en](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![id](https://img.shields.io/badge/lang-Bahasa%20Indonesia-red.svg)](README-id.md)

</div>

---

> CUPANG is a lightweight XSS scanner designed to automatically detect Cross-Site Scripting (XSS) vulnerabilities with a modular and efficient approach.

## ✨ Features

<table>
<tr>
<td width="50%">

🎯 **Auto-Detection**
- Reflected XSS
- Stored XSS
- DOM-based XSS
- File Upload XSS

</td>
<td width="50%">

⚡ **Performance**
- Multi-threaded scanning
- Smart payload selection
- Configurable timeout
- Concurrent testing

</td>
</tr>
<tr>
<td width="50%">

🔍 **Smart Analysis**
- Context-aware detection
- False positive reduction
- Unique payload tracking
- Intelligent verification

</td>
<td width="50%">

📊 **Reporting**
- TXT reports
- Real-time console output
- Detailed vulnerability info

</td>
</tr>
<tr>
<td width="50%">

🛠️ **Flexibility**
- Custom headers support
- Authentication handling
- Lightweight mode (fast)
- Comprehensive mode (all payloads)

</td>
<td width="50%">

🎨 **User Experience**
- Color-coded output
- Progress indicators
- Clean interface

</td>
</tr>
</table>

## 📋 Requirements

| Component | Version |
|-----------|---------|
| Python | 3.6+ |
| requests | Latest |
| beautifulsoup4 | Latest |
| colorama | Latest |

## 🚀 Installation

1. Clone repository:
```bash
git clone https://github.com/andknownmaly/cupang.git
cd xss
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Atau manual:
```bash
pip install requests beautifulsoup4 colorama
```

## 💻 Usage

<details open>
<summary><b>Quick Start</b></summary>

### Basic Scan (Fast Mode)
```bash
python cupang.py https://example.com
```

### Comprehensive Scan (All Payloads)
```bash
python cupang.py https://example.com -a
```

</details>

<details>
<summary><b>Advanced Usage</b></summary>

### With Custom Headers
```bash
python cupang.py https://example.com -H "Cookie: session=abc123"
python cupang.py https://example.com -H "Authorization: Bearer token123" -H "X-Custom: value"
```

### Verbose Mode
```bash
python cupang.py https://example.com -v
```

### Full Configuration
```bash
python cupang.py https://example.com -a -v --threads 20 --timeout 15
```

</details>

## 🎮 Options

| Option | Description |
|--------|-------------|
| `target_url` | Target URL untuk scan (required) |
| `-a, --all` | Test dengan SEMUA payloads (comprehensive) |
| `-H, --header` | Tambahkan custom header (bisa digunakan multiple) |
| `--threads` | Jumlah threads (default: 10) |
| `--timeout` | Request timeout dalam detik (default: 10) |
| `-v, --verbose` | Enable verbose output |

## 🔍 Detection Methods

<details>
<summary><b>🔴 Reflected XSS</b></summary>

- ✅ Testing URL parameters
- ✅ Testing form inputs
- ✅ Payload reflection verification
- ✅ Context-aware detection

</details>

<details>
<summary><b>💾 Stored XSS</b></summary>

- ✅ Form submission testing
- ✅ Payload persistence verification
- ✅ Multi-page verification

</details>

<details>
<summary><b>🌐 DOM-based XSS</b></summary>

- ✅ JavaScript sink detection
- ✅ Location-based XSS (hash, search)
- ✅ DOM property testing
- ✅ Event handler testing

</details>

<details>
<summary><b>📁 File Upload XSS</b></summary>

- ✅ SVG file upload testing
- ✅ HTML file upload testing
- ✅ Content-type verification

</details>

## 📦 Payload Structure

<details>
<summary><b>Click to view payload organization</b></summary>

CUPANG uses external payloads from the `payloads/` directory:

```
payloads/
├── all_payloads.txt          # 🎯 Main payload file (500+ payloads)
├── reflected.txt             # 🔴 Reflected XSS specific
├── dom.txt                   # 🌐 DOM-based XSS specific
├── javascript_protocol.txt   # ⚡ JavaScript protocol payloads
├── xss_payloads.json        # 📋 Structured JSON payloads
└── *.svg                     # 🖼️ SVG-based XSS vectors
```

| Mode | Payloads Used | Description |
|------|---------------|-------------|
| **Fast** (default) | Top 50 | Quick scan with most effective payloads |
| **All** (`-a` flag) | All available | Comprehensive scan with all payloads |

</details>

## 📊 Output

### Console Output
- Real-time progress dengan color-coded results
- Vulnerability summary
- Detailed findings dengan context

### Export Files
- **JSON**: Detailed structured data dengan metadata lengkap
- **TXT**: Human-readable report

Files disimpan di folder `file/` dengan format:
- `xss_scan_results_[timestamp].json`
- `xss_scan_results_[timestamp].txt`

## 🎨 Features Detail

### Smart Verification
```python
- Unique ID untuk setiap scan session
- Payload reflection verification
- Context-aware detection
- False positive reduction
```

### Multi-Context Testing
```python
- URL parameters
- POST data
- HTTP headers
- Form inputs (text, textarea, hidden)
- File uploads (SVG, HTML)
- DOM sinks (innerHTML, location, eval)
```

### Performance Optimization
```python
- Concurrent testing dengan ThreadPoolExecutor
- Configurable threads dan timeout
- Efficient payload loading
- Smart retry mechanism
```

## 🛡️ Security & Ethics

<div align="center">

### ⚠️ **IMPORTANT DISCLAIMER** ⚠️

</div>

<table>
<tr>
<td width="50%" bgcolor="#d4edda">

### ✅ **Authorized Use**

- Testing on your own systems
- Authorized penetration testing
- Educational purposes
- Security research with permission
- Bug bounty programs

</td>
<td width="50%" bgcolor="#f8d7da">

### ❌ **Prohibited Use**

- Testing without permission
- Illegal activities
- Damaging others' systems
- Unauthorized access
- Malicious purposes

</td>
</tr>
</table>

> **The author is not responsible for any misuse of this tool. Use responsibly and ethically.**

## 🔧 Troubleshooting

<details>
<summary><b>Common Issues & Solutions</b></summary>

### Import Error
```bash
pip install --upgrade requests beautifulsoup4 colorama
```

### SSL Certificate Error
The tool handles SSL verification automatically. If you still encounter errors, check your internet connection.

### Timeout Issues
```bash
python cupang.py <url> --timeout 20
```

### Memory Issues
```bash
python cupang.py <url> --threads 5
```

### Permission Denied
```bash
chmod +x cupang.py
```

</details>

## 📝 Examples

<details>
<summary><b>💡 Click to see practical examples</b></summary>

### Example 1: Quick Test
```bash
python cupang.py https://testphp.vulnweb.com/
```

### Example 2: Authenticated Scan
```bash
python cupang.py https://example.com/dashboard \
  -H "Cookie: PHPSESSID=abc123; user=admin" \
  -a -v
```

### Example 3: Custom Configuration
```bash
python cupang.py https://target.com \
  --threads 15 \
  --timeout 20 \
  -H "Authorization: Bearer mytoken" \
  -H "X-API-Key: key123" \
  -a
```

### Example 4: Multiple Headers
```bash
python cupang.py https://api.example.com \
  -H "Authorization: Bearer token" \
  -H "X-API-Key: key123" \
  -H "User-Agent: CustomAgent" \
  --verbose
```

</details>

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         UniversalXSSScanner             │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────┐   │
│  │  Payload Loader                 │   │
│  │  - External files               │   │
│  │  - Fallback payloads            │   │
│  │  - Unique ID injection          │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Detection Modules              │   │
│  │  ├─ Reflected XSS               │   │
│  │  ├─ Stored XSS                  │   │
│  │  ├─ DOM-based XSS               │   │
│  │  └─ File Upload XSS             │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Verification Engine            │   │
│  │  - Context analysis             │   │
│  │  - Smart verification           │   │
│  │  - False positive reduction     │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │  Results Handler                │   │
│  │  - JSON export                  │   │
│  │  - TXT report                   │   │
│  │  - Console output               │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

## 🤝 Contributing

<details>
<summary><b>How to Contribute</b></summary>

We welcome contributions! Please follow these steps:

1. 🍴 Fork the repository
2. 🌿 Create feature branch (`git checkout -b feature/AmazingFeature`)
3. 💾 Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. 📤 Push to branch (`git push origin feature/AmazingFeature`)
5. 🎉 Open a Pull Request

</details>

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

<div align="center">

Created with ❤️ by **Security Researchers**

[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github)](https://github.com/yourusername)
[![Twitter](https://img.shields.io/badge/Twitter-Follow-1DA1F2?style=for-the-badge&logo=twitter)](https://twitter.com/yourhandle)

</div>

## 🔗 Resources

<details>
<summary><b>External Documentation & References</b></summary>

| Resource | Description |
|----------|-------------|
| [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/) | Comprehensive XSS documentation |
| [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) | XSS payload references |
| [HackTricks XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting) | Advanced XSS techniques |
| [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security) | Web security fundamentals |

</details>

## 📞 Support

<div align="center">

**Need help or found a bug?**

[![Issues](https://img.shields.io/badge/Report-Issue-red?style=for-the-badge)](https://github.com/yourusername/cupang/issues)
[![Email](https://img.shields.io/badge/Email-Contact-blue?style=for-the-badge)](mailto:your-email@example.com)
[![Discord](https://img.shields.io/badge/Discord-Join-7289DA?style=for-the-badge&logo=discord)](https://discord.gg/yourserver)

</div>

---

<div align="center">

### 🐟 **CUPANG**
**Fast • Lightweight • Powerful**

Made with ❤️ for the Security Community

[⬆ Back to Top](#-cupang)

</div>


