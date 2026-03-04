# 🌀 Vortex-Skeleton


**Vortex-Skeleton** is a modular web security scanning framework built for **penetration testers, security researchers, and bug bounty hunters**.
It provides a flexible and extensible architecture for performing **automated vulnerability assessments (VAPT)** against modern web applications and APIs.

The framework is designed with a **plugin-based detection engine**, enabling rapid integration of new vulnerability checks and custom security testing modules.

---

# 🚀 Features

• Modular **plugin-based vulnerability detection system**
• Designed for **web application and API security testing**
• Built-in vulnerability checks for multiple attack classes
• **Parallel scanning engine** for faster testing
• **Evidence collection** for vulnerability findings
• **CVSS-based risk scoring** for severity classification
• **Extensible architecture** for custom vulnerability plugins
• Structured **report generation** for VAPT assessments

---

# 🔍 Supported Vulnerability Checks

The framework includes detection modules for a variety of common and advanced web vulnerabilities:

### Injection Attacks

* SQL Injection
* NoSQL Injection
* LDAP Injection
* XPath Injection
* Server-Side Template Injection (SSTI)
* Deserialization vulnerabilities

### Web Exploitation

* Cross-Site Scripting (XSS)
* HTML Injection
* CRLF Injection
* Open Redirect

### Access Control Issues

* Insecure Direct Object Reference (IDOR)
* Mass Assignment vulnerabilities

### Security Misconfigurations

* CORS Misconfiguration
* Missing Security Headers
* Clickjacking

### Advanced Attack Surfaces

* Server-Side Request Forgery (SSRF)
* JWT Security Weaknesses
* HTTP Request Smuggling
* Prototype Pollution
* GraphQL security issues

---

# 🏗 Project Architecture

```
Vortex-Skeleton/
│
├── core/
│   ├── engine.py
│   ├── analyzer.py
│   ├── http.py
│   ├── parameters.py
│   └── surface.py
│
├── plugins/
│   ├── sqli.py
│   ├── xss.py
│   ├── ssrf.py
│   ├── idor.py
│   └── ...
│
├── evidence/
│   └── store.py
│
├── report/
│   └── generator.py
│
├── risk/
│   └── cvss.py
│
└── main.py
```

---

# ⚙ Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Vortex-Skeleton.git
```

Navigate into the project directory:

```bash
cd Vortex-Skeleton
```

Install required dependencies:

```bash
pip install -r requirements.txt
```

---

# ▶ Usage

Run the scanner against a target:

```bash
python3 vortex.py https://target.com
```

Example:

```bash
python3 vortex.py https://target.com
```

---

# 🔌 Plugin System

The framework uses a **plugin-based architecture**, making it easy to add new vulnerability checks.

To add a new plugin:

1. Create a new Python file in the `plugins/` directory
2. Implement your vulnerability detection logic
3. Register it within the scanning engine

This allows the framework to remain **scalable and extensible**.

---

# 📊 Reporting

The scanner collects **evidence for each detected vulnerability**, including:

* HTTP requests
* HTTP responses
* Payloads used
* Detection logic
* Severity scoring (CVSS)

Reports can be used directly for **VAPT documentation and security assessments**.

---

# ⚠ Disclaimer

This tool is intended **only for authorized security testing and educational purposes**.

Do **NOT** use this framework against systems without explicit permission.
The author is **not responsible for misuse or damage** caused by this tool.

---

# 🤝 Contributing

Contributions are welcome.

If you'd like to improve the framework:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

# 📜 License

This project is licensed under the **MIT License**.

---

# 👨‍💻 Author

Security Research & Development Project focused on **automated vulnerability discovery and penetration testing workflows**.

---

# ⭐ Support

If you find this project useful, consider **starring the repository** to support its development.
