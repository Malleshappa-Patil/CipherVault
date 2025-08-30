# 🔒 CipherVault

A secure, educational password manager implementation in Python featuring both CLI and web interfaces. Built with industry-standard cryptography for learning purposes.

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org)
[![Cryptography](https://img.shields.io/badge/Encryption-AES--256--GCM-green.svg)](https://cryptography.io)
[![Flask](https://img.shields.io/badge/Web-Flask-red.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](#license)

## ⚠️ Important Security Notice

**This is an educational demonstration project.** 

🚫 **DO NOT USE FOR PRODUCTION** without additional security hardening:
- Memory protection and secure data clearing
- Protection against timing attacks
- Session management improvements
- Additional authentication factors
- Professional security audit

## ✨ Features

### 🔐 Security Features
- **AES-256-GCM Encryption**: Military-grade encryption with built-in integrity verification
- **PBKDF2-SHA256 Key Derivation**: 100,000+ iterations to resist brute-force attacks
- **Random Salt Generation**: Unique 256-bit salt per vault prevents rainbow table attacks
- **Zero-Knowledge Architecture**: Master password never stored anywhere
- **Integrity Verification**: Detects tampering and wrong passwords automatically

### 🖥️ Dual Interface
- **Command Line Interface**: Full-featured terminal application
- **Web Interface**: Modern, responsive web UI with live search
- **Session Security**: Web interface locks automatically when browser closes

### 📦 Core Functionality
- **Secure Storage**: Encrypted vault file with JSON data structure
- **Add Entries**: Store website credentials securely
- **View All**: Display all stored passwords with reveal/hide options
- **Smart Search**: Find entries by site name (partial matching)
- **Duplicate Handling**: Update existing entries or create new ones

## 📋 Installation & Setup

### Prerequisites
- Python 3.7 or higher
- pip package manager

### 1. Clone/Download Project
```bash
git clone <your-repo-url>
cd mini-password-manager
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install cryptography>=41.0.0 flask>=2.3.0
```

### 3. Create Templates Folder (for web interface)
```bash
mkdir templates
```

## 🚀 Usage

### Command Line Interface

**Start CLI version:**
```bash
python3 main.py
```

**First-time setup:**
- Enter a strong master password (you'll need this every time)
- Confirm the password
- Vault file `vault.enc` is created automatically

**Available commands:**
1. **Add Entry**: Store new site credentials
2. **View All**: Display all entries with password reveal option
3. **Search**: Find entries by site name
4. **Exit**: Close application securely

### Web Interface

**Start web server:**
```bash
python3 web_app.py
```

**Access application:**
- Open browser and go to: `http://localhost:5000`
- Enter your master password
- Use the intuitive web interface

**Web features:**
- 🏠 **Dashboard**: Overview of all entries with live search
- ➕ **Add Entry**: Clean form interface for new passwords
- 🔍 **Search**: Advanced search with real-time results
- 👁️ **Password Reveal**: Click to show/hide passwords securely
- 🔒 **Auto-Lock**: Vault locks when browser closes

## 📁 Project Structure

```
mini-password-manager/
├── 📄 main.py                  # CLI interface and main entry point
├── 🌐 web_app.py              # Flask web server and routes
├── 🔐 crypto_utils.py         # Cryptographic functions
├── 🗄️ vault_manager.py        # Vault operations and file handling
├── 📋 requirements.txt        # Python dependencies
├── 📖 README.md              # This documentation
├── 📂 templates/              # Web interface templates
│   ├── base.html             # Base template with styling
│   ├── login.html            # Master password entry
│   ├── dashboard.html        # Main vault dashboard
│   ├── add_entry.html        # Add new password form
│   ├── search.html           # Search interface
│   └── search_results.html   # Search results display
└── 🔒 vault.enc              # Encrypted vault file (auto-generated)
```

## 🔬 Technical Implementation

### Cryptographic Design

**File Format:**
```
vault.enc = salt(32 bytes) + nonce(12 bytes) + encrypted_data
```

**Encryption Process:**
1. **Master Password** → PBKDF2-SHA256 (100k iterations) → **Encryption Key**
2. **JSON Data** → AES-256-GCM → **Encrypted Vault**
3. **Random Nonce** → Ensures unique encryption each time

**Security Parameters:**
```python
SALT_LENGTH = 32      # 256 bits
KEY_LENGTH = 32       # 256 bits for AES-256  
NONCE_LENGTH = 12     # 96 bits for GCM
ITERATIONS = 100000   # PBKDF2 iterations
```

### Data Structure
```python
# Internal JSON structure (before encryption)
[
    {
        "site": "gmail.com",
        "username": "user@gmail.com", 
        "password": "SecurePassword123!"
    },
    # ... more entries
]
```

## 🛡️ Security Analysis

### ✅ Implemented Security Features

| Feature | Implementation | Security Benefit |
|---------|----------------|------------------|
| **Encryption** | AES-256-GCM | Military-grade confidentiality + integrity |
| **Key Derivation** | PBKDF2-SHA256, 100k iterations | Slows brute-force attacks |
| **Salt** | 256-bit random per vault | Prevents rainbow table attacks |
| **Nonce** | 96-bit random per encryption | Ensures ciphertext uniqueness |
| **Authentication** | GCM built-in MAC | Detects tampering/wrong password |
| **Zero Knowledge** | Master password never stored | No password recovery backdoors |

### ⚠️ Security Limitations (Educational Use Only)

| Missing Feature | Risk | Production Requirement |
|----------------|------|----------------------|
| **Memory Protection** | Sensitive data in RAM | Secure memory allocation |
| **Timing Attack Protection** | Password length leakage | Constant-time operations |
| **Secure Deletion** | Data recovery from disk | Cryptographic file shredding |
| **Session Timeouts** | Long-lived web sessions | Automatic lock after inactivity |
| **Multi-Factor Auth** | Single point of failure | Additional authentication factors |
| **Audit Logging** | No access tracking | Security event monitoring |

## 🚨 What Happens If You Forget Master Password?

**Complete data loss.** This is intentional and secure:

- ❌ **No recovery mechanism** (by design)
- ❌ **No password hints** (security risk) 
- ❌ **No backdoors** (prevents unauthorized access)
- ✅ **Better to lose data than have it stolen**

**Prevention strategies:**
- Write down master password and store securely
- Use memorable but strong password
- Test password regularly
- Consider implementing recovery keys (reduces security)

## 📊 Example Usage Session

### CLI Example
```bash
$ python3 main.py
============================================================
🔒 MINI PASSWORD MANAGER v1.0
============================================================
Creating new vault...
Enter master password: ********
Confirm master password: ********
✓ Vault created successfully

MAIN MENU
1. Add new entry
Enter your choice: 1

Site/Service name: github.com
Username: myusername
Password: mySecurePassword123!
✓ Added entry for 'github.com'
```

### Web Interface
1. 🌐 Navigate to `http://localhost:5000`
2. 🔒 Enter master password
3. 🏠 Access dashboard with all entries
4. ➕ Add new entries via clean form
5. 🔍 Search entries with live filtering
6. 👁️ Reveal passwords with one click

## 🔧 Troubleshooting

### Common Issues

**❌ "Invalid master password" error:**
- Check password carefully (case-sensitive)
- If forgotten, vault is permanently inaccessible
- Delete `vault.enc` to start fresh (loses all data)

**❌ Import errors:**
- Ensure all `.py` files are in same directory
- Install dependencies: `pip install cryptography flask`
- Check Python version (3.7+ required)

**❌ Web interface not loading:**
- Ensure Flask is installed: `pip install flask`
- Create `templates/` folder with HTML files
- Check firewall isn't blocking port 5000

**❌ "Invalid vault file format":**
- Corrupted vault file from incomplete write
- Delete `vault.enc` and recreate vault
- Ensure sufficient disk space

### Development Notes

**Adding new features:**
- Modify `vault_manager.py` for core functionality
- Update both `main.py` (CLI) and `web_app.py` (web) interfaces
- Maintain backward compatibility with existing vaults

**Security improvements:**
- Implement secure memory clearing
- Add session timeout functionality
- Consider hardware security modules (HSM)
- Add backup/export capabilities

## 📚 Learning Objectives

This project demonstrates:

### Cryptography Concepts
- **Symmetric encryption** with AES
- **Key derivation functions** (PBKDF2)  
- **Authenticated encryption** (GCM mode)
- **Salt and nonce** usage
- **Integrity verification**

### Software Engineering
- **Modular design** with separated concerns
- **Error handling** and user feedback
- **Secure coding practices**
- **CLI and web interface development**
- **Session management**

### Security Principles
- **Defense in depth**
- **Zero-knowledge architecture**
- **Fail-safe defaults**
- **Principle of least privilege**

## 🤝 Contributing

This is an educational project. Contributions welcome for:
- Additional security hardening
- Code improvements
- Documentation updates
- New interface options
- Security analysis

## 📄 License

**Educational Use Only**

This project is intended for learning and demonstration purposes. Not recommended for production use without significant security enhancements and professional security review.

## 🎯 Future Enhancements

### Security Improvements
- [ ] Secure memory handling
- [ ] Timing attack protection  
- [ ] Hardware security module support
- [ ] Multi-factor authentication
- [ ] Session timeout management

### Features
- [ ] Password strength analyzer
- [ ] Secure password generator
- [ ] Export/import functionality
- [ ] Multiple vault support
- [ ] Password history tracking

### Interface
- [ ] Desktop GUI (Tkinter/PyQt)
- [ ] Mobile app compatibility
- [ ] Browser extension
- [ ] REST API
- [ ] Docker containerization

## 🆘 Support

For educational purposes and questions:
- Review the code comments for detailed explanations
- Check troubleshooting section above
- Understand this is a learning project, not production software

## 🙏 Acknowledgments

Built using:
- [Cryptography](https://cryptography.io/) - Industry-standard Python crypto library
- [Flask](https://flask.palletsprojects.com/) - Lightweight web framework
- [OWASP Guidelines](https://owasp.org/) - Security best practices

---

**Remember: Strong cryptography + secure implementation = safe data storage**

*Happy learning and stay secure! 🔒*