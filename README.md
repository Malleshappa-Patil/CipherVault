# CipherVault

A simple, secure password manager implemented in Python using industry-standard cryptography.

## ⚠️ Security Warning

**This is a demonstration implementation for educational purposes.** 

Do not use in production environments without additional security hardening:
- Secure memory handling (clearing sensitive data)
- Protection against timing attacks
- Memory dump protection
- Additional authentication factors
- Regular security audits
- Code review by security professionals

## Features

- **Strong Encryption**: AES-256-GCM for confidentiality and integrity
- **Secure Key Derivation**: PBKDF2-SHA256 with 100,000+ iterations
- **Random Salt**: Unique salt per vault for rainbow table protection
- **Master Password**: Single password protects entire vault
- **Simple Interface**: Command-line interface for easy interaction
- **Vault File**: Encrypted file storage (vault.enc)

## Security Design

### Cryptographic Components
- **Encryption**: AES-256 in GCM mode (authenticated encryption)
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **Salt**: 256-bit random salt per vault
- **Nonce**: 96-bit random nonce per encryption
- **Integrity**: GCM provides built-in authentication

### File Format
```
vault.enc = salt(32 bytes) + nonce(12 bytes) + encrypted_data
```

### Security Properties
- **Confidentiality**: Passwords encrypted with AES-256
- **Integrity**: GCM mode detects tampering
- **Authentication**: Wrong master password fails gracefully
- **Salt**: Prevents rainbow table attacks
- **Iterations**: 100k PBKDF2 iterations slow brute force

## Installation

1. Install Python 3.7+ and pip
2. Install dependencies:
   ```bash
   pip install cryptography>=41.0.0
   ```

## Usage

### Running the Program
```bash
python main.py
```

### First Run
- Creates new vault with master password
- Master password is your single key to all stored credentials
- **Choose a strong, memorable master password!**

### Menu Options
1. **Add Entry**: Store new site credentials
2. **View All**: Display all stored entries
3. **Search**: Find entries by site name
4. **Exit**: Close application securely

### Example Session
```
🔒 MINI PASSWORD MANAGER v1.0
Creating new vault...
Enter master password: ********
Confirm master password: ********
✓ Vault created successfully

MAIN MENU
1. Add new entry
Enter your choice: 1

Site/Service name: github.com
Username: myuser
Password: mypassword123
✓ Added entry for 'github.com'
```

## File Structure
```
project/
├── main.py              # Main entry point and CLI
├── vault_manager.py     # Vault operations
├── crypto_utils.py      # Cryptographic functions
├── requirements.txt     # Dependencies
├── README.md           # This documentation
└── vault.enc           # Encrypted vault (created at runtime)
```

## Security Considerations

### What This Implements
✅ Strong encryption (AES-256-GCM)  
✅ Secure key derivation (PBKDF2)  
✅ Random salts and nonces  
✅ Integrity verification  
✅ Secure password input (hidden)  

### Production Hardening Needed
❌ Memory protection (sensitive data clearing)  
❌ Timing attack protection  
❌ Secure deletion of temporary files  
❌ Multi-factor authentication  
❌ Backup and recovery mechanisms  
❌ Password strength validation  
❌ Session timeouts  
❌ Audit logging  

### Best Practices for Use
- Use a strong, unique master password
- Store vault.enc securely (backup recommended)
- Don't share vault files
- Run only on trusted systems
- Consider using established password managers for critical use

## Dependencies
- `cryptography>=41.0.0`: Industry-standard Python cryptography library

## License
Educational/demonstration use only. Not recommended for production use.