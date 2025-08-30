"""
Cryptographic utilities for the password manager.
Handles key derivation and AES-GCM encryption/decryption.
"""

import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, Any, Tuple


class CryptoManager:
    """Handles all cryptographic operations for the password manager."""
    
    # Security parameters
    SALT_LENGTH = 32  # 256 bits
    KEY_LENGTH = 32   # 256 bits for AES-256
    NONCE_LENGTH = 12 # 96 bits for GCM
    ITERATIONS = 100000  # PBKDF2 iterations (OWASP minimum)
    
    @classmethod
    def derive_key(cls, password: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit AES key from password using PBKDF2-SHA256.
        
        Args:
            password: Master password string
            salt: Random salt bytes
            
        Returns:
            32-byte derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=cls.KEY_LENGTH,
            salt=salt,
            iterations=cls.ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))
    
    @classmethod
    def encrypt_data(cls, data: Dict[str, Any], key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Dictionary to encrypt (will be JSON serialized)
            key: 32-byte encryption key
            
        Returns:
            Tuple of (encrypted_data, nonce)
        """
        # Serialize data to JSON bytes
        json_data = json.dumps(data, indent=2).encode('utf-8')
        
        # Generate random nonce
        nonce = os.urandom(cls.NONCE_LENGTH)
        
        # Encrypt using AES-GCM (provides both confidentiality and integrity)
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, json_data, None)
        
        return encrypted_data, nonce
    
    @classmethod
    def decrypt_data(cls, encrypted_data: bytes, nonce: bytes, key: bytes) -> Dict[str, Any]:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted bytes
            nonce: Nonce used during encryption
            key: 32-byte decryption key
            
        Returns:
            Decrypted dictionary
            
        Raises:
            InvalidTag: If authentication fails (wrong password/corrupted data)
        """
        aesgcm = AESGCM(key)
        
        # Decrypt and verify integrity
        decrypted_bytes = aesgcm.decrypt(nonce, encrypted_data, None)
        
        # Parse JSON
        return json.loads(decrypted_bytes.decode('utf-8'))

