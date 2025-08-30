"""
Vault management for the password manager.
Handles vault file operations and credential management.
"""

import os
import json
import getpass
from typing import Dict, List, Optional, Any
from cryptography.exceptions import InvalidTag

from crypto_utils import CryptoManager


class VaultManager:
    """Manages the encrypted password vault."""
    
    def __init__(self, vault_path: str = "vault.enc"):
        """
        Initialize vault manager.
        
        Args:
            vault_path: Path to the vault file
        """
        self.vault_path = vault_path
        self.crypto = CryptoManager()
        self._master_key = None
        self._salt = None
    
    def _get_master_password(self, confirm: bool = False) -> str:
        """
        Securely get master password from user.
        
        Args:
            confirm: Whether to ask for password confirmation
            
        Returns:
            Master password string
        """
        password = getpass.getpass("Enter master password: ")
        
        if confirm:
            confirm_password = getpass.getpass("Confirm master password: ")
            if password != confirm_password:
                raise ValueError("Passwords do not match!")
        
        return password
    
    def _load_vault_metadata(self) -> Dict[str, Any]:
        """
        Load vault file and extract metadata.
        
        Returns:
            Dictionary containing salt, nonce, and encrypted data
            
        Raises:
            FileNotFoundError: If vault doesn't exist
            ValueError: If vault format is invalid
        """
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError(f"Vault file '{self.vault_path}' not found")
        
        try:
            with open(self.vault_path, 'rb') as f:
                vault_data = f.read()
            
            # Vault format: salt (32 bytes) + nonce (12 bytes) + encrypted_data
            min_size = self.crypto.SALT_LENGTH + self.crypto.NONCE_LENGTH
            if len(vault_data) < min_size:
                raise ValueError(f"Invalid vault file format: file size {len(vault_data)} bytes, minimum required {min_size} bytes")
            
            salt = vault_data[:self.crypto.SALT_LENGTH]
            nonce = vault_data[self.crypto.SALT_LENGTH:self.crypto.SALT_LENGTH + self.crypto.NONCE_LENGTH]
            encrypted_data = vault_data[self.crypto.SALT_LENGTH + self.crypto.NONCE_LENGTH:]
            
            return {
                'salt': salt,
                'nonce': nonce,
                'encrypted_data': encrypted_data
            }
        except Exception as e:
            raise ValueError(f"Error reading vault file: {e}")
    
    def _save_vault(self, entries: List[Dict[str, str]]) -> None:
        """
        Encrypt and save entries to vault file.
        
        Args:
            entries: List of credential dictionaries
        """
        if self._master_key is None or self._salt is None:
            raise RuntimeError("Master key not initialized")
        
        # Encrypt the entries
        encrypted_data, nonce = self.crypto.encrypt_data(entries, self._master_key)
        
        # Save to file: salt + nonce + encrypted_data
        with open(self.vault_path, 'wb') as f:
            f.write(self._salt + nonce + encrypted_data)
    
    def initialize_vault(self) -> None:
        """Initialize a new vault with master password."""
        print("Creating new vault...")
        password = self._get_master_password(confirm=True)
        
        # Generate random salt for this vault
        self._salt = os.urandom(self.crypto.SALT_LENGTH)
        
        # Derive master key
        self._master_key = self.crypto.derive_key(password, self._salt)
        
        # Create empty vault
        self._save_vault([])
        print(f"✓ Vault created successfully at '{self.vault_path}'")
    
    def unlock_vault(self) -> List[Dict[str, str]]:
        """
        Unlock vault with master password and return decrypted entries.
        
        Returns:
            List of credential dictionaries
            
        Raises:
            ValueError: If wrong password or corrupted vault
        """
        try:
            vault_metadata = self._load_vault_metadata()
        except FileNotFoundError:
            print("Vault not found. Creating new vault...")
            self.initialize_vault()
            return []
        
        password = self._get_master_password()
        self._salt = vault_metadata['salt']
        
        # Derive key from master password
        self._master_key = self.crypto.derive_key(password, self._salt)
        
        try:
            # Attempt to decrypt vault
            entries = self.crypto.decrypt_data(
                vault_metadata['encrypted_data'],
                vault_metadata['nonce'],
                self._master_key
            )
            print("✓ Vault unlocked successfully")
            return entries
        except InvalidTag:
            raise ValueError("Invalid master password or corrupted vault!")
    
    def add_entry(self, entries: List[Dict[str, str]], site: str, username: str, password: str) -> None:
        """
        Add a new credential entry to the vault.
        
        Args:
            entries: Current list of entries
            site: Website/service name
            username: Username for the site
            password: Password for the site
        """
        # Check for duplicate sites (optional - you might want multiple accounts per site)
        for entry in entries:
            if entry['site'].lower() == site.lower():
                overwrite = input(f"Entry for '{site}' already exists. Overwrite? (y/N): ")
                if overwrite.lower() != 'y':
                    print("Entry not added.")
                    return
                entries.remove(entry)
                break
        
        # Add new entry
        new_entry = {
            'site': site,
            'username': username,
            'password': password
        }
        entries.append(new_entry)
        
        # Save updated vault
        self._save_vault(entries)
        print(f"✓ Added entry for '{site}'")
    
    def view_all_entries(self, entries: List[Dict[str, str]]) -> None:
        """
        Display all vault entries (passwords masked by default).
        
        Args:
            entries: List of credential dictionaries
        """
        if not entries:
            print("No entries found in vault.")
            return
        
        print(f"\n{'='*60}")
        print(f"{'VAULT ENTRIES':<60}")
        print(f"{'='*60}")
        
        for i, entry in enumerate(entries, 1):
            print(f"\n{i}. Site: {entry['site']}")
            print(f"   Username: {entry['username']}")
            
            # Ask if user wants to see password
            show_pass = input(f"   Show password for {entry['site']}? (y/N): ")
            if show_pass.lower() == 'y':
                print(f"   Password: {entry['password']}")
            else:
                print(f"   Password: {'*' * len(entry['password'])}")
    
    def search_entry(self, entries: List[Dict[str, str]], site: str) -> None:
        """
        Search for entries by site name.
        
        Args:
            entries: List of credential dictionaries
            site: Site name to search for
        """
        matches = [entry for entry in entries if site.lower() in entry['site'].lower()]
        
        if not matches:
            print(f"No entries found for '{site}'")
            return
        
        print(f"\nFound {len(matches)} entry/entries for '{site}':")
        print("="*50)
        
        for i, entry in enumerate(matches, 1):
            print(f"\n{i}. Site: {entry['site']}")
            print(f"   Username: {entry['username']}")
            
            show_pass = input(f"   Show password for {entry['site']}? (y/N): ")
            if show_pass.lower() == 'y':
                print(f"   Password: {entry['password']}")
            else:
                print(f"   Password: {'*' * len(entry['password'])}")
