"""
Mini Password Manager - Main Entry Point
A secure password manager using AES-256-GCM encryption.

SECURITY WARNING: This is a demonstration implementation.
For production use, additional security measures should be implemented:
- Secure memory handling (clearing sensitive data)
- Protection against timing attacks
- Secure random number generation validation
- Additional authentication factors
- Regular security audits
"""

import sys
import os
from typing import List, Dict
from vault_manager import VaultManager


def print_banner():
    """Display application banner."""
    print("="*60)
    print("🔒 MINI PASSWORD MANAGER v1.0")
    print("="*60)
    print("WARNING: This is a demonstration tool.")
    print("Do not use for production without security hardening!")
    print("="*60)


def print_menu():
    """Display main menu options."""
    print("\n" + "="*30)
    print("MAIN MENU")
    print("="*30)
    print("1. Add new entry")
    print("2. View all entries")
    print("3. Search entry by site")
    print("4. Exit")
    print("="*30)


def get_user_choice() -> str:
    """Get and validate user menu choice."""
    while True:
        choice = input("\nEnter your choice (1-4): ").strip()
        if choice in ['1', '2', '3', '4']:
            return choice
        print("Invalid choice. Please enter 1, 2, 3, or 4.")


def add_entry_interactive(vault: VaultManager, entries: List[Dict[str, str]]) -> None:
    """Interactive function to add a new entry."""
    print("\n" + "-"*30)
    print("ADD NEW ENTRY")
    print("-"*30)
    
    site = input("Site/Service name: ").strip()
    if not site:
        print("Site name cannot be empty!")
        return
    
    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty!")
        return
    
    password = input("Password: ").strip()
    if not password:
        print("Password cannot be empty!")
        return
    
    try:
        vault.add_entry(entries, site, username, password)
    except Exception as e:
        print(f"Error adding entry: {e}")


def search_entry_interactive(vault: VaultManager, entries: List[Dict[str, str]]) -> None:
    """Interactive function to search for entries."""
    print("\n" + "-"*30)
    print("SEARCH ENTRY")
    print("-"*30)
    
    site = input("Enter site name to search: ").strip()
    if not site:
        print("Search term cannot be empty!")
        return
    
    vault.search_entry(entries, site)


def main():
    """Main application entry point."""
    print_banner()
    
    # Initialize vault manager
    vault = VaultManager()
    
    # Unlock vault (or create new one)
    try:
        entries = vault.unlock_vault()
    except ValueError as e:
        print(f"❌ Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1
    
    # Main application loop
    while True:
        try:
            print_menu()
            choice = get_user_choice()
            
            if choice == '1':
                add_entry_interactive(vault, entries)
            
            elif choice == '2':
                print("\n" + "-"*30)
                print("ALL VAULT ENTRIES")
                print("-"*30)
                vault.view_all_entries(entries)
            
            elif choice == '3':
                search_entry_interactive(vault, entries)
            
            elif choice == '4':
                print("\n👋 Goodbye! Stay secure!")
                break
        
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            print("Please try again.")
    
    # Security: Clear sensitive data from memory (basic attempt)
    if vault._master_key:
        vault._master_key = None
    if vault._salt:
        vault._salt = None
    
    return 0


if __name__ == "__main__":
    sys.exit(main())