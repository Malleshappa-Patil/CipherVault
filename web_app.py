"""
Web interface for the Mini Password Manager.
Flask-based web application with secure session handling.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import secrets
from typing import List, Dict
from vault_manager import VaultManager
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate random secret key for sessions

# Global vault manager instance
vault_manager = VaultManager()


@app.route('/')
def index():
    """Main page - check if vault is unlocked."""
    if 'vault_unlocked' in session and session['vault_unlocked']:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/unlock', methods=['POST'])
def unlock_vault():
    """Unlock the vault with master password."""
    master_password = request.form.get('master_password')
    
    if not master_password:
        flash('Master password is required!', 'error')
        return redirect(url_for('index'))
    
    try:
        # Temporarily store password for vault operations
        session['temp_password'] = master_password
        entries = vault_manager.unlock_vault()
        
        # Store unlocked state and entries in session
        session['vault_unlocked'] = True
        session['entries'] = entries
        session.pop('temp_password', None)  # Remove temp password
        
        flash('Vault unlocked successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except ValueError as e:
        session.pop('temp_password', None)
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('index'))
    except Exception as e:
        session.pop('temp_password', None)
        flash(f'Unexpected error: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """Main dashboard showing all entries."""
    if not session.get('vault_unlocked'):
        return redirect(url_for('index'))
    
    entries = session.get('entries', [])
    return render_template('dashboard.html', entries=entries)


@app.route('/add', methods=['GET', 'POST'])
def add_entry():
    """Add new entry to vault."""
    if not session.get('vault_unlocked'):
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        site = request.form.get('site', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not all([site, username, password]):
            flash('All fields are required!', 'error')
            return render_template('add_entry.html')
        
        try:
            entries = session.get('entries', [])
            
            # Check for existing entry
            for i, entry in enumerate(entries):
                if entry['site'].lower() == site.lower():
                    entries[i] = {'site': site, 'username': username, 'password': password}
                    vault_manager._save_vault(entries)
                    session['entries'] = entries
                    flash(f'Updated entry for {site}!', 'success')
                    return redirect(url_for('dashboard'))
            
            # Add new entry
            new_entry = {'site': site, 'username': username, 'password': password}
            entries.append(new_entry)
            vault_manager._save_vault(entries)
            session['entries'] = entries
            
            flash(f'Added entry for {site}!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error adding entry: {str(e)}', 'error')
    
    return render_template('add_entry.html')


@app.route('/search')
def search():
    """Search entries by site name."""
    if not session.get('vault_unlocked'):
        return redirect(url_for('index'))
    
    query = request.args.get('q', '').strip()
    entries = session.get('entries', [])
    
    if query:
        matches = [entry for entry in entries if query.lower() in entry['site'].lower()]
        return render_template('search_results.html', matches=matches, query=query)
    
    return render_template('search.html')


@app.route('/reveal_password/<int:entry_index>')
def reveal_password(entry_index):
    """AJAX endpoint to reveal password for specific entry."""
    if not session.get('vault_unlocked'):
        return jsonify({'error': 'Vault not unlocked'}), 401
    
    entries = session.get('entries', [])
    
    if 0 <= entry_index < len(entries):
        return jsonify({'password': entries[entry_index]['password']})
    
    return jsonify({'error': 'Entry not found'}), 404


@app.route('/lock')
def lock_vault():
    """Lock the vault and clear session."""
    session.clear()
    flash('Vault locked successfully!', 'info')
    return redirect(url_for('index'))


# Override VaultManager methods to work with Flask sessions
def patched_get_master_password(self, confirm=False):
    """Get master password from session instead of getpass."""
    password = session.get('temp_password')
    if not password:
        raise ValueError("Master password not found in session")
    return password

# Monkey patch for web compatibility
vault_manager._get_master_password = patched_get_master_password.__get__(vault_manager, VaultManager)


if __name__ == '__main__':
    print("🌐 Starting Mini Password Manager Web Interface...")
    print("🔗 Open your browser and go to: http://localhost:5000")
    print("⚠️  WARNING: This is for demonstration only!")
    print("🛑 Do not use over untrusted networks!")
    app.run(debug=True, host='localhost', port=5000)
