"""
Module Database - Gestion SQLite pour users et historique
"""

import sqlite3
import hashlib
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass

from modules.config import DATA_DIR

DB_PATH = DATA_DIR / "security_audit.db"


@dataclass
class User:
    """Modèle utilisateur"""
    id: int
    username: str
    password_hash: str
    role: str  # admin, operator, viewer
    email: str = ""
    created_at: str = ""
    last_login: str = ""
    
    def can_scan(self) -> bool:
        return self.role in ('admin', 'operator')
    
    def can_manage_users(self) -> bool:
        return self.role == 'admin'
    
    def can_send_email(self) -> bool:
        return self.role in ('admin', 'operator')
    
    def can_export(self) -> bool:
        return True  # Tous peuvent exporter


class Database:
    """Gestionnaire de base de données SQLite"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.db_path = DB_PATH
        self._init_db()

    @contextmanager
    def _conn(self):
        """
        Context manager qui garantit la fermeture de la connexion
        même si une exception est levée. Commit explicite uniquement
        sur les opérations en écriture (via le caller).
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """[DEPRECATED] Conservée pour rétro-compatibilité — préférer self._conn()."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialiser les tables"""
        with self._conn() as conn:
            cursor = conn.cursor()
            
            # Table users
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'viewer',
                    email TEXT DEFAULT '',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_login TEXT
                )
            ''')
            
            # Table scan_history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    target TEXT,
                    scan_type TEXT,
                    hosts_scanned INTEGER DEFAULT 0,
                    hosts_up INTEGER DEFAULT 0,
                    open_ports INTEGER DEFAULT 0,
                    vulnerabilities INTEGER DEFAULT 0,
                    duration REAL DEFAULT 0,
                    results TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Table settings
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            
            conn.commit()
            
            # Créer admin par défaut s'il n'existe pas
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
                    ('admin', self.hash_password('admin'), 'admin', '')
                )
                conn.commit()

    @staticmethod
    def hash_password(password: str) -> str:
        """Hasher un mot de passe"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    # ==================== USERS ====================
    
    def create_user(self, username: str, password: str, role: str = 'viewer', 
                    email: str = '') -> bool:
        """Créer un utilisateur"""
        try:
            with self._conn() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
                    (username, self.hash_password(password), role, email)
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authentifier un utilisateur"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM users WHERE username = ? AND password_hash = ?",
                (username, self.hash_password(password))
            )
            row = cursor.fetchone()
            
            if row:
                # Mettre à jour last_login
                cursor.execute(
                    "UPDATE users SET last_login = ? WHERE id = ?",
                    (datetime.now().isoformat(), row['id'])
                )
                conn.commit()
                
                return User(
                    id=row['id'],
                    username=row['username'],
                    password_hash=row['password_hash'],
                    role=row['role'],
                    email=row['email'] or '',
                    created_at=row['created_at'] or '',
                    last_login=datetime.now().isoformat()
                )
            
            return None
    
    def get_user(self, user_id: int) -> Optional[User]:
        """Obtenir un utilisateur par ID"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
        
        if row:
            return User(
                id=row['id'],
                username=row['username'],
                password_hash=row['password_hash'],
                role=row['role'],
                email=row['email'] or '',
                created_at=row['created_at'] or '',
                last_login=row['last_login'] or ''
            )
        return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Obtenir un utilisateur par nom d'utilisateur"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
        
        if row:
            return User(
                id=row['id'],
                username=row['username'],
                password_hash=row['password_hash'],
                role=row['role'],
                email=row['email'] or '',
                created_at=row['created_at'] or '',
                last_login=row['last_login'] or ''
            )
        return None
    
    def get_all_users(self) -> List[User]:
        """Obtenir tous les utilisateurs"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
            rows = cursor.fetchall()
        
        return [User(
            id=row['id'],
            username=row['username'],
            password_hash=row['password_hash'],
            role=row['role'],
            email=row['email'] or '',
            created_at=row['created_at'] or '',
            last_login=row['last_login'] or ''
        ) for row in rows]
    
    def update_user(self, user_id: int, **kwargs) -> bool:
        """
        Mettre à jour un utilisateur.
        Retourne True si l'opération est valide (même sans champs à modifier
        — un appel sans kwargs est un no-op légitime, pas une erreur).
        Retourne False uniquement en cas d'erreur SQL.
        """
        allowed = ['username', 'role', 'email']
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        
        if 'password' in kwargs:
            updates['password_hash'] = self.hash_password(kwargs['password'])
        
        if not updates:
            # Pas d'erreur : juste rien à faire
            return True
        
        try:
            with self._conn() as conn:
                cursor = conn.cursor()
                set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
                cursor.execute(
                    f"UPDATE users SET {set_clause} WHERE id = ?",
                    (*updates.values(), user_id)
                )
                conn.commit()
            return True
        except sqlite3.Error:
            return False
    
    def delete_user(self, user_id: int) -> bool:
        """Supprimer un utilisateur"""
        try:
            with self._conn() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE id = ? AND username != 'admin'", (user_id,))
                conn.commit()
                affected = cursor.rowcount
            return affected > 0
        except sqlite3.Error:
            return False
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """Changer le mot de passe"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash FROM users WHERE id = ?", (user_id,)
            )
            row = cursor.fetchone()
            
            if row and row['password_hash'] == self.hash_password(old_password):
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (self.hash_password(new_password), user_id)
                )
                conn.commit()
                return True
            
            return False
    
    # ==================== SETTINGS ====================
    
    def get_setting(self, key: str, default: str = '') -> str:
        """Obtenir un paramètre"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
        return row['value'] if row else default
    
    def set_setting(self, key: str, value: str):
        """Définir un paramètre"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, value)
            )
            conn.commit()
    
    def get_all_settings(self) -> Dict[str, str]:
        """Obtenir tous les paramètres"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            rows = cursor.fetchall()
        return {row['key']: row['value'] for row in rows}
    
    # ==================== SCAN HISTORY ====================
    
    def save_scan(self, user_id: int, target: str, scan_type: str,
                  hosts_scanned: int, hosts_up: int, open_ports: int,
                  vulnerabilities: int, duration: float, results: str = '') -> int:
        """Sauvegarder un scan"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_history 
                (user_id, target, scan_type, hosts_scanned, hosts_up, open_ports, 
                 vulnerabilities, duration, results)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, target, scan_type, hosts_scanned, hosts_up, open_ports,
                  vulnerabilities, duration, results))
            conn.commit()
            scan_id = cursor.lastrowid
        return scan_id
    
    def get_scan_history(self, user_id: int = None, limit: int = 50) -> List[Dict]:
        """Obtenir l'historique des scans"""
        with self._conn() as conn:
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute('''
                    SELECT sh.*, u.username 
                    FROM scan_history sh 
                    LEFT JOIN users u ON sh.user_id = u.id
                    WHERE sh.user_id = ?
                    ORDER BY sh.created_at DESC LIMIT ?
                ''', (user_id, limit))
            else:
                cursor.execute('''
                    SELECT sh.*, u.username 
                    FROM scan_history sh 
                    LEFT JOIN users u ON sh.user_id = u.id
                    ORDER BY sh.created_at DESC LIMIT ?
                ''', (limit,))
            
            rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    def delete_scan(self, scan_id: int) -> bool:
        """Supprimer un scan de l'historique"""
        try:
            with self._conn() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
                conn.commit()
            return True
        except sqlite3.Error:
            return False


# Instance globale
db = Database()
