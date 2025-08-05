#!/usr/bin/env python3
"""
User Authentication Module

A SQLite-based authentication system with secure password hashing using bcrypt.
"""

import sqlite3
import bcrypt
import getpass
import sys
from typing import Optional, Tuple
from contextlib import contextmanager
from pathlib import Path


class AuthError(Exception):
    """Custom exception for authentication errors."""
    pass


class AuthModule:
    """SQLite backend for user authentication with bcrypt password hashing."""
    
    def __init__(self, db_path: str = "auth.db"):
        """
        Initialize the AuthModule with a database path.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = Path(db_path)
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Create the database and users table if they don't exist."""
        try:
            with self._get_db_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash BLOB NOT NULL
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            raise AuthError(f"Failed to initialize database: {e}")
    
    @contextmanager
    def _get_db_connection(self):
        """
        Context manager for database connections.
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            raise AuthError(f"Database error: {e}")
        finally:
            if conn:
                conn.close()
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Register a new user with hashed password.
        
        Args:
            username: User's username
            password: User's plaintext password
            
        Returns:
            bool: True if registration successful
            
        Raises:
            AuthError: If username already exists or validation fails
            ValueError: If inputs are invalid
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Validate password strength (basic)
        if len(password) < 6:
            raise AuthError("Password must be at least 6 characters long")
        
        try:
            # Hash the password
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            with self._get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username.strip(), password_hash)
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            raise AuthError("Username already exists")
        except sqlite3.Error as e:
            raise AuthError(f"Failed to register user: {e}")
    
    def login_user(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        """
        Authenticate user credentials.
        
        Args:
            username: User's username
            password: User's plaintext password
            
        Returns:
            Tuple[bool, Optional[int]]: (success, user_id) where user_id is None if failed
            
        Raises:
            AuthError: If database error occurs
            ValueError: If inputs are invalid
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        
        if not password:
            raise ValueError("Password cannot be empty")
        
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute(
                    "SELECT id, password_hash FROM users WHERE username = ?",
                    (username.strip(),)
                )
                row = cursor.fetchone()
                
                if not row:
                    return False, None  # User not found
                
                user_id = row["id"]
                stored_hash = row["password_hash"]
                
                # Verify password
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    return True, user_id
                else:
                    return False, None  # Invalid password
        except sqlite3.Error as e:
            raise AuthError(f"Failed to authenticate user: {e}")
    
    def user_exists(self, username: str) -> bool:
        """
        Check if a username already exists.
        
        Args:
            username: Username to check
            
        Returns:
            bool: True if username exists
            
        Raises:
            AuthError: If database error occurs
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute(
                    "SELECT 1 FROM users WHERE username = ?",
                    (username.strip(),)
                )
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            raise AuthError(f"Failed to check username: {e}")


def main():
    """Main function for CLI demonstration of the AuthModule."""
    print("=== User Authentication Demo ===\n")
    
    # Initialize auth module
    try:
        auth = AuthModule()
    except Exception as e:
        print(f"Error initializing auth module: {e}")
        sys.exit(1)
    
    while True:
        print("\nOptions:")
        print("1. Register new user")
        print("2. Login")
        print("3. Check if user exists")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            username = input("Enter username: ").strip()
            if not username:
                print("Username cannot be empty!")
                continue
                
            password = getpass.getpass("Enter password (min 6 characters): ")
            
            try:
                auth.register_user(username, password)
                print(f"✓ User '{username}' registered successfully!")
            except ValueError as e:
                print(f"⚠ Validation error: {e}")
            except AuthError as e:
                print(f"✗ Registration failed: {e}")
            except Exception as e:
                print(f"✗ Unexpected error: {e}")
        
        elif choice == "2":
            username = input("Enter username: ").strip()
            if not username:
                print("Username cannot be empty!")
                continue
                
            password = getpass.getpass("Enter password: ")
            
            try:
                success, user_id = auth.login_user(username, password)
                if success:
                    print(f"✓ Login successful! Welcome user ID: {user_id}")
                else:
                    print("✗ Invalid username or password")
            except ValueError as e:
                print(f"⚠ Validation error: {e}")
            except AuthError as e:
                print(f"✗ Authentication error: {e}")
            except Exception as e:
                print(f"✗ Unexpected error: {e}")
        
        elif choice == "3":
            username = input("Enter username to check: ").strip()
            if not username:
                print("Username cannot be empty!")
                continue
                
            try:
                exists = auth.user_exists(username)
                if exists:
                    print(f"✓ Username '{username}' exists")
                else:
                    print(f"○ Username '{username}' is available")
            except AuthError as e:
                print(f"✗ Check failed: {e}")
            except Exception as e:
                print(f"✗ Unexpected error: {e}")
        
        elif choice == "4":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")


# Integration example with todo_backend.py
def integrate_with_todo_example():
    """
    Example of how to integrate AuthModule with TodoBackend.
    This would typically be in a separate application file.
    """
    # Example usage pattern:
    # 1. Initialize both modules
    # auth = AuthModule()
    # todo_backend = TodoBackend()
    # 
    # 2. Register or login user
    # success, user_id = auth.login_user(username, password)
    # 
    # 3. If successful, use user_id to scope todo operations
    # (This would require modifying TodoBackend to associate todos with user_id)
    pass


if __name__ == "__main__":
    # Check if bcrypt is available
    try:
        import bcrypt
    except ImportError:
        print("Error: bcrypt module not found. Install with: pip install bcrypt")
        sys.exit(1)
    
    main()