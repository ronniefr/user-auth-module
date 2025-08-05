# User Auth Module

**A Python module for secure user authentication—featuring password hashing with bcrypt, SQL injection prevention, and integration with SQLite backends like your todo app.**

---

## 🚩 Why use this?

- Secure registration and login for MVPs or startups
- Protects against common risks like weak passwords and injections
- Modular design: Easily integrates with databases (e.g., your todo backend)
- CLI demo for testing auth flows
- Perfect for quant tools (secure user metrics) or AI apps (protected access)

---

## 🛠️ Features

- **Hashing & Verification:** Uses bcrypt for safe password storage
- **SQL Safety:** Parameterized queries to block injections
- **Error Handling:** Validates inputs and handles failures
- **Extensible:** Add JWT/OAuth—see notes below

---

## 🚀 Quickstart

1. Clone:
    ```
    git clone git@github.com:ronniefr/user-auth-module.git
    cd user-auth-module
    ```

2. Install dependencies:
    ```
    pip install bcrypt
    ```

3. Run (assumes a 'users.db' file):
    ```
    python auth_module.py
    ```
   - Follow CLI for register/login demos

---

## 🔑 Extend to Advanced Auth

- **JWT/OAuth:**  
  Modular class—add methods for token generation. Install `pyjwt` via `pip install pyjwt` and update verify to handle sessions/tokens.  
  Example: Integrate with FastAPI for API-based auth.

- **Security Note:** Enforce strong passwords (e.g., length checks) and add rate limiting for production.

---

### ⚡ Example Usage

'''

from auth_module import AuthModule

auth = AuthModule('users.db')
auth.register_user('user1', 'strongpass123')
success = auth.login_user('user1', 'strongpass123')
print(success) # True if authenticated
'''


---

## 🤝 Contributing

- Fork, PR, and suggest features (e.g., MFA, role-based access)
- Open issues for bugs or improvements!

---

## 📄 License

MIT — free for all use cases!
