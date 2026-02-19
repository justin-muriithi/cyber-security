import hashlib
import getpass  # Used to hide password input

# 1️⃣ Class: PasswordSecurity
class PasswordSecurity:
    def check_strength(self, password):
        # Check minimum length
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."

        # Check for uppercase letters
        if not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter."

        # Check for lowercase letters
        if not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter."

        # Check for digits
        if not any(char.isdigit() for char in password):
            return False, "Password must contain at least one number."

        return True, "Password is strong."

    def hash_password(self, password):
        # Hash the password using SHA-256
        return hashlib.sha256(password.encode()).hexdigest()

# 2️⃣ Class: User
class User:
    def __init__(self, username, hashed_password):
        self.username = username
        self.hashed_password = hashed_password

# 3️⃣ Class: AuthenticationSystem
class AuthenticationSystem:
    def __init__(self):
        self.users = {}  # Stores users: {username: User object}
        self.security = PasswordSecurity()  # Helper for password tasks

    # Registration method
    def register(self, username, password):
        if username in self.users:
            print("❌ Username already exists.")
            return

        is_strong, message = self.security.check_strength(password)
        if not is_strong:
            print(f"❌ {message}")
            return

        hashed_password = self.security.hash_password(password)
        self.users[username] = User(username, hashed_password)
        print("✅ User registered successfully.")

    # Login method
    def login(self, username, password):
        if username not in self.users:
            print("❌ User not found.")
            return

        hashed_input = self.security.hash_password(password)
        if hashed_input == self.users[username].hashed_password:
            print("✅ Authentication successful. Access granted.")
        else:
            print("❌ Authentication failed. Incorrect password.")

# 4️⃣ Main program
def main():
    auth_system = AuthenticationSystem()

    # Registration
    print("=== User Registration ===")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")  # Hides input
    auth_system.register(username, password)

    print("\n=== User Login ===")
    login_username = input("Enter username: ")
    login_password = getpass.getpass("Enter password: ")
    auth_system.login(login_username, login_password)

if __name__ == "__main__":
    main()

