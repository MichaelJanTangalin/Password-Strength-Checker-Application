import os
import re
import random
import string
import tkinter as tk
from tkinter import messagebox
import json
from datetime import datetime
from cryptography.fernet import Fernet


# GUI COMPONENTS
class PasswordStrengthChecker:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Strength Checker")

        self.label = tk.Label(master, text="Enter your password:", font=("Arial Black", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=10)

        self.strength_label = tk.Label(master, text="", font=("Arial", 12))
        self.strength_label.grid(row=1, column=0, columnspan=2, pady=(0, 5))

        self.input_frame = tk.Frame(master)
        self.input_frame.grid(row=2, column=0, columnspan=2, pady=5)

        self.password_entry = tk.Entry(self.input_frame, show="*", font=("Arial", 14))
        self.password_entry.grid(row=0, column=0, padx=10, sticky="ew")
        self.password_entry.bind("<KeyRelease>", self.check_password_strength)

        self.eye_button = tk.Button(self.input_frame, text="Show", font=("Arial", 12), command=self.toggle_eye)
        self.eye_button.grid(row=0, column=1, padx=(0, 10), sticky="e")

        self.check_button = tk.Button(master, text="Check Strength", font=("Arial", 14), command=self.check_strength)
        self.check_button.grid(row=3, column=0, padx=5, pady=10, sticky="ew")

        self.generate_button = tk.Button(master, text="Generate Password", font=("Arial", 14),
                                         command=self.generate_password_and_check)
        self.generate_button.grid(row=3, column=1, padx=5, pady=10, sticky="ew")

        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_columnconfigure(1, weight=1)
        self.master.grid_rowconfigure(0, weight=1)
        self.master.grid_rowconfigure(1, weight=0)
        self.master.grid_rowconfigure(2, weight=1)
        self.master.grid_rowconfigure(3, weight=1)

        self.show_password = False

        # Generate a key for encryption (you should only do this once)
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def check_password_strength(self, event=None):
        password = self.password_entry.get()
        if not password:
            self.strength_label.config(text="")
            return
        strength, _ = self.evaluate_strength(password)
        self.strength_label.config(text=f"Strength: {strength}", fg=self.get_strength_color(strength))

    # Strength Checker Function
    def check_strength(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Empty Password input", "Please type a password.")
            return
        strength, recommendations = self.evaluate_strength(password)
        if strength == "Weak":
            messagebox.showinfo("Strength Check", f"Password strength: {strength}\n{recommendations}", icon="error")
        elif strength == "Moderate":
            messagebox.showinfo("Strength Check", f"Password strength: {strength}\n{recommendations}", icon="warning")
        else:
            messagebox.showinfo("Success", f"Password strength: {strength}\n{recommendations}")

        # Encrypt password
        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()

        # Write encrypted password strength information to JSON file
        data = {
            "password": encrypted_password,
            "strength": strength,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        # Check if the file exists
        if os.path.exists("password_storage.json"):
            # Open the existing JSON file for reading
            with open("password_storage.json", "r") as json_file:
                # Load existing data
                existing_data = json.load(json_file)
        else:
            # If the file doesn't exist, initialize existing_data as an empty list
            existing_data = []

        # Append new data to the existing data
        existing_data.append(data)

        # Open the JSON file in write mode
        with open("password_storage.json", "w") as json_file:
            # Dump the updated data with indentation
            json.dump(existing_data, json_file, indent=4)

    # Strength Evaluation
    def evaluate_strength(self, password):
        length = len(password)
        complexity = self.calculate_complexity(password)

        if length < 8 or complexity < 3:
            return "Weak", "Recommendations: Consider increasing length and adding special characters."
        elif length < 12 or complexity < 4:
            return "Moderate", "Recommendations: Consider adding more characters or special characters to improve security."
        else:
            return "Strong", "Password is strong."

    def calculate_complexity(self, password):
        complexity = 0
        if re.search(r'[a-z]', password):
            complexity += 1
        if re.search(r'[A-Z]', password):
            complexity += 1
        if re.search(r'[0-9]', password):
            complexity += 1
        if re.search(r'[^a-zA-Z0-9]', password):
            complexity += 1
        return complexity

    # GENERATE RANDOM AND SECURE PASSWORD
    def generate_password(self):
        length = 12  # Default password length
        password = ''.join(random.choices(
            string.ascii_letters + string.digits + string.punctuation,
            k=length))
        return password

    def generate_password_and_check(self):
        password = self.generate_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.check_password_strength()

    def toggle_eye(self):
        if self.show_password:
            self.password_entry.config(show="*")
            self.show_password = False
            self.eye_button.config(text="Show")
        else:
            self.password_entry.config(show="")
            self.show_password = True
            self.eye_button.config(text="Hide")

    # COLOR CODING OF STRENGTH
    def get_strength_color(self, strength):
        if strength == "Weak":
            return "red"
        elif strength == "Moderate":
            return "orange"
        else:
            return "green"


# Main Function
def main():
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()


if __name__ == "__main__":
    main()
