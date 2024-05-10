# Password Strength Checker

This program is a simple graphical user interface (GUI) tool built with Python's Tkinter library for checking the strength of passwords and generating secure passwords.

## Features

- **Password Strength Check**: Evaluates the strength of a password based on length and complexity.
- **GUI Interface**: Provides a user-friendly interface for entering passwords and viewing strength assessments.
- **Password Generation**: Allows users to generate random and secure passwords of default length.
- **Encryption and Storage**: Encrypts passwords and stores them along with their strength and timestamp in a JSON file.

## How to Use

1. **Enter Password**: Type your desired password into the provided entry field.
2. **Check Strength**: Click the "Check Strength" button to evaluate the strength of the entered password.
3. **Generate Password**: Optionally, click the "Generate Password" button to create a random and secure password.
4. **Show/Hide Password**: Click the "Show" button to toggle between displaying and hiding the entered password.
5. **View Strength**: The strength of the password is displayed below the entry field, with color coding indicating weak (red), moderate (orange), or strong (green) strength.
6. **Storage**: Upon checking strength, the encrypted password along with its strength and timestamp is stored in a JSON file named `password_storage.json`.

## Strength Evaluation

- **Weak Passwords**: Less than 8 characters or lacking in complexity (e.g., no special characters).
- **Moderate Passwords**: Between 8 and 11 characters or moderate complexity.
- **Strong Passwords**: 12 or more characters or high complexity.

## Requirements

- Python 3.x
- Tkinter (usually comes pre-installed with Python)
- cryptography (install via `pip install cryptography`)

## Running the Program

To execute the program, run the Python script `password_strength_checker.py`. This will launch the GUI application where you can interact with the password strength checker.

```bash
python password_strength_checker.py
