import tkinter as tk
from tkinter import messagebox
import re
import hashlib
import requests

# List of common passwords used 
COMMON_PASSWORDS = ["123456", "password", "123456789", "qwerty", "12345678", "111111", "123123", "abc123"]

# Functions
def check_password_strength(password):
    errors = []
    if len(password) < 12:
        errors.append("Use at least 12 characters")
    if not re.search(r"[a-z]", password):
        errors.append("Add lowercase letters")
    if not re.search(r"[A-Z]", password):
        errors.append("Add uppercase letters")
    if not re.search(r"\d", password):
        errors.append("Add numbers")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Add special characters")
    
    return errors

def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS

def check_pwned(password):
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pass[:5], sha1_pass[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    hashes = (line.split(":") for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return int(count)
    return 0

def evaluate_password():
    password = entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password")
        return
    
    errors = check_password_strength(password)
    common = is_common_password(password)
    try:
        pwned_count = check_pwned(password)
    except:
        pwned_count = -1  # API error handling

    # Update GUI labels
    if errors:
        strength_label.config(text="WEAK", fg="red")
    elif errors <= 2:
        strength_label.config(text="MEDIUM", fg="orange")
    else:
        strength_label.config(text="STRONG", fg="green")
    
    suggestions_text = ""
    for e in errors:
        suggestions_text += "- " + e + "\n"
    if common:
        suggestions_text += "- This is a commonly used password\n"
    if pwned_count > 0:
        suggestions_text += f"- Found in data breaches {pwned_count} times\n"
    elif pwned_count == 0:
        suggestions_text += "- Not found in known breaches\n"
    else:
        suggestions_text += "- Could not check breaches\n"
    
    suggestions_label.config(text=suggestions_text)

# GUI Setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("500x400")

tk.Label(root, text="Enter Password:", font=("Arial", 14)).pack(pady=10)
entry = tk.Entry(root, width=30, font=("Arial", 14), show="*")
entry.pack(pady=5)

check_btn = tk.Button(root, text="Check Strength", command=evaluate_password, font=("Arial", 12, "bold"), bg="#0FE616", fg="gray", activebackground="gray",
    activeforeground="gray", relief="raised")
check_btn.pack(pady=10)

tk.Label(root, text="Password Strength:", font=("Arial", 14)).pack(pady=5)
strength_label = tk.Label(root, text="---", font=("Arial", 16))
strength_label.pack(pady=5)

tk.Label(root, text="Suggestions:", font=("Arial", 14)).pack(pady=5)
suggestions_label = tk.Label(root, text="", justify="left", font=("Arial", 12))
suggestions_label.pack(pady=5)

root.mainloop()
